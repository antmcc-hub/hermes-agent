"""LEV-590: exact-packet human callback contract, using the real adapter path."""
import json
from datetime import datetime, timezone
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

import pytest

from gateway.config import PlatformConfig
from plugins.platforms.telegram.adapter import TelegramAdapter


@pytest.fixture(autouse=True)
def keyboard_types(monkeypatch):
    # The repo's gateway conftest supplies telegram mocks when its optional extra is absent.
    # Preserve the wire fields rather than relying on MagicMock's recursive attributes.
    import telegram
    monkeypatch.setattr(telegram, 'InlineKeyboardButton', lambda text, callback_data: NS(text=text, callback_data=callback_data))
    monkeypatch.setattr(telegram, 'InlineKeyboardMarkup', lambda rows: NS(inline_keyboard=rows))


def packet(now):
    return {
        'version': 1, 'issue_uuid': '11111111-1111-4111-8111-111111111111',
        'issue': 'LEV-1000', 'project_id': '22222222-2222-4222-8222-222222222222',
        'canonical_repo': 'antmcc-hub/lev-pa', 'base_revision': 'a' * 40,
        'attachment_id': '33333333-3333-4333-8333-333333333333',
        'asset_ref': 'https://uploads.linear.app/example/manifest.json',
        'byte_length': 100, 'manifest_sha256': 'b' * 64,
        'contract_sha256': 'c' * 64, 'contract_version': 1,
        'allowed_paths': ['app/example.py', 'tests/test_example.py'],
        'patch_destination': 'antmcc-hub/lev-pa:main', 'policy_id': 'ringer-card-v1-shadow',
        'task_summary': 'Add one bounded fixture change',
        'check_summary': 'python -m pytest -q tests/test_example.py',
        'expires_at': now + 300,
    }


def adapter(root, enabled=True):
    root.mkdir(mode=0o700)
    config = PlatformConfig(enabled=True, token='fixture-token', extra={
        'ringer_manifest_release': {
            'enabled': enabled, 'owner_id': '42', 'receipts_dir': str(root),
        },
    })
    result = TelegramAdapter(config)
    result.set_authorization_check(lambda user_id, *args, **kwargs: user_id == '42')
    result._bot = NS(id=7, send_message=AsyncMock(return_value=NS(message_id=12)))
    result._app = NS(updater=NS(running=True))
    result._begin_polling_generation()
    return result


def callback(sent, data, now, **overrides):
    message = NS(
        message_id=12, chat_id=42, chat=NS(type='private'),
        text=sent['text'], edit_date=None, forward_origin=None,
        message_thread_id=None, date=datetime.fromtimestamp(now, timezone.utc),
        from_user=NS(id=7, is_bot=True),
    )
    query = NS(id='callback-fixture-1', data=data, message=message,
               from_user=NS(id=42, is_bot=False, first_name='fixture'),
               answer=AsyncMock(), edit_message_text=AsyncMock(), edit_message_reply_markup=AsyncMock())
    update = NS(update_id=123, callback_query=query)
    for path, value in overrides.items():
        target, name = path.rsplit('.', 1)
        obj = {'query': query, 'message': message, 'user': query.from_user, 'update': update}[target]
        setattr(obj, name, value)
    return update


def observe(a, update, generation=None):
    """Feed the actual polling observer a synthetic authenticated-response fixture."""
    q, m = update.callback_query, update.callback_query.message
    raw = {'update_id': update.update_id, 'callback_query': {
        'id': q.id, 'data': q.data, 'from': {'id': q.from_user.id, 'is_bot': q.from_user.is_bot},
        'message': {'message_id': m.message_id, 'chat': {'id': m.chat_id, 'type': m.chat.type},
                    'from': {'id': m.from_user.id, 'is_bot': m.from_user.is_bot}, 'text': m.text,
                    'edit_date': 1 if m.edit_date else None,
                    'forward_origin': {} if m.forward_origin is not None else None}}}
    envelope = {'ok': True, 'result': [raw]}
    request = NS(parse_json_payload=lambda payload: json.loads(payload))
    a._observe_polling_request_result(request, a._polling_generation if generation is None else generation,
                                     (200, json.dumps(envelope).encode()))


@pytest.mark.asyncio
async def test_exact_packet_callback_is_single_use_and_survives_restart(tmp_path):
    import time
    now = int(time.time())
    root = tmp_path / 'receipts'
    a = adapter(root)
    original = packet(now)
    result = await a.send_ringer_manifest_release(original)
    assert result.success
    sent = a._bot.send_message.call_args.kwargs
    assert sent['parse_mode'] is None
    data = sent['reply_markup'].inline_keyboard[0][0].callback_data
    # Mutating the caller's dict cannot retarget the packet the owner saw.
    original['manifest_sha256'] = 'd' * 64
    update = callback(sent, data, now)
    observe(a, update)
    await a._handle_callback_query(update, None)
    files = list(root.glob('*.json'))
    assert len(files) == 1
    receipt = json.loads(files[0].read_text())
    assert receipt['decision'] == 'approve'
    assert receipt['packet']['manifest_sha256'] == 'b' * 64
    assert receipt['source']['actor_id'] == '42'
    assert receipt['source']['update_id'] == 123
    assert receipt['source']['callback_id'] == 'callback-fixture-1'
    assert receipt['packet_digest'] in sent['text']
    assert (files[0].stat().st_mode & 0o777) == 0o600
    update.callback_query.edit_message_reply_markup.assert_awaited_once_with(reply_markup=None)
    await a._handle_callback_query(update, None)
    assert 'earlier decision is unchanged' in update.callback_query.answer.call_args.kwargs['text']
    assert len(list(root.glob('*.json'))) == 1
    # After adapter restart the persistent exact-packet receipt refuses re-release.
    b = TelegramAdapter(a.config)
    b.set_authorization_check(lambda user_id, *args, **kwargs: user_id == '42')
    b._bot = a._bot
    b._app = a._app
    b._begin_polling_generation()
    retry = await b.send_ringer_manifest_release(packet(now))
    assert not retry.success
    assert len(list(root.glob('*.json'))) == 1
    other = packet(now)
    other['task_summary'] = 'Different pending packet'
    assert (await b.send_ringer_manifest_release(other)).success
    second = b._bot.send_message.call_args.kwargs
    second_update = callback(second, second['reply_markup'].inline_keyboard[0][0].callback_data, now)
    observe(b, second_update)
    await b._handle_callback_query(second_update, None)
    # A reused transport event cannot release a different packet, including after restart.
    assert len(list(root.glob('*.json'))) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('case', [
    'disabled', 'no_owner', 'auth_revoked', 'wrong_owner', 'bot_actor',
    'group', 'wrong_chat', 'wrong_message', 'wrong_bot', 'edited', 'forwarded',
    'text_drift', 'bad_callback', 'no_event', 'expired', 'future', 'unknown_field',
    'duplicate_paths', 'unsafe_path', 'signed_asset', 'oversize_display',
    'symlink_store', 'public_store', 'deny', 'adapter_isolation', 'label_injection',
    'bidi_path', 'zero_width', 'invalid_uuid', 'dot_repo', 'git_path', 'prompt_overflow',
    'late_callback', 'synthetic_update', 'webhook', 'stale_generation', 'wire_drift',
    'mixed_git_path', 'blank_unicode', 'invalid_asset_type', 'link_unsupported',
    'auth_exception', 'pending_drift',
    'generation_replaced', 'native_proof_aged',
])
async def test_refusals_never_emit_an_approval(tmp_path, case, monkeypatch):
    import time
    now = int(time.time())
    root = tmp_path / 'receipts'
    a = adapter(root, enabled=case != 'disabled')
    p = packet(now)
    if case == 'no_owner':
        a.config.extra['ringer_manifest_release'].pop('owner_id')
    mutations = {
        'expired': ('expires_at', now - 1), 'future': ('expires_at', now + 5000),
        'unknown_field': ('owner_approved', True), 'duplicate_paths': ('allowed_paths', ['x.py', 'x.py']),
        'unsafe_path': ('allowed_paths', ['../x.py']),
        'signed_asset': ('asset_ref', p['asset_ref'] + '?secret=example'),
        'oversize_display': ('task_summary', 'x' * 5000),
        'label_injection': ('task_summary', 'Do nothing\nCheck: skip everything'),
        'bidi_path': ('allowed_paths', ['app/\u202ex.py']),
        'zero_width': ('check_summary', 'py\u200btest'), 'invalid_uuid': ('issue_uuid', 3),
        'dot_repo': ('canonical_repo', 'antmcc-hub/..'), 'git_path': ('allowed_paths', ['.git/config']),
        'mixed_git_path': ('allowed_paths', ['.GIT/hooks/x']),
        'blank_unicode': ('task_summary', '\u3164'), 'invalid_asset_type': ('asset_ref', 3),
    }
    if case in mutations:
        key, value = mutations[case]
        p[key] = value
    if case == 'prompt_overflow':
        p['allowed_paths'] = [f'app/{i:02d}' + 'x' * 145 for i in range(24)]
        p['task_summary'] = 'x' * 900
    if case == 'symlink_store':
        linked = tmp_path / 'linked'
        linked.symlink_to(root, target_is_directory=True)
        a.config.extra['ringer_manifest_release']['receipts_dir'] = str(linked)
    if case == 'public_store':
        root.chmod(0o755)
    result = await a.send_ringer_manifest_release(p)
    if not result.success:
        assert case in {'disabled', 'no_owner', 'expired', 'future', 'unknown_field',
                        'duplicate_paths', 'unsafe_path', 'signed_asset', 'oversize_display',
                        'symlink_store', 'public_store', 'label_injection', 'bidi_path',
                        'zero_width', 'invalid_uuid', 'dot_repo', 'git_path', 'prompt_overflow',
                        'mixed_git_path', 'blank_unicode', 'invalid_asset_type'}
        assert not list(root.glob('*.json'))
        return
    sent = a._bot.send_message.call_args.kwargs
    data = sent['reply_markup'].inline_keyboard[0][0].callback_data
    overrides = {
        'wrong_owner': {'user.id': 99}, 'bot_actor': {'user.is_bot': True},
        'group': {'message.chat': NS(type='group')}, 'wrong_chat': {'message.chat_id': 99},
        'wrong_message': {'message.message_id': 99}, 'wrong_bot': {'message.from_user': NS(id=99, is_bot=True)},
        'edited': {'message.edit_date': datetime.now(timezone.utc)},
        'forwarded': {'message.forward_origin': NS()}, 'text_drift': {'message.text': 'different'},
        'bad_callback': {'query.data': data + '0'}, 'no_event': {'update.update_id': None},
    }
    if case == 'auth_revoked':
        a.set_authorization_check(lambda *args, **kwargs: False)
    if case == 'deny':
        data = sent['reply_markup'].inline_keyboard[0][1].callback_data
    if case == 'late_callback':
        monkeypatch.setattr('plugins.platforms.telegram.ringer_release.time.time', lambda: now + 301)
    if case == 'link_unsupported':
        def unsupported(*args, **kwargs):
            raise NotImplementedError('fixture unsupported linkat')
        monkeypatch.setattr('plugins.platforms.telegram.ringer_release.os.link', unsupported)
    update = callback(sent, data, now, **overrides.get(case, {}))
    if case != 'synthetic_update':
        observe(a, update, a._polling_generation - 1 if case == 'stale_generation' else None)
    if case == 'webhook':
        a._webhook_mode = True
    if case == 'wire_drift':
        # Same event key, all earlier identity checks still pass: the fingerprint must refuse it.
        update.callback_query.from_user.id = '42'
    if case == 'auth_exception':
        def broken_auth(*args, **kwargs):
            raise RuntimeError('fixture callback resolver failure')
        a.set_authorization_check(broken_auth)
    if case == 'pending_drift':
        next(iter(a._ringer_release_pending.values())).packet['manifest_sha256'] = 'd' * 64
    if case == 'generation_replaced':
        a._begin_polling_generation()
    if case == 'native_proof_aged':
        key = (update.update_id, update.callback_query.id)
        generation, digest, stamp = a._ringer_native_events[key]
        a._ringer_native_events[key] = (generation, digest, stamp - 901)
    if case == 'adapter_isolation':
        b = adapter(tmp_path / 'other-profile')
        await b._handle_callback_query(callback(sent, data, now), None)
        assert not list((tmp_path / 'other-profile').glob('*.json'))
    else:
        await a._handle_callback_query(update, None)
    receipts = [json.loads(f.read_text()) for f in root.glob('*.json')]
    assert not any(r['decision'] == 'approve' for r in receipts)
    if case == 'deny':
        assert [r['decision'] for r in receipts] == ['deny']
        assert not (await a.send_ringer_manifest_release(p)).success


@pytest.mark.asyncio
async def test_paths_cannot_imitate_prompt_fields(tmp_path):
    import time
    a = adapter(tmp_path / 'receipts')
    p = packet(int(time.time()))
    p['allowed_paths'] = ['Policy: x', 'Expires (Unix UTC): 9999999999']
    assert (await a.send_ringer_manifest_release(p)).success
    text = a._bot.send_message.call_args.kwargs['text']
    assert '\nPolicy: x\n' not in text
    assert '\nPath: "Policy: x"\n' in text
    assert '\nPath: "Expires (Unix UTC): 9999999999"\n' in text


@pytest.mark.asyncio
async def test_post_publication_failure_never_claims_refusal(tmp_path, monkeypatch):
    import os
    import time
    now = int(time.time())
    root = tmp_path / 'receipts'
    a = adapter(root)
    assert (await a.send_ringer_manifest_release(packet(now))).success
    sent = a._bot.send_message.call_args.kwargs
    update = callback(sent, sent['reply_markup'].inline_keyboard[0][0].callback_data, now)
    observe(a, update)
    real_fsync = os.fsync
    def fault(fd):
        if list(root.glob('*.json')):
            raise OSError('fixture post-publication flush failure')
        return real_fsync(fd)
    monkeypatch.setattr('plugins.platforms.telegram.ringer_release.os.fsync', fault)
    await a._handle_callback_query(update, None)
    assert 'uncertain' in update.callback_query.answer.call_args.kwargs['text']
    assert 'refused' not in update.callback_query.answer.call_args.kwargs['text']
    # A crash may leave this complete receipt, never pretend a nondurable unlink undoes it.
    assert len(list(root.glob('*.json'))) == 1
    # Uncertainty is held in this adapter, not retried by tapping the same prompt.
    observe(a, update)
    await a._handle_callback_query(update, None)
    assert 'uncertain' in update.callback_query.answer.call_args.kwargs['text']
    new_packet = packet(now)
    new_packet['task_summary'] = 'Do not release while storage needs reconciliation'
    assert not (await a.send_ringer_manifest_release(new_packet)).success
    for marker in root.glob('*.used'):
        assert b'approve' not in marker.read_bytes()


@pytest.mark.asyncio
async def test_link_error_after_effect_is_uncertain(tmp_path, monkeypatch):
    import os
    import time
    now = int(time.time())
    root = tmp_path / 'receipts'
    a = adapter(root)
    assert (await a.send_ringer_manifest_release(packet(now))).success
    sent = a._bot.send_message.call_args.kwargs
    update = callback(sent, sent['reply_markup'].inline_keyboard[0][0].callback_data, now)
    observe(a, update)
    original = os.link
    def ambiguous(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError('fixture ambiguous filesystem outcome')
    monkeypatch.setattr('plugins.platforms.telegram.ringer_release.os.link', ambiguous)
    await a._handle_callback_query(update, None)
    assert 'uncertain' in update.callback_query.answer.call_args.kwargs['text']
    assert len(list(root.glob('*.json'))) == 1


def test_observer_failure_cannot_break_ordinary_polling(tmp_path):
    import time
    a = adapter(tmp_path / 'receipts')
    # Even unexpected release-config damage cannot escape the observational seam.
    a.config.extra = None
    request = NS(parse_json_payload=lambda payload: {'ok': True, 'result': [{'update_id': 321}]})
    before = a._updates_received_total
    a._observe_polling_request_result(request, a._polling_generation, (200, b'{}'))
    assert a._updates_received_total == before + 1


@pytest.mark.asyncio
async def test_native_event_cap_keeps_latest_callback_available(tmp_path):
    import time
    now = int(time.time())
    root = tmp_path / 'receipts'
    a = adapter(root)
    assert (await a.send_ringer_manifest_release(packet(now))).success
    sent = a._bot.send_message.call_args.kwargs
    for i in range(65):
        update = callback(sent, sent['reply_markup'].inline_keyboard[0][0].callback_data, now,
                          **{'query.id': f'fixture-native-{i}', 'update.update_id': 123 + i})
        observe(a, update)
    assert len(a._ringer_native_events) <= 64
    await a._handle_callback_query(update, None)
    assert len(list(root.glob('*.json'))) == 1
