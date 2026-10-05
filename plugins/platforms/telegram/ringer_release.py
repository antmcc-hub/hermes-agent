"""Downstream exact-packet owner release ingress (LEV-590), off by default.

Receipts rely on coordinator OS isolation, not on a claimed actor in Linear.
No function in this module is registered as a model tool or text command.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import tempfile
import time
import unicodedata
from urllib.parse import urlsplit
from uuid import UUID

from gateway.platforms.base import SendResult, utf16_len


FIELDS = frozenset({
    'version', 'issue_uuid', 'issue', 'project_id', 'canonical_repo', 'base_revision',
    'attachment_id', 'asset_ref', 'byte_length', 'manifest_sha256', 'contract_sha256',
    'contract_version', 'allowed_paths', 'patch_destination', 'policy_id',
    'task_summary', 'check_summary', 'expires_at',
})
CALLBACK = re.compile(r'^rm:(approve|deny):([0-9a-f]{32})$')


class ReleaseRefused(ValueError):
    """Safe, fixed reason; never forward transport errors or packet contents."""


class StorageUncertain(OSError):
    """Publication may have happened; never claim refusal or attempt nondurable rollback."""


def _visible_line(text):
    return isinstance(text, str) and bool(text.strip()) and text == text.strip() and (
        unicodedata.normalize('NFC', text) == text) and all(
        not unicodedata.category(char).startswith('C')
        and not unicodedata.category(char).startswith('M')
        and char not in '\u2028\u2029\u3164\u2800' for char in text
    )


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def _packet(value, now):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ReleaseRefused('packet_schema')
    try:
        raw = _canonical(value)
        if len(raw) > 16384:
            raise ReleaseRefused('packet_size')
        packet = json.loads(raw)
        for key in ('issue_uuid', 'project_id', 'attachment_id'):
            if not isinstance(packet[key], str) or str(UUID(packet[key])) != packet[key]:
                raise ReleaseRefused('packet_identity')
        if type(packet['version']) is not int or packet['version'] != 1:
            raise ReleaseRefused('packet_version')
        if type(packet['contract_version']) is not int or packet['contract_version'] != 1:
            raise ReleaseRefused('contract_version')
        if not re.fullmatch(r'LEV-[1-9][0-9]*', packet['issue']):
            raise ReleaseRefused('issue_identity')
        if not re.fullmatch(r'antmcc-hub/[A-Za-z0-9][A-Za-z0-9_.-]*', packet['canonical_repo']):
            raise ReleaseRefused('repository_identity')
        for key, length in (('base_revision', 40), ('manifest_sha256', 64), ('contract_sha256', 64)):
            if not re.fullmatch('[0-9a-f]{' + str(length) + '}', packet[key]):
                raise ReleaseRefused('packet_digest')
        if type(packet['byte_length']) is not int or not 0 < packet['byte_length'] <= 1048576:
            raise ReleaseRefused('manifest_size')
        expiry = packet['expires_at']
        if type(expiry) is not int or not now < expiry <= now + 900:
            raise ReleaseRefused('packet_expiry')
        if not isinstance(packet['asset_ref'], str):
            raise ReleaseRefused('asset_reference')
        asset = urlsplit(packet['asset_ref'])
        if (asset.scheme != 'https' or asset.netloc != 'uploads.linear.app'
                or asset.query or asset.fragment or not asset.path.startswith('/')):
            raise ReleaseRefused('asset_reference')
        paths = packet['allowed_paths']
        if not isinstance(paths, list) or not 0 < len(paths) <= 24:
            raise ReleaseRefused('allowed_paths')
        for path in paths:
            if (not isinstance(path, str) or not path or len(path) > 160
                    or not _visible_line(path)
                    or PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts
                    or any(part.casefold() == '.git' for part in PurePosixPath(path).parts)
                    or str(PurePosixPath(path)) != path or path == '.'
                    or any(c in path for c in '\\*?[]\x00\r\n')):
                raise ReleaseRefused('allowed_paths')
        if len(set(paths)) != len(paths):
            raise ReleaseRefused('allowed_paths')
        for key in ('patch_destination', 'policy_id', 'task_summary', 'check_summary'):
            text = packet[key]
            if not _visible_line(text) or len(text) > 1000:
                raise ReleaseRefused('packet_summary')
        if packet['patch_destination'] != packet['canonical_repo'] + ':main':
            raise ReleaseRefused('patch_destination')
    except (TypeError, ValueError, OverflowError) as exc:
        if isinstance(exc, ReleaseRefused):
            raise
        raise ReleaseRefused('packet_schema') from None
    return packet, hashlib.sha256(raw).hexdigest()


def _settings(adapter):
    config = adapter.config.extra.get('ringer_manifest_release')
    if not isinstance(config, dict) or config.get('enabled') is not True:
        raise ReleaseRefused('release_disabled')
    owner = config.get('owner_id')
    if not isinstance(owner, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', owner):
        raise ReleaseRefused('owner_missing')
    root = Path(config.get('receipts_dir', ''))
    if not root.is_absolute() or root.is_symlink():
        raise ReleaseRefused('receipt_store')
    mode = root.stat()
    if not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.geteuid() or stat.S_IMODE(mode.st_mode) != 0o700:
        raise ReleaseRefused('receipt_store')
    return owner, root.resolve()


def _display(packet, digest):
    quoted = lambda value: json.dumps(value, ensure_ascii=True)
    text = (
        'Approve this exact Ringer work order before execution?\n'
        'This is NOT approval to merge code or activate a runtime.\n\n'
        f"Issue: {packet['issue']}\nRepo: {packet['canonical_repo']}\n"
        f"Base: {packet['base_revision']}\nManifest SHA-256: {packet['manifest_sha256']}\n"
        f"Packet SHA-256: {digest}\nPolicy: {quoted(packet['policy_id'])}\n"
        f"Task: {quoted(packet['task_summary'])}\nCheck: {quoted(packet['check_summary'])}\n"
        + 'Allowed paths (JSON-quoted exact strings):\n'
        + '\n'.join('Path: ' + quoted(path) for path in packet['allowed_paths'])
        + f"\nExpires (Unix UTC): {packet['expires_at']}"
    )
    if utf16_len(text) > 3800:
        raise ReleaseRefused('prompt_size')
    return text


@dataclass(frozen=True)
class Pending:
    packet: dict
    digest: str
    text: str
    owner: str
    bot_id: str
    message_id: int
    root: Path


def _persist(root, digest, receipt):
    """Publish only complete bytes, with no overwrites or partially-visible approval."""
    payload = _canonical(receipt)
    fd, path = tempfile.mkstemp(prefix='.release-', dir=root)
    publication_attempted = False
    target = root / (digest + '.json')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        source = receipt['source']
        event_key = hashlib.sha256(_canonical({
            'bot_id': source['bot_id'], 'update_id': source['update_id'],
            'callback_id': source['callback_id'],
        })).hexdigest()
        # Consumed transport-event data is not a decision, even if a consumer reads it.
        event_fd = os.open(root / ('event-' + event_key + '.used'),
                           os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(event_fd, 'wb') as marker:
            marker.write(b'consumed\n')
            marker.flush()
            os.fsync(marker.fileno())
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        # Durable event consumption precedes publication. A link error can be ambiguous on NFS.
        publication_attempted = True
        os.link(path, target, follow_symlinks=False)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        if publication_attempted:
            # An unlink is not a crash-durable undo. Retain evidence for reconciliation.
            raise StorageUncertain('receipt_status_uncertain') from None
        raise
    finally:
        try:
            os.unlink(path)
        except OSError:
            # A leaked temporary inode is not release authority; do not overturn a commit.
            pass


def _polling_ready(adapter):
    return (getattr(adapter, '_webhook_mode', None) is False
            and getattr(adapter, '_teardown_started', True) is False
            and getattr(adapter, '_polling_progress_accepting', False) is True
            and getattr(getattr(getattr(adapter, '_app', None), 'updater', None), 'running', False) is True)


def _wire_fields(raw):
    query = raw['callback_query']
    message = query['message']
    actor, bot, chat = query['from'], message['from'], message['chat']
    return [raw['update_id'], query['id'], query['data'], actor['id'], actor['is_bot'],
            chat['id'], chat['type'], message['message_id'], message['text'], bot['id'], bot['is_bot'],
            message.get('edit_date') is not None, message.get('forward_origin') is not None]


def observe_native_callbacks(adapter, updates, generation):
    """Only the native, generation-fenced getUpdates observer calls this producer."""
    config = adapter.config.extra.get('ringer_manifest_release')
    if (not isinstance(config, dict) or config.get('enabled') is not True
            or not _polling_ready(adapter) or generation != adapter._polling_generation
            or not isinstance(updates, list)):
        return
    now = time.monotonic()
    events = getattr(adapter, '_ringer_native_events', {})
    events = {key: value for key, value in events.items()
              if value[0] == generation and now - value[2] <= 900}
    for raw in updates[:100]:
        try:
            fields = _wire_fields(raw)
            match = CALLBACK.fullmatch(fields[2])
            if (not match or match.group(2) not in getattr(adapter, '_ringer_release_pending', {})
                    or type(fields[0]) is not int or fields[0] <= 0
                    or not isinstance(fields[1], str) or not 0 < len(fields[1]) <= 200):
                continue
            digest = hashlib.sha256(_canonical(fields)).hexdigest()
            key = (fields[0], fields[1])
            if key not in events and len(events) >= 64:
                events.pop(next(iter(events)))
            events[key] = (generation, digest, now)
        except (KeyError, TypeError, ValueError, AttributeError):
            # Observation must not break ordinary gateway traffic, nor log raw updates.
            continue
    adapter._ringer_native_events = events


def _consume_native_callback(adapter, update):
    if not _polling_ready(adapter):
        raise ReleaseRefused('native_transport')
    query, message = update.callback_query, update.callback_query.message
    fields = [update.update_id, query.id, query.data, query.from_user.id, query.from_user.is_bot,
              message.chat_id, message.chat.type, message.message_id, message.text,
              message.from_user.id, message.from_user.is_bot,
              message.edit_date is not None, message.forward_origin is not None]
    proof = getattr(adapter, '_ringer_native_events', {}).pop((update.update_id, query.id), None)
    if (proof is None or proof[0] != adapter._polling_generation
            or time.monotonic() - proof[2] > 900
            or proof[1] != hashlib.sha256(_canonical(fields)).hexdigest()):
        raise ReleaseRefused('native_transport')


async def send_release(adapter, value):
    """Coordinator-only entry point; sending a prompt cannot manufacture an approval."""
    requests, request_id = None, None
    sending = False
    try:
        owner, root = _settings(adapter)
        if getattr(adapter, '_ringer_release_storage_uncertain', False):
            raise ReleaseRefused('operator_reconciliation_required')
        if not _polling_ready(adapter):
            raise ReleaseRefused('native_transport')
        if not adapter._is_callback_user_authorized(owner, chat_id=owner, chat_type='private'):
            raise ReleaseRefused('owner_not_authorized')
        packet, digest = _packet(value, int(time.time()))
        if (root / (digest + '.json')).exists():
            raise ReleaseRefused('packet_consumed')
        text = _display(packet, digest)
        bot_id = str(adapter._bot.id)
        if not re.fullmatch(r'[1-9][0-9]*', bot_id):
            raise ReleaseRefused('bot_identity')
        requests = getattr(adapter, '_ringer_release_pending', None)
        if requests is None:
            requests = adapter._ringer_release_pending = {}
        now = int(time.time())
        for key in list(requests):
            if requests[key].packet['expires_at'] <= now:
                del requests[key]
        if len(requests) >= 8 or any(p.digest == digest for p in requests.values()):
            raise ReleaseRefused('pending_limit')
        request_id = secrets.token_hex(16)
        requests[request_id] = Pending(packet, digest, text, owner, bot_id, 0, root)
        from telegram import InlineKeyboardButton, InlineKeyboardMarkup
        keyboard = InlineKeyboardMarkup([[
            InlineKeyboardButton('Approve exact packet', callback_data='rm:approve:' + request_id),
            InlineKeyboardButton('Deny', callback_data='rm:deny:' + request_id),
        ]])
        sending = True
        message = await adapter._bot.send_message(chat_id=int(owner), text=text,
                                                reply_markup=keyboard, parse_mode=None)
        if type(message.message_id) is not int or message.message_id <= 0:
            raise ReleaseRefused('message_identity')
        requests[request_id] = Pending(packet, digest, text, owner, bot_id, message.message_id, root)
        return SendResult(success=True, message_id=str(message.message_id))
    except (ReleaseRefused, OSError, NotImplementedError, TypeError, ValueError):
        if requests is not None and request_id is not None:
            requests.pop(request_id, None)
        return SendResult(success=False, error='ringer_release_refused')
    except Exception:
        # Telegram exceptions can include a token in their URL: never propagate them.
        if requests is not None and request_id is not None:
            requests.pop(request_id, None)
        return SendResult(success=False, error=(
            'ringer_release_transport_failed' if sending else 'ringer_release_refused'))


async def handle_release(adapter, update):
    query = update.callback_query
    match = CALLBACK.fullmatch(query.data) if isinstance(query.data, str) else None
    result = 'No new Ringer release recorded. Any earlier decision is unchanged.'
    try:
        if getattr(adapter, '_ringer_release_storage_uncertain', False):
            raise StorageUncertain('operator_reconciliation_required')
        if not match:
            raise ReleaseRefused('callback_shape')
        decision, request_id = match.groups()
        owner, root = _settings(adapter)
        pending = getattr(adapter, '_ringer_release_pending', {}).get(request_id)
        if pending is None or pending.owner != owner or pending.root != root:
            raise ReleaseRefused('pending_missing')
        user, message = query.from_user, query.message
        if (str(user.id) != owner or user.is_bot is not False
                or not adapter._is_callback_user_authorized(owner, chat_id=owner, chat_type='private')
                or str(message.chat_id) != owner or message.chat.type != 'private'
                or message.message_id != pending.message_id or message.text != pending.text
                or str(message.from_user.id) != pending.bot_id or message.from_user.is_bot is not True
                or message.edit_date is not None or message.forward_origin is not None
                or type(update.update_id) is not int or update.update_id <= 0
                or not isinstance(query.id, str) or not 0 < len(query.id) <= 200
                or pending.packet['expires_at'] <= int(time.time())):
            raise ReleaseRefused('callback_provenance')
        _consume_native_callback(adapter, update)
        _, digest = _packet(pending.packet, int(time.time()))
        if digest != pending.digest or _display(pending.packet, digest) != pending.text:
            raise ReleaseRefused('pending_drift')
        receipt = {
            'version': 1, 'decision': decision, 'packet': pending.packet,
            'packet_digest': pending.digest, 'recorded_at': int(time.time()),
            'source': {'kind': 'telegram_callback', 'actor_id': owner, 'chat_id': owner,
                       'bot_id': pending.bot_id, 'message_id': pending.message_id,
                       'update_id': update.update_id, 'callback_id': query.id},
        }
        _persist(root, pending.digest, receipt)
        adapter._ringer_release_pending.pop(request_id)
        result = 'Exact Ringer packet approved.' if decision == 'approve' else 'Ringer packet denied.'
        try:
            await query.edit_message_reply_markup(reply_markup=None)
        except Exception:
            # UI cleanup cannot overturn a committed decision or leak a transport URL.
            pass
    except StorageUncertain:
        adapter._ringer_release_storage_uncertain = True
        result = 'Ringer receipt status uncertain. Do not execute; operator review required.'
    except Exception:
        # Missing or partially-inaccessible callbacks must never reach a model or generic approval.
        pass
    try:
        await query.answer(text=result)
    except Exception:
        # The durable decision is independent of a failed toast; do not log a token-bearing URL.
        return
