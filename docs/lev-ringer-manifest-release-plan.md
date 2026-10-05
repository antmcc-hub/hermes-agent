# Exact-packet Hermes release bridge Implementation Plan

> For the implementing agent: implement task by task, verify each step, and never activate from this build approval.

Goal: Carry a genuine owner Telegram callback, bound to an immutable validated release packet and its exact displayed presentation, into protected existing coordinator artifacts.

Architecture: A topical module beside the existing Telegram adapter owns strict packet validation, exact prompt binding, single-use pending requests and atomic receipt persistence. Two adapter entry points send the bounded prompt and dispatch only its dedicated callback prefix. Generic text approvals, supplied source strings and Linear history never authenticate this route. No model tool, web endpoint, new secret or database is introduced. No production configuration changes.

Owner continuation approval permits further bounded fixes and review cycles. Native provenance is enforced through a minimal third seam in the existing generation-fenced getUpdates observer. Live installation and canary gates remain separate.

Tech Stack: Python standard library, existing python-telegram-bot adapter, existing SendResult, repository test runner and current test virtualenv.

Canonical target: antmcc-hub/hermes-agent owned downstream fork, base 7a4881394457a71cb22b74ebbe64eb9c803c3527. Direct Mini worktree. No upstream contribution or automatic installation.

## Task 1: reproduce missing exact-packet bridge

Create tests/gateway/test_telegram_manifest_release.py. The complete failing tests are in that file: one positive single-use/restart invariant plus parametrized refusals through the real TelegramAdapter callback dispatcher. Minimal initial regression:

```python
result = await adapter.send_ringer_manifest_release(packet)
assert result.success
await adapter._handle_callback_query(owner_callback, None)
assert receipt['packet']['manifest_sha256'] == packet['manifest_sha256']
```

Run HERMES_PYTHON=/Users/lev-ai/code/hermes-agent/.venv/bin/python scripts/run_tests.sh tests/gateway/test_telegram_manifest_release.py -q. Expected RED: missing send_ringer_manifest_release. This is fixture-only, not a live Telegram send.

## Task 2: immutable prompt and fail-closed callback

Create plugins/platforms/telegram/ringer_release.py and minimally extend plugins/platforms/telegram/adapter.py. Strictly validate one versioned bounded packet with exact digest/scope/base/attachment/policy fields, clone it before display, and bind a cryptographically random request ID to exact private-chat prompt text and the resulting bot/message IDs. Gate on a configured owner ID AND the adapter's current authorization check. Require a non-bot actor, authenticated live callback event ID, unedited/unforwarded bot-owned message and nonexpired pending packet. No fallback to mutable card contents or generic /approve.

Persist one fully written, fsynced mode-0600 receipt by atomic no-overwrite link in an existing owner-only mode-0700 store. Both approve and deny consume the packet. Default-off and invalid configuration refuse. Restart loses pending prompts but preserves consumed packet receipts; re-prompt cannot reset consumption.

Implementation shape:

```python
async def send_ringer_manifest_release(self, packet):
    from plugins.platforms.telegram.ringer_release import send_release
    return await send_release(self, packet)
```

Dedicated callback dispatch calls the module only for rm: messages; no generic new core tool. Use the existing adapter auth resolver, never read launch-profile credentials or process environment.

Rerun Task 1, then commit the narrow implementation and invariant tests only after PASS.

## Task 3: integration, review and owner handoff

Run new tests plus tests/gateway/test_telegram_approval_buttons.py, test_telegram_callback_auth_fail_closed.py and test_telegram_auth_check.py through scripts/run_tests.sh with the existing test interpreter. Inspect exact diff, run secret-safe review, and run a bounded independent review where available; record any unavailable review accurately. Commit documentation with the wire contract and trust boundary. Push the branch to the owned fork, open a bot-authored PR, request antmcc-hub review and verify OPEN/review request via API.

## Acceptance and remaining gates

This bridge PR does not complete OE admission or LEV-590. It provides the source-side event contract for that follow-on. A protected receipt directory is a boundary only if lower-trust Ringer workers AND model terminal/file/code-execution paths cannot write it or the gateway's pending state. Mode 0700 alone does not separate processes with the same UID. Refuse live use until the actual OS/sandbox restriction is demonstrated under LEV-590/592. This module does not claim to contain a compromised coordinator/admin.

Before canary: owner-reviewed bridge and OE PRs merged; genuine transport round trip; source event binding independently verified; store isolation proven; exact packet revocation and no duplicate starts; separate LEV-234 authorization. A fixture receipt is never a production release.

## Scheduled Task Impact

No schedule, LaunchAgent, daemon, connector, token or runtime switch change. New route is off by default. Live installation/restart and activation remain separately approved operations. Existing Git-manifest route stays unchanged.

## Wire contract and operational hold

The source schema is version 1. Required fields are version, issue_uuid, issue, project_id, canonical_repo, base_revision, attachment_id, asset_ref, byte_length, manifest_sha256, contract_sha256, contract_version, allowed_paths, patch_destination, policy_id, task_summary, check_summary and expires_at. Unknown fields are refused. Expiry is an integer UTC Unix timestamp, no more than 900 seconds ahead. The packet digest is SHA-256 over ASCII JSON with sorted keys and separators (comma, colon), no whitespace and no non-finite numbers. Exact paths and full base/manifest/contract digests are bound; the manifest itself is not copied into the prompt.

Future operator configuration belongs in this adapter's PlatformConfig.extra.ringer_manifest_release object: enabled (true only after release authority), owner_id (decimal string), receipts_dir (absolute path to an existing coordinator-owned directory). There are no new environment variables. Empty or missing configuration refuses. Do not set these keys in the production profile from this PR.

The coordinator calls TelegramAdapter.send_ringer_manifest_release with the complete immutable packet. That method is not registered as a model tool, generic CLI approval, MCP tool or slash command. A prompt alone cannot approve anything. The dedicated callback dispatcher receives the Telegram Update directly, checks the current owner allowlist and exact bot/message/text/request binding, then persists a version-1 receipt containing decision, packet, packet_digest, recorded_at and source. Source includes kind=telegram_callback, actor_id, chat_id, bot_id, message_id, update_id and callback_id. No transport token or signed download URL is persisted.

Source authenticity relies on the existing authenticated Telegram polling transport and the protected coordinator/gateway process, not on the shape of update_id, callback_id or the random request handle. None of those identifiers is a signature. The existing generation-fenced getUpdates observer records a bounded, expiring fingerprint of relevant callback fields only for pending release handles. Callback dispatch consumes that exact fingerprint once and refuses unobserved or changed updates, stale generations, stopped polling, teardown and all webhook modes. No raw update content is persisted or logged. Do not expose the observer or gateway state to model code execution or worker write access: a compromised coordinator is explicitly outside this boundary.

OE must construct summaries from the exact downloaded, SHA-256/byte-length-verified manifest and compare its real task/check/expected-file policy against the packet. Supplied human-readable prose alone is not that comparison. The source-side bridge intentionally does not download or execute the manifest. The consumer must require decision=approve (never mere file existence), validate schema, recompute the packet digest, independently authenticate the protected event provenance, check expiry, compare current card/contract/base/policy/attachment identity and revocation, and retain the independent issue+manifest attempt ledger. LEV-590 admission work supplies these checks before any execution. A changed expiry after denial may produce a new owner decision; it cannot authorize replay of a consumed OE attempt.

Each receipt is a mode-0600 <packet_digest>.json file under the existing mode-0700 directory. A separate event-<event_sha256>.used file consumes the transport event across distinct packets. event_sha256 hashes canonical JSON containing bot_id, update_id and callback_id, not the packet. This marker contains only "consumed" and is flushed, including its directory entry, before receipt publication. A crash between event consumption and packet publication refuses replay conservatively without a decision record. Consumers must ignore .release-* temporary files and .used markers as release authority, strictly validate complete .json receipts and preserve issue+manifest attempt identity independently of this packet digest. Different packet expiry or a new approval event cannot reset OE attempts.

If any storage operation fails once receipt publication has been attempted, including an ambiguous link failure, the toast reports uncertain storage and demands operator reconciliation. It never claims refusal or attempts a nondurable unlink rollback; the complete receipt may exist or survive a crash. Live admission must remain disabled during any unresolved storage fault. Deployment must use and verify a local POSIX filesystem with durable atomic no-overwrite links, not a network share. Temporary-file cleanup failure after a successful durable commit does not overturn the recorded decision. Deployment must also prove every receipt-store ancestor is protected against lower-trust writes; checking the leaf mode is not a substitute for that OS-level proof.

The native fingerprint regression preserves the (update_id, callback_id) lookup key and changes actor ID representation after observation, so it exercises the fingerprint mismatch rather than a missing key or an earlier identity refusal. Separate regressions record valid proof before replacing its generation, and age only the monotonic proof timestamp while packet expiry stays valid. Pending packet digest/presentation are recomputed before persistence. Native proof is capped at the latest 64 events; new callbacks evict the oldest rather than remain blocked until timeout. Unexpected observer/config failures cannot escape into ordinary polling; callback exceptions never reach the generic raw-update logging path. Prompts explicitly use parse_mode=None so configured formatting defaults cannot reinterpret exact JSON strings.

After a committed approve/deny decision, remove the keyboard best-effort. UI errors cannot overturn persistence. Repeat, missing, expired or invalid callbacks state that no new release was recorded and any earlier decision is unchanged, never implying a previous approval was withdrawn. A storage uncertainty holds further sends/callbacks in that adapter until operator reconciliation; restarting clears memory, not the operational requirement to keep the route disabled and reconcile the protected store.

Ordinary os.fsync checks process-restart ordering, not a claimed power-loss guarantee. On macOS, actual drive-cache durability needs an audited F_FULLFSYNC strategy and filesystem/hardware evidence before any live enablement, as described in the [Apple fsync manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html). These fixture tests do not prove power-loss recovery. That host-specific durability gate, native PTB round trip and OS isolation remain unresolved activation checks.

Prompt policy/task/check text and every allowed path are ASCII JSON-quoted, with each path explicitly labelled Path. Quotes, label-like filenames and Unicode are rendered unambiguously as exact strings, not prompt field labels. Visible-line validation additionally refuses controls, combining marks, blank filler characters, non-NFC text and surrounding whitespace. Case-insensitive .git path segments are refused. Hidden packet fields remain bound by the displayed packet digest; OE must independently validate them against the card/manifest, not claim they were all displayed to the owner.

Additional TDD slice: update tests/gateway/test_telegram_manifest_release.py with regressions for valid label-like paths, synthetic/webhook/stale/changed native callbacks, mixed-case Git metadata, invisible filler, malformed asset type, unsupported atomic link and post-publication directory failure. Run the existing isolated runner; expect failures against the prior implementation. Fix plugins/platforms/telegram/ringer_release.py and the six-line polling-observer seam in adapter.py, then rerun those tests plus approval/auth/polling-progress/ingress-delivery-gap files. Commit all four scoped files only after passing verification and source-based review adjudication.

Fixture verification: the repository's gateway tests mock optional python-telegram-bot types when the test environment lacks that extra. These tests exercise real adapter/module imports with fake transport and faithful keyboard fields. They do not prove a live Telegram API round trip. That round trip, source provenance, model/worker OS isolation and owner activation remain mandatory canary checks. Same-user mode-0700 permissions are not sufficient isolation on their own.
