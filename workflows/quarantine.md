# Workflow: Quarantine, restore and permanent deletion

**Quarantine** (`action: quarantine`, approved by the user):
- The executor re-validates the target: same path, not a link or junction, SHA-256 unchanged.
- It renames the file in place, streams it into the vault with AES-256-GCM (chunked,
  authenticated), verifies the vault copy by reading it back, and only then removes the original.
- It records the original path, hash, size, timestamps, permissions and attributes. The vault
  directory is restricted to the user (and SYSTEM). Blobs cannot be executed.
- If the file is in use, nothing changes and the result is `code: locked`. The user stops the
  program or reboots, then runs `sentry remediate` again.

**Restore** (if it was a false positive): `sentry quarantine restore Q-…` (human, approval). If
the original path is occupied, the file is written to `<path>.restored`.

**Permanent deletion**: `sentry quarantine delete Q-…` (human, separate approval, cannot be
undone). It is refused for items that came from protected OS or security locations.

Listing: `sentry_quarantine_list`.
