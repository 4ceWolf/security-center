# Effective initrd review design — 2026-10-19

Purpose: close the archive-alias review gap before any laptop image can be signed.
This is an offline, conservative validator, not an extractor or authorization tool.
It reads the bounded parser's original archive order directly from image bytes;
serialized dictionaries sorted for display are not replay inputs.

Replay both segments in order. Resolve parent symlinks relative to the archive
root, including absolute links rooted inside that image. Resolve `..` after each
preceding symlink expansion; reject root escapes, cycles/overlong chains, missing
parents and non-directory parents. Preserve each member's raw name, archive index,
order, effective path and metadata. A member's final component is the entry being
created, not a link to follow. Repeated entries may only agree in all reviewed
semantic metadata (type/permissions, ownership, size, payload hash, link target,
mtime); retain every repetition in the audit trail. Inode/device numbering and
nlink 0 versus 1 are archive bookkeeping, not permission to accept hardlinks.
The underlying parser rejects hardlinks and special files already.

Validate every final symlink for bounded traversal and root confinement, permitting
ordinary dangling links. This intentionally accepts only a conservative subset;
it must refuse rather than imitate ambiguous kernel replacement behavior.

Compare effective images by exact path and semantic metadata. Return additions,
removals and changes without excluding directories, libraries or aliases. Keep
original image/segment hashes and full ordered provenance. An unchanged map does
not mean byte-identical or authorize signing: raw segment differences still need
review, and dependency closure, firmware testing and production capture remain
separate gates. No host boot, baseline, TPM, authentication or signing change.
Rollback: remove the new offline tool/tests; no installed state is affected.

2026-10-19 actual-image bound: the authenticated working UKI contains a
189,358,649-byte initrd, above the synthetic parser's128MiB image ceiling. Raise
the offline stored-image ceiling to256MiB; keep256MiB decoded,64MiB individual
member and16,384-entry limits. This permits bounded review of the actual capture
without relaxing alias/metadata acceptance or changing installed services.
