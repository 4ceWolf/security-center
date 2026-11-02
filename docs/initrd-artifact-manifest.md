# Captured test-initrd artifact manifest — 2026-10-18

`tools/initrd_manifest.py` inventories the complete single-newc archive used by our
disposable guest harness, without extracting it. Regular files carry content
SHA256, mode, uid/gid, size, mtime and link count; symlinks also carry their exact
target. Directories and parent relationships are included. Unsupported archive
variants, special nodes/hardlinks, malformed/truncated/trailing data, unsafe or
duplicate names and entries beneath a symlink require review.

Bounds:8192members,64MiB/member,256MiB total decoded archive,4096byte member names
and symlink targets. Hashing uses64KiB chunks. This parser supports our packer's
known single-newc format, not concatenated microcode/newc images or arbitrary UKIs.
All manifests explicitly start approved=False. Matching an existing capture is not
authorization to sign, install or boot a production image.

The VM harness now copies the gzip artifact into a Linux memfd, seals writes,
growth, shrinkage and seal changes, hashes it, parses a second descriptor of that
same sealed object, saves initrd-manifest.json and its digest in report.json, and
passes the sealed descriptor to QEMU. A subsequent path replacement/edit therefore
cannot change the initrd consumed by this run. The latest harness also attempts a
write after sealing and requires PermissionError before proceeding. The descriptor
is closed after QEMU. This adds a temporary compressed-image memory copy (~22MB in
the first run), separate from the384MiB test guest and resident security services.

This binds the test report to captured initrd bytes; it does not attest the kernel,
firmware, QEMU, loaded runtime unit graph or behavior of captured helpers. The
kernel is still selected from the host's installed kernel path. Guest fixtures
intentionally generate/replace service and adapter files after boot; those runtime
outputs require their own snapshot checks. No firmware Secure Boot or actual
measured UKI chain is claimed. Complete production-image manifests, trusted source
review, signing checkpoints and cold-boot/runtime verification remain pending.

Four new tests verify file/symlink metadata, changed contents/modes/new-file refusal,
unsafe/duplicate/special paths, truncated and appended archives. Python suite290
passed. First sealed-image failure-checker guest ft74_a4d passed, exit0,28.69s,
508members; its compressed initrd SHA256 is
4a18a1ae083b2825c561210f4f3857a2cd1df2d9051c1aa94faf65dbbb5620c3.
An independent post-run parse/hash of the saved artifact matched the complete
manifest and the report's manifest digest. No host boot/TPM/authentication,
installed files or approved FIM baseline changed.

Final successful-checker guest wpldnf_g passed, exit0,20.62s,508members, including
the explicit post-seal write-refusal assertion and all prior required markers.
Manifest SHA256 c0fd62d9b586f23baceea1e635fa0b66d6c2a373798944034532f667e5129ecb;
compressed initrd SHA25680a2c1764f2514a2efec0e00b36a2fa42d6aac8a608decde499cbed8bfa5c789.
