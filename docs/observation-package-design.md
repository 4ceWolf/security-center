# Observation package capture design — 2026-10-18

Purpose: create a project-local captured input tree for review, never an installed
package, signed UKI or authorization to run a privileged build. Capture fixed
project payloads, installed Python interpreter/selected stdlib/extensions and their
resolved ELF dependencies, unit/hook, exact policy and explicit reviewed root
mapping. Use no caller-provided source directory, executable command or destination
outside a fresh project work/observation-package-* tree. Mapping syntax is bounded.

Record source path, symlink resolution, content SHA256, size and mode. Refuse changes
during capture and oversized/nonregular sources. Pin all captured inputs in an
input manifest; its digest (excluding itself and source.sha256) is the embedded
producer's source digest. Final package manifest additionally binds that digest
file and input manifest. Neither manifest is approved or self-authenticating.
No keys, TPM tokens, LUKS header, actual account credential or signing config is
copied. Candidate policy is currently project source and must be separately
reviewed against the root-owned saved candidates before production publication.

The Python runtime is a bounded selected subset used in the guest, not a claim of
complete general Python support. Its capture and mkinitcpio hook additions must be
compared in a full Arch disposable build. ldd is invoked only on the fixed installed
Python binary/extensions, with a bounded timeout; no captured project script is
executed. Flatten copied installed symlinks to captured regular file bytes at the
same target paths and retain source-link metadata for review.

Validation: manifest covers every staged regular file, refuses unexpected/symlinked
entries, wrong modes/digests and unsafe paths. Test tampering and escaping mappings.
A source manifest alone does not bind kernel, microcode, stub, command line, full
initrd or PCR signatures; the later image manifest and specialist checkpoint do.
Rollback: delete the captured work directory after no process uses it; no host
state requires rollback. Privileged image build/sign/install remains pending.

Next validation uses an unsigned disposable initrd assembled by installed mkinitcpio
inside an unprivileged bubblewrap namespace. Read-only /usr is its tool/package
source, overlaid with the captured observer package; /etc is synthetic; no host
/boot, secrets, TPM, network or host block devices are available. Only a new project
work directory is writable. Use explicit synthetic config and --nopost, no preset,
no UKI/signing options. This is guest image assembly, not the proposed laptop build.
Retain generated tree/logs, validate included hook/payload and image inventory;
results do not establish firmware signatures or hardware recovery.
