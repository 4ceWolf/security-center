# Handover design — proposed, not enforced
First implement an observation record generated in signed initramfs under root-only volatile storage, boot-ID-bound and retained through switch-root. Include schema version, timestamp, collector version, actual evidence and failures. Emit unknown where data is absent. Normal-user tampering must fail; root tampering remains in the stated trust model.

Track separate claims: Secure Boot variable observed, image measured, TPM token configured, TPM unlock observed, signed PCR authorization verified, device scan performed, device policy decision. Never collapse these to “verified boot” without supporting evidence. systemd credentials or a keyring improve access handling but do not automatically prove provenance or resistance to compromised root.

Investigate TPM attestation/NV only after collision, ownership, wear, rollback and recovery analysis. Do not provision NV or alter PCR policies during MVP. A signed record needs a trustworthy signer and binding to current boot, and a replay-resistant verifier; a root-readable local signing key is insufficient against root.

## Implementation status
initramfs/handover.py now implements bounded root-private observations, not attestation. Current-boot and I/O failure tests pass inside the disposable VM. See testing.md. Actual switch-root retention, signed-initramfs placement and dashboard consumption remain outstanding. Do not use the record as an authority for TPM permission or Distress restoration.

Update: runtime retention is now verified through actual util-linux switch_root into a disposable LUKS/ext4 root, using a record from the final root unlock. The systemd/mkinitcpio production path is still untested, and provenance remains a local observation rather than attestation. Evidence: work/luks-vm-c0ri8g6p.

Combined systemd PID1 ordering + systemd SwitchRoot + retained root-unlock observation now verified in disposable guests for both service outcomes. See testing.md final runs e6hmkplb/hgj9ds1f. Production image/provenance and persistent antirollback guarantees remain separate, incomplete requirements.

## Staged dashboard consumer
collector.preboot now consumes the shared initramfs/handover.py parser at the proposed fixed production directory /run/security-center-boot (boot.json). This location is not populated on the laptop. Current-boot ID, bounded schema, owner/mode, attempt ordering and attested=false checks come from the shared parser. Missing evidence reports unknown; unreadable evidence unavailable; invalid/stale/contradictory evidence attention. Valid manual or TPM observations remain unknown/not attested and explicitly cannot authorize actions. A reported failed unlock is attention.

No root-private record is presented as a cryptographic attestation. Root can fabricate it; no production gate, TPM policy or Distress restoration uses this result. The fixed /run ancestry is trusted by this adapter; final directory/file no-follow checks are in the parser. Stronger provenance and concurrent hostile-root protection are not supplied.

The release maps initramfs/handover.py into /usr/local/lib/security-center/handover.py alongside the collector. Build import validation follows installed module names; staged FIM includes that destination. Release now14files and FIM scope19paths, versus live17-file baseline. The runtime rehearsal materializes the declared library layout in a private temporary directory before starting the actual daemon. Source development tools/tests explicitly include both source directories; production needs no user-controlled search path.

139Python tests pass, including six new presentation tests; the existing shared parser/VM tests remain applicable. Packaged runtime monitor-4ep_gn1n passed17modules, history crash/restart123->227events, invalid requests, database failure and socket cleanup. This rehearsal has no actual root-owned preboot record; it verifies packaging and missing-record behavior. Production producer, actual signed image, trusted attestation and privileged end-to-end handover remain pending. No boot or installed collector changes.
