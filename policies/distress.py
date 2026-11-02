"""Offline deterministic reducer. No persistence, credentials or host operations.
Evidence arguments are trusted-adapter requirements, not verified by this module.
"""
from dataclasses import dataclass, replace

STATES = {'NORMAL', 'TRIGGERED', 'BOOT_REQUIRED', 'RECOVERY_SESSION', 'RESTORE_PENDING'}

@dataclass(frozen=True)
class State:
    phase: str
    boot_id: str
    policy_digest: str
    sequence: int = 0

    def valid(self):
        return (self.phase in STATES and isinstance(self.boot_id,str) and 0 < len(self.boot_id) <= 64
                and isinstance(self.policy_digest,str) and len(self.policy_digest)==64
                and all(c in '0123456789abcdef' for c in self.policy_digest)
                and type(self.sequence) is int and self.sequence >= 0)


def permits_tpm(state):
    """Missing/corrupt state never means NORMAL. Provenance is a separate gate."""
    try:
        return isinstance(state,State) and state.valid() and state.phase == 'NORMAL'
    except (TypeError,AttributeError):
        return False


def transition(state, event, *, boot_id, policy_digest,
               manual_unlock=False, owner_authenticated=False,
               power_only=False, restoration_verified=False):
    if not isinstance(state,State) or not state.valid():
        raise ValueError('Invalid persisted state; require manual recovery')
    if not isinstance(boot_id,str) or not boot_id or len(boot_id)>64:
        raise ValueError('Invalid boot identity')
    same_boot = boot_id == state.boot_id
    same_policy = policy_digest == state.policy_digest
    phase = state.phase
    if event == 'trigger' and same_boot:
        # A repeated trigger reasserts protection, including during recovery.
        next_phase = 'TRIGGERED'
    elif event == 'shutdown_prepared' and phase == 'TRIGGERED' and same_boot:
        next_phase = 'BOOT_REQUIRED'
    elif event == 'boot_observed' and not same_boot:
        if phase == 'NORMAL':
            next_phase = 'NORMAL' if same_policy else 'BOOT_REQUIRED'
        elif phase == 'RESTORE_PENDING' and same_policy and restoration_verified is True:
            next_phase = 'NORMAL'
        else:
            # Unexpected power loss cannot clear distress or preserve owner evidence.
            next_phase = 'BOOT_REQUIRED'
    elif event == 'owner_recovered' and phase == 'BOOT_REQUIRED' and same_boot:
        if not (manual_unlock is True and owner_authenticated is True and power_only is True and same_policy):
            raise ValueError('Recovery evidence incomplete; retain strict state')
        next_phase = 'RECOVERY_SESSION'
    elif event == 'normal_reboot_requested' and phase == 'RECOVERY_SESSION' and same_boot:
        if not (owner_authenticated is True and same_policy):
            raise ValueError('Owner reboot or policy continuity unverified')
        next_phase = 'RESTORE_PENDING'
    else:
        raise ValueError('Out-of-order or replayed transition')
    # Original policy digest is preserved: never silently accept concurrent changes.
    return replace(state, phase=next_phase, boot_id=boot_id, sequence=state.sequence+1)
