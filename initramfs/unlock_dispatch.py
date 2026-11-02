"""Undeployed unlock dispatcher. Adapters must verify evidence and bound calls."""

def unlock(load_decision, attempt_tpm, attempt_manual):
    try:
        decision = load_decision()
        allowed = (isinstance(decision, dict)
                   and decision.get('allow_tpm_attempt') is True
                   and decision.get('manual_recovery_required') is False)
    except Exception:
        allowed = False
    attempts = []
    if allowed:
        attempts.append('tpm')
        try:
            if attempt_tpm() is True:
                return {'unlocked': True, 'method': 'tpm', 'attempts': attempts}
        except Exception:
            pass
    attempts.append('manual')
    try:
        success = attempt_manual() is True
    except Exception:
        success = False
    return {'unlocked': success, 'method': 'manual' if success else 'none', 'attempts': attempts}
