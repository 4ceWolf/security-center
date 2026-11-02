"""Bounded manual-only retry coordination; no credentials or TPM operations.

Adapters own terminal input, per-call timeouts and actual mapping verification.
Unexpected callback exceptions propagate. A retry requires explicit True consent.
"""


def recover(attempt, confirm_retry, limit=3):
    if type(limit) is not int or not 1 <= limit <= 3:
        raise ValueError('Manual attempt limit must be between one and three')
    for count in range(1, limit+1):
        if attempt() is True:
            return dict(unlocked=True, attempts=count, reason='Manual unlock verified')
        if count == limit:
            return dict(unlocked=False, attempts=count, reason='Manual attempts exhausted')
        if confirm_retry(count) is not True:
            return dict(unlocked=False, attempts=count, reason='Manual recovery paused')
