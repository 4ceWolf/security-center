"""Offline recovery preflight. Produces review evidence, never an enrollment command."""
import hashlib
import json
import re

HEX = re.compile(r'^[0-9a-f]{64}$')
FIELDS = {'schema_version','device_uuid','expected_device_uuid','secure_boot',
          'lockdown','manual_slot_0_present','manual_passphrase_verified',
          'public_key_sha256','expected_public_key_sha256','tokens',
          'intentional_change_confirmed','header_backup_verified'}
TOKEN_FIELDS = {'direct_pcrs','signed_pcrs','policy_reference','pcr_bank','srk_present','keyslots'}


def prepare(evidence):
    """Caller evidence is untrusted. Even a clean result requires privileged recapture.

    No passphrase, raw token or TPM blob belongs in this schema. A digest binds the
    proposal to its inputs; it is not authorization and cannot be replayed as Apply.
    """
    if not isinstance(evidence,dict) or set(evidence)!=FIELDS:
        raise ValueError('Invalid recovery evidence')
    if type(evidence['schema_version']) is not int or evidence['schema_version']!=1:
        raise ValueError('Unsupported recovery schema')
    flags=('secure_boot','manual_slot_0_present','manual_passphrase_verified',
           'intentional_change_confirmed','header_backup_verified')
    if any(type(evidence[k]) is not bool for k in flags):
        raise ValueError('Invalid recovery evidence flag')
    if evidence['lockdown'] not in ('none','integrity','confidentiality','unknown'):
        raise ValueError('Invalid lockdown evidence')
    for key in ('device_uuid','expected_device_uuid'):
        if not isinstance(evidence[key],str) or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',evidence[key]):
            raise ValueError('Invalid volume identity')
    for key in ('public_key_sha256','expected_public_key_sha256'):
        if not isinstance(evidence[key],str) or not HEX.fullmatch(evidence[key]):
            raise ValueError('Invalid public-key fingerprint')
    tokens=evidence['tokens']
    if not isinstance(tokens,list) or len(tokens)>32:
        raise ValueError('Invalid token summary')
    for token in tokens:
        if not isinstance(token,dict) or set(token)!=TOKEN_FIELDS:
            raise ValueError('Invalid or private token fields')
        for key in ('direct_pcrs','signed_pcrs'):
            if not isinstance(token[key],list) or len(token[key])>24 or any(type(n) is not int or not 0<=n<=23 for n in token[key]) or len(set(token[key]))!=len(token[key]):
                raise ValueError('Invalid PCR selection')
        if type(token['srk_present']) is not bool:
            raise ValueError('Invalid SRK evidence')
        if not isinstance(token['policy_reference'],str) or len(token['policy_reference'])>64 or not isinstance(token['pcr_bank'],str) or len(token['pcr_bank'])>16:
            raise ValueError('Invalid token policy')
        slots=token['keyslots']
        if not isinstance(slots,list) or not slots or len(slots)>32 or any(not isinstance(s,str) or not re.fullmatch(r'(?:[0-9]|[12][0-9]|3[01])',s) for s in slots) or len(set(slots))!=len(slots):
            raise ValueError('Invalid token keyslots')
    blockers=[]
    for key,code in (('secure_boot','secure_boot_required'),('manual_slot_0_present','manual_slot_missing'),
                     ('manual_passphrase_verified','manual_passphrase_unverified'),
                     ('intentional_change_confirmed','cause_unreviewed'),('header_backup_verified','backup_unverified')):
        if not evidence[key]:blockers.append(code)
    if evidence['lockdown'] not in ('integrity','confidentiality'):blockers.append('lockdown_unverified')
    if evidence['device_uuid']!=evidence['expected_device_uuid']:blockers.append('volume_changed')
    if evidence['public_key_sha256']!=evidence['expected_public_key_sha256']:blockers.append('public_key_changed')
    if len(tokens)!=1:blockers.append('token_layout_requires_review')
    for token in tokens:
        if (token['direct_pcrs']!=[7] or token['signed_pcrs']!=[11]
                or token['policy_reference']!='initrd' or token['pcr_bank']!='sha256'
                or not token['srk_present'] or '0' in token['keyslots']):
            blockers.append('token_policy_requires_review');break
    raw=json.dumps(evidence,sort_keys=True,separators=(',',':')).encode()
    return {'schema_version':1,'proposal_sha256':hashlib.sha256(raw).hexdigest(),
            'blockers':blockers,'eligible_for_transaction_review':not blockers,
            'repair_authorized':False,'enrollment_performed':False,
            'required_next_step':'Privileged fresh capture and reviewed signed-policy recovery transaction'}
