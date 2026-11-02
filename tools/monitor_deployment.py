"""Bind reviewed bytes, protected backups, services and an unapproved baseline.

Library only. The caller holds TransactionStore's exclusive lock. Production
adapters must use fixed paths and captured bytes; no browser entrypoint exists.
"""
import json
import os
from baseline_migration import digest, prepare as baseline_candidate
from release_binding import bind, release, SCOPE
from service_transaction import ServiceTransaction

REQUIRED = ('secureboot','lockdown','tpm','luks','firewall',
            'listeners','apparmor','services','processes','telemetry','usbguard',
            'devices','updates','integrity','audit','snapshots')


class Deployment:
    def __init__(self, tx, services, scan, trust, baseline_reader):
        self.tx, self.services, self.scan, self.trust = tx, services, scan, trust
        self.baseline_reader = baseline_reader
        self.coordinator = ServiceTransaction(tx, services)

    def prepare(self, previous_raw, previous_sha, manifest_raw, release_sha, contents):
        if digest(self.baseline_reader()) != previous_sha: raise ValueError('Approved baseline changed')
        before = self.scan()
        bound = bind(previous_raw, previous_sha, manifest_raw, release_sha, contents, before)
        if not bound['writes']: raise ValueError('Release already installed; no transaction needed')
        # Inspect trust state before any installed mutation; corruption is not bootstrap.
        trust_mode = self.trust.prepare()
        token = self.tx.prepare(bound['writes'], {p:before[p] for p in bound['writes']}, release_sha)
        folder = self.tx._folder(token)
        try:
            self.tx._write(folder, 'prior-baseline.json', previous_raw)
            self.tx._write(folder, 'release.json', manifest_raw)
            for index, name in enumerate(sorted(release.FILES)):
                self.tx._write(folder, f'release-{index}.bytes', contents[name])
            state = dict(schema=1, previous_sha=previous_sha, release_sha=release_sha,
                         before=before, trust_mode=trust_mode, trust_phase='pending')
            self.tx._write(folder, 'deployment.json', json.dumps(state).encode())
        finally: os.close(folder)
        self.coordinator.prepare(token)
        return token

    def _load(self, folder):
        state = json.loads(self.tx._read(folder, 'deployment.json', 65536))
        if state.get('schema') != 1 or state.get('trust_mode') not in ('create','preserve') or state.get('trust_phase') not in ('pending','initializing','ready'):
            raise ValueError('Invalid deployment journal')
        previous = self.tx._read(folder, 'prior-baseline.json', 65536)
        manifest = self.tx._read(folder, 'release.json', 65536)
        contents = {name:self.tx._read(folder, f'release-{i}.bytes') for i,name in enumerate(sorted(release.FILES))}
        bound = bind(previous, state['previous_sha'], manifest, state['release_sha'], contents, state['before'])
        record = self.tx._load(folder)
        entries = {entry['path']:entry for entry in record['entries']}
        if record['reviewed_release_sha'] != state['release_sha'] or set(entries) != set(bound['writes']):
            raise ValueError('File transaction differs from captured release')
        for path, entry in entries.items():
            if entry['before'] != state['before'][path] or entry['after']['sha256'] != digest(bound['writes'][path]):
                raise ValueError('File transaction differs from reviewed payload')
        return state, bound, previous, manifest, contents

    def run(self, token, *, rollback=False, checkpoint=lambda _:None):
        folder = self.tx._folder(token)
        try:
            state, bound, previous, manifest, contents = self._load(folder)
            if digest(self.baseline_reader()) != state['previous_sha']:
                raise ValueError('Approved baseline changed; explicit recovery required')
            # A resumed update may contain only original or journalled file states.
            current = self.scan()
            entries = {entry['path']:entry for entry in self.tx._load(folder)['entries']}
            if set(current) != SCOPE: raise ValueError('Incomplete current scope')
            for path in SCOPE:
                allowed = [state['before'][path]]
                if path in entries: allowed.append(entries[path]['after'])
                if current[path] not in allowed: raise ValueError('Unrelated change since preparation: '+path)
            def trust_ready():
                if state['trust_phase'] == 'initializing':
                    raise ValueError('Interrupted trust initialization requires explicit recovery')
                if state['trust_phase'] == 'ready':
                    self.trust.verify()
                    return
                if state['trust_mode'] == 'create':
                    state['trust_phase'] = 'initializing'
                    self.tx._write(folder, 'deployment.json', json.dumps(state).encode())
                    checkpoint('trust_initializing')
                    self.trust.initialize(contents['policies/normal-devices.candidate.json'])
                else:
                    self.trust.verify()
                state['trust_phase'] = 'ready'
                self.tx._write(folder, 'deployment.json', json.dumps(state).encode())
                checkpoint('trust_ready')
            result = self.coordinator.run(token, REQUIRED, rollback=rollback,
                                          checkpoint=checkpoint, after_files=trust_ready)
            if result['phase'] != 'healthy': return result
            # Terminal service receipts aren't a fresh liveness check.
            if self.services.states()['security-center.service']:
                self.services.health(REQUIRED)
            self.trust.verify()
            candidate = baseline_candidate(previous, state['previous_sha'], manifest,
                                           state['release_sha'], state['before'], self.scan())
            self.tx._write(folder, 'candidate-baseline.json', candidate['candidate_raw'])
            receipt = dict(schema=1, phase='awaiting_baseline_approval', token=token,
                           release_sha256=state['release_sha'],
                           candidate_sha256=candidate['candidate_sha256'],
                           previous_baseline_sha256=state['previous_sha'],
                           baseline_approved=False, scope_count=candidate['new_count'])
            self.tx._write(folder, 'receipt.json', json.dumps(receipt).encode())
            return receipt
        finally: os.close(folder)
