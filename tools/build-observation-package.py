#!/usr/bin/python3
"""Capture or verify staged observer inputs; no installation/build/signing."""
import argparse
import json
from observation_package import build, verify
parser=argparse.ArgumentParser()
group=parser.add_mutually_exclusive_group(required=True)
group.add_argument('--mapping')
group.add_argument('--verify')
options=parser.parse_args()
folder=options.verify or build(options.mapping)
data=verify(folder)
print(json.dumps(dict(package=str(folder),files=len(data['files']),inputs_sha256=data['inputs_sha256'],installed=False,approved=False)))
