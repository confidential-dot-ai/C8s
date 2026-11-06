#!/usr/bin/env python3
"""Independent read-only absence audit; never deletes or changes cloud state."""
import argparse
import datetime as dt
import json
from pathlib import Path
import sys
import urllib.parse

from cloud import resource_path
from fixtures import NS, OWNER, need


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['directory', 'kubeconfig', 'cloud-helpers']: p.add_argument('--'+name, required=True)
    args = p.parse_args(); directory = Path(args.directory)
    state = json.loads((directory/'journal.json').read_text())
    sys.path.insert(0, args.cloud_helpers)
    from cds_ha_rehearsal import kube_client, atomic_json
    kube = kube_client(args.kubeconfig); paths = set()
    for row in state['resources']:
        path = resource_path(row['item'], state['run']); need(path == row['path'], 'journal path differs')
        paths.add(path)
        if row.get('pv'): paths.add('/api/v1/persistentvolumes/'+row['pv']['name'])
    remaining = []
    for path in sorted(paths):
        code, _ = kube.call('GET', path, expected=(200, 404))
        if code != 404: remaining.append(path)
    _, pods = kube.call('GET', '/api/v1/namespaces/'+NS+'/pods?labelSelector='+urllib.parse.quote(OWNER+'='+state['run']))
    remaining.extend('owned-pod/'+x['metadata']['name'] for x in pods['items'])
    result = {'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'read_only_independent_audit': True,
              'resource_paths_checked': len(paths), 'cleanup_verified': not remaining, 'remaining': remaining}
    atomic_json(directory/'cleanup-audit.json', result)
    print(json.dumps({k: v for k, v in result.items() if k != 'remaining'}))
    need(not remaining, 'owned resources remain')


if __name__ == '__main__': main()
