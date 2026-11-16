"""Kernel test on a new disposable encrypted EROFS/dm-verity fixture only.

Run on the candidate host. Never open, unmount or close an existing device.
No test key or plaintext is printed.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

assert os.geteuid() == 0
os.umask(0o077)
tag = 'ci-ro-share-' + uuid.uuid4().hex[:16]
root = Path('/run') / tag
root.mkdir(mode=0o700)
opened = []
mounted = []
loop = None
stage = 'prepare'
report = {'checkedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'disposableFixtureOnly': True, 'gpuChanges': False,
          'existingModelDevicesTouched': False, 'checks': {}}


def command(args, required=True):
    result = subprocess.run(args, capture_output=True, timeout=25)
    if required and result.returncode:
        report['failedCommand'] = args[0]
        report['failedCode'] = result.returncode
        report['busyError'] = b'in use' in result.stderr or b'already mapped' in result.stderr
        raise RuntimeError('fixture command failed')
    return result


def close(name):
    binary = next(binary for binary, n in opened if n == name)
    command([binary, 'close', name])
    opened.remove((binary, name))


def crypt(name, shared=False, key='key', required=True):
    assert not os.path.lexists('/dev/mapper/' + name)
    args = ['cryptsetup', 'open', '--type', 'plain', '--hash', 'plain',
            '--key-file', str(root / key), '--keyfile-size', '64',
            '--cipher', 'aes-xts-plain64', '--key-size', '512', '--sector-size', '512']
    if name != tag + '-writer':
        args.append('--readonly')
    if shared:
        args.append('--shared')
    result = command(args + ['--batch-mode', loop, name], required=required)
    if result.returncode == 0:
        opened.append(('cryptsetup', name))
    return result


def verity(crypt_name, name, required=True):
    assert not os.path.lexists('/dev/mapper/' + name)
    result = command(['veritysetup', 'open', '/dev/mapper/' + crypt_name, name,
        '/dev/mapper/' + crypt_name, root_hash, '--no-superblock', '--format', '1',
        '--hash', 'sha256', '--data-block-size', '4096', '--hash-block-size', '4096',
        '--data-blocks', str(blocks), '--hash-offset', str(offset), '--salt', salt], required=required)
    if result.returncode == 0:
        opened.append(('veritysetup', name))
    return result


def mount(name, target):
    target.mkdir()
    command(['mount', '-t', 'erofs', '-o', 'ro', '/dev/mapper/' + name, str(target)])
    mounted.append(target)


try:
    source = root / 'input'
    source.mkdir()
    payload = b'Public disposable C8s read-only sharing fixture.\n' * 1024
    (source / 'fixture').write_bytes(payload)
    (root / 'key').write_bytes(os.urandom(64))
    (root / 'wrong-key').write_bytes(os.urandom(64))
    command(['mkfs.erofs', str(root / 'data.erofs'), str(source)])
    offset = (root / 'data.erofs').stat().st_size
    assert offset % 4096 == 0
    blocks = offset // 4096
    formatted = command(['veritysetup', 'format', str(root / 'data.erofs'), str(root / 'hashes'),
        '--no-superblock', '--hash', 'sha256', '--data-block-size', '4096', '--hash-block-size', '4096'])
    text = formatted.stdout.decode()
    root_hash = re.search(r'^Root hash:\s*([0-9a-f]+)$', text, re.M).group(1)
    salt = re.search(r'^Salt:\s*([0-9a-f]+)$', text, re.M).group(1)
    backing = root / 'ciphertext'
    with backing.open('wb') as stream:
        stream.truncate(32 * 1024 * 1024)
    loop = command(['losetup', '--find', '--show', str(backing)]).stdout.decode().strip()
    actual = command(['losetup', '--noheadings', '--output', 'BACK-FILE', loop]).stdout.decode().strip()
    assert actual == str(backing), 'loop does not belong to this fixture'
    stage = 'initialize-own-fixture'
    writer = tag + '-writer'
    crypt(writer)
    with open('/dev/mapper/' + writer, 'r+b', buffering=0) as stream:
        stream.write((root / 'data.erofs').read_bytes())
        stream.seek(offset)
        stream.write((root / 'hashes').read_bytes())
        os.fsync(stream.fileno())
    close(writer)
    a, av, b, bv = [tag + s for s in ['-a', '-av', '-b', '-bv']]
    stage = 'first-reader'
    crypt(a)
    verity(a, av)
    mount(av, root / 'mount-a')
    assert (root / 'mount-a/fixture').read_bytes() == payload
    stage = 'baseline-second-reader'
    baseline = crypt(b, required=False)
    report['checks']['secondReaderWithoutSharedRejected'] = baseline.returncode != 0
    if baseline.returncode == 0:
        close(b)
    stage = 'shared-second-reader'
    crypt(b, shared=True)
    verity(b, bv)
    mount(bv, root / 'mount-b')
    assert (root / 'mount-b/fixture').read_bytes() == payload
    report['checks']['secondReaderWithSharedMatches'] = True
    report['checks']['cryptAndVerityReadOnly'] = all(command(['blockdev', '--getro', '/dev/mapper/' + n]).stdout.strip() == b'1' for n in [a, av, b, bv])
    stage = 'replace-first-reader'
    command(['umount', str(root / 'mount-a')])
    mounted.remove(root / 'mount-a')
    close(av)
    close(a)
    assert (root / 'mount-b/fixture').read_bytes() == payload
    baseline = crypt(a, required=False)
    report['checks']['replacementWithoutSharedRejected'] = baseline.returncode != 0
    if baseline.returncode == 0:
        close(a)
    crypt(a, shared=True)
    verity(a, av)
    command(['mount', '-t', 'erofs', '-o', 'ro', '/dev/mapper/' + av, str(root / 'mount-a')])
    mounted.append(root / 'mount-a')
    assert (root / 'mount-a/fixture').read_bytes() == payload
    assert (root / 'mount-b/fixture').read_bytes() == payload
    report['checks']['replacementWithSharedAndOtherReaderMatches'] = True
    stage = 'wrong-key-integrity-control'
    bad, badv = tag + '-bad', tag + '-badv'
    crypt(bad, shared=True, key='wrong-key')
    opened_bad = verity(bad, badv, required=False)
    rejected = opened_bad.returncode != 0
    if not rejected:
        rejected = command(['dd', 'if=/dev/mapper/' + badv, 'of=/dev/null', 'bs=4096', 'count=1', 'status=none'], required=False).returncode != 0
    assert rejected
    report['checks']['wrongKeyStillRejectedByVerity'] = True
    report['allPassed'] = all(report['checks'].values())
except Exception as error:
    report.update(allPassed=False, failedStage=stage, errorType=type(error).__name__)
finally:
    failures = 0
    for target in reversed(mounted):
        failures += command(['umount', str(target)], required=False).returncode != 0
    for binary, name in reversed(opened):
        failures += command([binary, 'close', name], required=False).returncode != 0
    if loop:
        failures += command(['losetup', '--detach', loop], required=False).returncode != 0
    report['cleanupPassed'] = failures == 0
    if not failures:
        shutil.rmtree(root)
    print(json.dumps(report))
    raise SystemExit(0 if report.get('allPassed') and report['cleanupPassed'] else 1)
