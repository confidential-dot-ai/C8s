"""Bounded, independently verified image transfer through the exec proxy."""
import hashlib
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time

CHUNK = 8 * 1024 * 1024


class ReceiverFailed(RuntimeError):
    pass


def chunk_receiver(size, digest, path, token):
    if not 0 < size <= CHUNK or not re.fullmatch('[0-9a-f]{64}', digest) or not re.fullmatch('[0-9a-f]{32}', token):
        raise ValueError('invalid framed chunk')
    # head supplies framing even when the API proxy leaves stdin open. A
    # receiver can only publish completion after checking size and contents.
    return ['sh', '-c',
        'set -e; head -c "$1" > "$2"; '
        '[ "$(wc -c < "$2")" -eq "$1" ]; '
        'hash=$(sha256sum "$2"); [ "${hash%% *}" = "$3" ]; '
        'printf "%s" "$4" > "$2.complete"',
        'chunk-receiver', str(size), path, digest, token]


def extract_receiver(parts, digest, destination, marker, token):
    if not parts or not re.fullmatch('[0-9a-f]{64}', digest) or not re.fullmatch('[0-9a-f]{32}', token):
        raise ValueError('invalid archive extraction')
    return ['sh', '-c',
        'set -e; expected=$1; destination=$2; marker=$3; token=$4; shift 4; '
        'hash=$(cat -- "$@" | sha256sum); [ "${hash%% *}" = "$expected" ]; '
        'cat -- "$@" | tar -xzf - -C "$destination"; '
        'printf "%s" "$token" > "$marker"',
        'extract-receiver', digest, destination, marker, token, *parts]


def receive(run, name, pod, argv, marker, token, data, seconds):
    with (run.directory/(name+'.stdout')).open('wb') as out, (run.directory/(name+'.stderr')).open('wb') as err:
        process = subprocess.Popen(run.kubectl('exec', '-i', pod, '--', *argv),
            stdin=data if data is not None else subprocess.DEVNULL, stdout=out, stderr=err)
        try:
            deadline = time.monotonic()+seconds
            while time.monotonic() < deadline:
                run.live()
                if process.poll() not in (None, 0):
                    raise ReceiverFailed('framed receiver exited unsuccessfully; inspect private stderr')
                try:
                    value = run.command(name+'-completion', run.kubectl('exec', pod, '--', 'sh', '-c',
                        'if [ -f "$1" ]; then cat "$1"; fi', 'completion', marker), timeout=15)
                except (RuntimeError, subprocess.TimeoutExpired):
                    time.sleep(2)
                    continue
                if value == token.encode():
                    return
                if value:
                    raise ValueError('unexpected image transfer token')
                time.sleep(2)
            raise TimeoutError('framed image receiver completion timed out')
        except (TimeoutError, ReceiverFailed):
            # Retain the observed byte count without reading image contents.
            # A delayed receiver can only touch this attempt's unique path.
            if data is not None and marker.endswith('.complete'):
                try:
                    run.command(name+'-progress', run.kubectl('exec', pod, '--', 'sh', '-c',
                        'if [ -f "$1" ]; then wc -c < "$1"; fi', 'progress', marker.removesuffix('.complete')), timeout=10)
                except (RuntimeError, subprocess.TimeoutExpired):
                    pass
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait()


def upload(run, pod, archive, destination):
    # A new path for every attempt prevents a delayed receiver from racing a
    # retry. Only independently verified chunks enter the final archive. All
    # temporary remote bytes live on the owned disposable PVC.
    archive = Path(archive)
    deadline = time.monotonic()+420
    parts = []
    digest = hashlib.sha256()
    with archive.open('rb') as source:
        while data := source.read(CHUNK):
            digest.update(data)
            for attempt in range(3):
                run.live()
                if time.monotonic() >= deadline:
                    raise TimeoutError('bounded image transfer deadline reached')
                token = secrets.token_hex(16)
                path = destination+'/.cds-chunk-'+token
                name = pod+f'-chunk-{len(parts):03}-{attempt}'
                with tempfile.TemporaryFile(dir='/tmp') as framed:
                    framed.write(data); framed.seek(0)
                    try:
                        receive(run, name, pod, chunk_receiver(len(data), hashlib.sha256(data).hexdigest(), path, token),
                            path+'.complete', token, framed, min(45, deadline-time.monotonic()))
                    except (TimeoutError, ReceiverFailed):
                        if attempt == 2: raise
                        run.event('image-chunk-retry', chunk=len(parts))
                        time.sleep(2**(attempt+1))
                        continue
                parts.append(path)
                break
    token = secrets.token_hex(16)
    marker = destination+'/.cds-extracted-'+token
    receive(run, pod+'-extract', pod, extract_receiver(parts, digest.hexdigest(), destination, marker, token),
        marker, token, None, 180)
    run.event('framed-image-receiver-completed', archive=archive.name, chunks=len(parts))
