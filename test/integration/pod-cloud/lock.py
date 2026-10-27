#!/usr/bin/env python3
"""Hold a host file lock across the shell runner, including pre-ledger setup."""
import fcntl
import hashlib
import os
import stat
import sys


def lock_path(args):
    if len(args) == 3 and args[0] == "run":
        directory = args[2]
    elif len(args) == 2 and args[0] == "cleanup":
        directory = args[1]
    else:
        raise ValueError("expected run INPUT NEW_STATE or cleanup EXISTING_STATE")
    if not os.path.isabs(directory):
        raise ValueError("absolute state directory required")
    directory = os.path.realpath(directory)
    digest = hashlib.sha256(os.fsencode(directory)).hexdigest()
    return os.path.join(os.path.dirname(directory), ".podcloud-lock-" + digest)


def main():
    verify = sys.argv[1:2] == ["--verify"]
    args = sys.argv[2:] if verify else sys.argv[1:]
    script, arguments = args[0], args[1:]
    path = lock_path(arguments)
    if verify:
        fd = int(os.environ["C8S_PODCLOUD_LOCK_FD"])
        if fd < 3:
            raise ValueError("invalid inherited lock descriptor")
    else:
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    held, current = os.fstat(fd), os.lstat(path)
    if (not stat.S_ISREG(held.st_mode) or held.st_uid != os.getuid()
            or held.st_mode & 0o077 or held.st_nlink != 1
            or (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino)):
        raise ValueError("private owned lock file required")
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if verify:
        return
    os.set_inheritable(fd, True)
    environment = dict(os.environ, C8S_PODCLOUD_LOCKED="1", C8S_PODCLOUD_LOCK_FD=str(fd))
    os.execvpe("bash", ["bash", script, *arguments], environment)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, IndexError):
        print("cannot acquire or verify the exclusive Cloud runner lock; another run/cleanup may still be active", file=sys.stderr)
        sys.exit(1)
