import errno
from afs import _fs
from afs._fs import whichcell, lsmount

def inafs(path):
    """Return True if a path is in AFS."""
    try:
        whichcell(path)
    except OSError, e:
        if e.errno in (errno.EINVAL, errno.ENOENT):
            return False

    return True

def ismount(path):
    """Return True if a path is a mountpoint."""
    try:
        lsmount(path)
    except OSError, e:
        if e.errno in (errno.EINVAL, errno.ENOENT):
            return False
        raise

    return True
