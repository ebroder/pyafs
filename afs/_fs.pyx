from afs._util cimport *
from afs._util import pyafs_error

import os

DEF MAXSIZE = 2048

def whichcell(char* path):
    """Determine which AFS cell a particular path is in."""
    cdef char cell[MAXCELLCHARS]

    pioctl(path, VIOC_FILE_CELL_NAME, cell, sizeof(cell), NULL, 0, 1)
    return cell

def lsmount(char* path):
    """
    Return the volume name for which path is a mount point.

    lsmount throws an Exception if path is not a mountpoint.
    """
    cdef char vol[MAXSIZE]

    dir, base = os.path.split(path)

    pioctl(dir, VIOC_AFS_STAT_MT_PT, vol, sizeof(vol), <char *>base, len(base), 1)
    return vol
