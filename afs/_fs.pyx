from afs cimport *
from afs import pyafs_error

def whichcell(char* path):
    """Determine which AFS cell a particular path is in."""
    cdef char cell[MAXCELLCHARS]

    pioctl_read(path, VIOC_FILE_CELL_NAME, cell, sizeof(cell), 1)
    return cell
