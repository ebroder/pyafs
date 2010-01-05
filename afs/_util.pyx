"""
General PyAFS utilities, such as error handling
"""

import sys

# otherwise certain headers are unhappy
cdef extern from "netinet/in.h": pass
cdef extern from "afs/vice.h": pass

cdef int _init = 0

# pioctl convenience wrappers

cdef extern int pioctl(char *dir, afs_int32 op,
                       void *out_buffer, unsigned short out_size,
                       void *in_buffer, unsigned short in_size,
                       afs_int32 follow) except -1:
    cdef ViceIoctl blob
    cdef afs_int32 code

    if in_buffer:
        blob.in_size = in_size
        blob.cin = in_buffer
    else:
        blob.in_size = 0

    if out_buffer:
        blob.out = out_buffer
        blob.out_size = out_size
    else:
        blob.out_size = 0

    code = cpioctl(dir, op, &blob, follow)
    # This might work with the rest of OpenAFS, but I'm not convinced
    # the rest of it is consistent
    if code == -1:
        raise OSError(errno, strerror(errno))
    pyafs_error(code)
    return code

# Error handling

class AFSException(Exception):
    def __init__(self, errno):
        self.errno = errno
        self.strerror = afs_error_message(errno)

    def __repr__(self):
        return "AFSException(%s)" % (self.errno)

    def __str__(self):
        return "[%s] %s" % (self.errno, self.strerror)

def pyafs_error(code):
    if not _init:
        initialize_ACFG_error_table()
        initialize_KTC_error_table()
        initialize_PT_error_table()
        initialize_RXK_error_table()
        initialize_U_error_table()

        _init = 1

    if code != 0:
        raise AFSException(code)
