cdef extern from "afs/stds.h":
    ctypedef long afs_int32

cdef extern from "ubik.h":
    enum:
        MAXSERVERS
    
    struct ubik_client:
        pass

cdef extern from "rx/rx.h":
    int rx_Init(int port)

cdef class PTS:
    cdef ubik_client * client
    
    def __cinit__(self):
        cdef afs_int32 code
        
        self.client = NULL
        
        code = rx_Init(0)
        if code != 0:
            raise Exception(str(code))
