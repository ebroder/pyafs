cdef extern from "afs/stds.h":
    ctypedef long afs_int32

cdef extern from "ubik.h":
    enum:
        MAXSERVERS
    
    struct ubik_client:
        pass

cdef extern from "rx/rx.h":
    int rx_Init(int port)
    void rx_Finalize()
