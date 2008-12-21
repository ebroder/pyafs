cdef extern from "afs/stds.h":
    ctypedef long afs_int32

cdef extern from "ubik.h":
    enum:
        MAXSERVERS
    
    # ubik_client is an opaque struct, so we don't care about its members
    struct ubik_client:
        pass

cdef extern from "rx/rx.h":
    int rx_Init(int port)
    void rx_Finalize()
