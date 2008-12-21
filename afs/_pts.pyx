cimport afs as a

cdef class PTS:
    cdef a.ubik_client * client
    
    def __cinit__(self):
        cdef a.afs_int32 code
        
        self.client = NULL
        
        code = a.rx_Init(0)
        if code != 0:
            raise Exception(str(code))
