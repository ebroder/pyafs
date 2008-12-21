cimport afs as a

cdef class PTS:
    cdef a.ubik_client * client
    
    def __cinit__(self, cell=None, sec=1):
        cdef a.afs_int32 code
        cdef a.afsconf_dir *cdir
        cdef a.afsconf_cell info
        cdef char * c_cell
        
        if cell is None:
            c_cell = NULL
        else:
            c_cell = cell
        
        self.client = NULL
        
        code = a.rx_Init(0)
        if code != 0:
            raise Exception(code, "Error initializing Rx")
        
        cdir = a.afsconf_Open(a.AFSDIR_CLIENT_ETC_DIRPATH)
        if cdir is NULL:
            raise OSError(a.errno,
                          "Error opening configuration directory (%s): %s" % \
                              (a.AFSDIR_CLIENT_ETC_DIRPATH, a.strerror(a.errno)))
        code = a.afsconf_GetCellInfo(cdir, c_cell, "afsprot", &info)
        if code != 0:
            raise Exception(code, "GetCellInfo: %s" % a.error_message(code))
    
    def __dealloc__(self):
        a.rx_Finalize()
