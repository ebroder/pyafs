from afs cimport *

cdef class PTS:
    cdef ubik_client * client
    
    def __cinit__(self, cell=None, sec=1):
        cdef afs_int32 code
        cdef afsconf_dir *cdir
        cdef afsconf_cell info
        cdef char * c_cell
        cdef ktc_principal prin
        cdef ktc_token token
        cdef rx_securityClass *sc
        
        if cell is None:
            c_cell = NULL
        else:
            c_cell = cell
        
        self.client = NULL
        
        code = rx_Init(0)
        if code != 0:
            raise Exception(code, "Error initializing Rx")
        
        cdir = afsconf_Open(AFSDIR_CLIENT_ETC_DIRPATH)
        if cdir is NULL:
            raise OSError(errno,
                          "Error opening configuration directory (%s): %s" % \
                              (AFSDIR_CLIENT_ETC_DIRPATH, strerror(errno)))
        code = afsconf_GetCellInfo(cdir, c_cell, "afsprot", &info)
        if code != 0:
            raise Exception(code, "GetCellInfo: %s" % error_message(code))
        
        if sec > 0:
            strncpy(prin.cell, info.name, sizeof(prin.cell))
            prin.instance[0] = 0
            strncpy(prin.name, "afs", sizeof(prin.name))
            
            code = ktc_GetToken(&prin, &token, sizeof(token), NULL);
            if code != 0:
                if sec >= 2:
                    # No really - we wanted authentication
                    raise Exception(code, "Failed to get token for service AFS: %s" % error_message(code))
                sec = 0
            else:
                if sec == 3:
                    level = rxkad_crypt
                else:
                    level = rxkad_clear
                sc = rxkad_NewClientSecurityObject(level, &token.sessionKey,
                                                   token.kvno, token.ticketLen,
                                                   token.ticket)
        
        if sec == 0:
            sc = rxnull_NewClientSecurityObject()
        else:
            sec = 2
        
        code = rxs_Release(sc)
    
    def __dealloc__(self):
        rx_Finalize()
