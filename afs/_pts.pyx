cimport afs as a

cdef class PTS:
    cdef a.ubik_client * client
    
    def __cinit__(self, cell=None, sec=1):
        cdef a.afs_int32 code
        cdef a.afsconf_dir *cdir
        cdef a.afsconf_cell info
        cdef char * c_cell
        cdef a.ktc_principal prin
        cdef a.ktc_token token
        cdef a.rx_securityClass *sc
        
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
        
        if sec > 0:
            a.strncpy(prin.cell, info.name, sizeof(prin.cell))
            prin.instance[0] = 0
            a.strncpy(prin.name, "afs", sizeof(prin.name))
            
            code = a.ktc_GetToken(&prin, &token, sizeof(token), NULL);
            if code != 0:
                if sec >= 2:
                    # No really - we wanted authentication
                    raise Exception(code, "Failed to get token for service AFS: %s" % a.error_message(code))
                sec = 0
            else:
                if sec == 3:
                    level = a.rxkad_crypt
                else:
                    level = a.rxkad_clear
                sc = a.rxkad_NewClientSecurityObject(level, &token.sessionKey,
                                                   token.kvno, token.ticketLen,
                                                   token.ticket)
        
        if sec == 0:
            sc = a.rxnull_NewClientSecurityObject()
        else:
            sec = 2
        
        code = a.rxs_Release(sc)
    
    def __dealloc__(self):
        a.rx_Finalize()
