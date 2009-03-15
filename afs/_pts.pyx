from afs cimport *

cdef import from "afs/ptuser.h":
    enum:
        PR_MAXNAMELEN

    ctypedef char prname[PR_MAXNAMELEN]

    struct namelist:
        unsigned int namelist_len
        prname *namelist_val

    struct idlist:
        unsigned int idlist_len
        afs_int32 *idlist_val

    int ubik_PR_NameToID(ubik_client *, afs_int32, namelist *, idlist *)
    int ubik_PR_IDToName(ubik_client *, afs_int32, idlist *, namelist *)

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
        cdef rx_connection *serverconns[MAXSERVERS]
        cdef int i

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
            raise Exception(code, "GetCellInfo: %s" % afs_error_message(code))

        if sec > 0:
            strncpy(prin.cell, info.name, sizeof(prin.cell))
            prin.instance[0] = 0
            strncpy(prin.name, "afs", sizeof(prin.name))

            code = ktc_GetToken(&prin, &token, sizeof(token), NULL);
            if code != 0:
                if sec >= 2:
                    # No really - we wanted authentication
                    raise Exception(code, "Failed to get token for service AFS: %s" % afs_error_message(code))
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

        memset(serverconns, 0, sizeof(serverconns))
        for 0 <= i < info.numServers:
            serverconns[i] = rx_NewConnection(info.hostAddr[i].sin_addr.s_addr,
                                              info.hostAddr[i].sin_port,
                                              PRSRV,
                                              sc,
                                              sec)

        code = ubik_ClientInit(serverconns, &self.client)
        if code != 0:
            raise Exception("Failed to initialize ubik connection to Protection server: %s" % afs_error_message(code))

        code = rxs_Release(sc)

    def __dealloc__(self):
        ubik_ClientDestroy(self.client)
        rx_Finalize()

    def NameToId(self, name):
        cdef namelist lnames
        cdef idlist lids
        cdef afs_int32 code, id
        name = name.lower()

        lids.idlist_len = 0
        lids.idlist_val = NULL
        lnames.namelist_len = 1
        lnames.namelist_val = <prname *>malloc(PR_MAXNAMELEN)
        strncpy(lnames.namelist_val[0], name, PR_MAXNAMELEN)
        code = ubik_PR_NameToID(self.client, 0, &lnames, &lids)
        if lids.idlist_val is not NULL:
            id = lids.idlist_val[0]
            free(lids.idlist_val)
        if code != 0:
            raise Exception("Failed to lookup PTS name: %s" % afs_error_message(code))
        return id

    def IdToName(self, id):
        cdef namelist lnames
        cdef idlist lids
        cdef afs_int32 code
        cdef char name[PR_MAXNAMELEN]

        lids.idlist_len = 1
        lids.idlist_val = <afs_int32 *>malloc(sizeof(afs_int32))
        lids.idlist_val[0] = id
        lnames.namelist_len = 0
        lnames.namelist_val = NULL
        code = ubik_PR_IDToName(self.client, 0, &lids, &lnames)
        if lnames.namelist_val is not NULL:
            strncpy(name, lnames.namelist_val[0], sizeof(name))
            free(lnames.namelist_val)
        if lids.idlist_val is not NULL:
            free(lids.idlist_val)
        if code != 0:
            raise Exception("Failed to lookup PTS ID: %s" % afs_error_message(code))
        return name
