cdef extern from "errno.h":
    int errno

cdef extern from "string.h":
    char * strerror(int errnum)

cdef extern from "netinet/in.h":
    struct in_addr:
        int s_addr
    struct sockaddr_in:
        short sin_family
        unsigned short sin_port
        in_addr sin_addr
        char sin_zero[8]

cdef extern from "afs/stds.h":
    ctypedef long afs_int32

cdef extern from "afs/dirpath.h":
    char * AFSDIR_CLIENT_ETC_DIRPATH

cdef extern from "afs/cellconfig.h":
    enum:
        MAXCELLCHARS
        MAXHOSTSPERCELL
        MAXHOSTCHARS
    
    # We just pass afsconf_dir structs around to other AFS functions,
    # so this can be treated as opaque
    struct afsconf_dir:
        pass
    
    # For afsconf_cell, on the other hand, we care about everything
    struct afsconf_cell:
        char name[MAXCELLCHARS]
        short numServers
        short flags
        sockaddr_in hostAddr[MAXHOSTSPERCELL]
        char hostName[MAXHOSTSPERCELL][MAXHOSTCHARS]
        char *linkedCell
        int timeout
     
    afsconf_dir *afsconf_Open(char *adir)
    int afsconf_GetCellInfo(afsconf_dir *adir,
                            char *acellName,
                            char *aservice,
                            afsconf_cell *acellInfo)

cdef extern from "ubik.h":
    enum:
        MAXSERVERS
    
    # ubik_client is an opaque struct, so we don't care about its members
    struct ubik_client:
        pass

cdef extern from "rx/rx.h":
    int rx_Init(int port)
    void rx_Finalize()

cdef extern from "afs/com_err.h":
    char * error_message(int)
