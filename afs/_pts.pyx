from afs._util cimport *
from afs._util import pyafs_error
import re

cdef extern from "afs/ptuser.h":
    enum:
        PR_MAXNAMELEN
        PRGRP
        PRUSERS
        PRGROUPS
        ANONYMOUSID
        PR_SF_ALLBITS
        PR_SF_NGROUPS
        PR_SF_NUSERS

    ctypedef char prname[PR_MAXNAMELEN]

    struct namelist:
        unsigned int namelist_len
        prname *namelist_val

    struct prlist:
        unsigned int prlist_len
        afs_int32 *prlist_val

    struct idlist:
        unsigned int idlist_len
        afs_int32 *idlist_val

    struct prcheckentry:
        afs_int32 flags
        afs_int32 id
        afs_int32 owner
        afs_int32 creator
        afs_int32 ngroups
        afs_int32 nusers
        afs_int32 count
        char name[PR_MAXNAMELEN]

    struct prlistentries:
        afs_int32 flags
        afs_int32 id
        afs_int32 owner
        afs_int32 creator
        afs_int32 ngroups
        afs_int32 nusers
        afs_int32 count
        char name[PR_MAXNAMELEN]

    struct prentries:
        unsigned int prentries_len
        prlistentries *prentries_val

    int ubik_PR_NameToID(ubik_client *, afs_int32, namelist *, idlist *)
    int ubik_PR_IDToName(ubik_client *, afs_int32, idlist *, namelist *)
    int ubik_PR_INewEntry(ubik_client *, afs_int32, char *, afs_int32, afs_int32)
    int ubik_PR_NewEntry(ubik_client *, afs_int32, char *, afs_int32, afs_int32, afs_int32 *)
    int ubik_PR_Delete(ubik_client *, afs_int32, afs_int32)
    int ubik_PR_AddToGroup(ubik_client *, afs_int32, afs_int32, afs_int32)
    int ubik_PR_RemoveFromGroup(ubik_client *, afs_int32, afs_int32, afs_int32)
    int ubik_PR_ListElements(ubik_client *, afs_int32, afs_int32, prlist *, afs_int32 *)
    int ubik_PR_ListOwned(ubik_client *, afs_int32, afs_int32, prlist *, afs_int32 *)
    int ubik_PR_ListEntry(ubik_client *, afs_int32, afs_int32, prcheckentry *)
    int ubik_PR_ChangeEntry(ubik_client *, afs_int32, afs_int32, char *, afs_int32, afs_int32)
    int ubik_PR_IsAMemberOf(ubik_client *, afs_int32, afs_int32, afs_int32, afs_int32 *)
    int ubik_PR_ListMax(ubik_client *, afs_int32, afs_int32 *, afs_int32 *)
    int ubik_PR_SetMax(ubik_client *, afs_int32, afs_int32, afs_int32)
    int ubik_PR_ListEntries(ubik_client *, afs_int32, afs_int32, afs_int32, prentries *, afs_int32 *)
    int ubik_PR_SetFieldsEntry(ubik_client *, afs_int32, afs_int32, afs_int32, afs_int32, afs_int32, afs_int32, afs_int32, afs_int32)

cdef extern from "afs/pterror.h":
    enum:
        PRNOENT

cdef extern from "krb5/krb5.h":
    struct _krb5_context:
        pass
    struct krb5_principal_data:
        pass

    ctypedef _krb5_context * krb5_context
    ctypedef krb5_principal_data * krb5_principal

    ctypedef long krb5_int32
    ctypedef krb5_int32 krb5_error_code
    krb5_error_code krb5_init_context(krb5_context *)
    krb5_error_code krb5_parse_name(krb5_context, char *, krb5_principal *)
    krb5_error_code krb5_unparse_name(krb5_context, krb5_principal, char **)
    krb5_error_code krb5_524_conv_principal(krb5_context, krb5_principal, char *, char *, char *)
    krb5_error_code krb5_425_conv_principal(krb5_context, char *, char *, char *, krb5_principal *)
    krb5_error_code krb5_get_host_realm(krb5_context, char *, char ***)
    void krb5_free_host_realm(krb5_context, char **)
    void krb5_free_principal(krb5_context, krb5_principal)
    void krb5_free_context(krb5_context)

cdef class PTEntry:
    cdef public afs_int32 flags
    cdef public afs_int32 id
    cdef public afs_int32 owner
    cdef public afs_int32 creator
    cdef public afs_int32 ngroups
    cdef public afs_int32 nusers
    cdef public afs_int32 count
    cdef public object name

    def __repr__(self):
        if self.name != '':
            return '<PTEntry: %s>' % self.name
        else:
            return '<PTEntry: PTS ID %s>' % self.id

cdef int _ptentry_from_c(PTEntry p_entry, prcheckentry * c_entry) except -1:
    if p_entry is None:
        raise TypeError
        return -1

    p_entry.flags = c_entry.flags
    p_entry.id = c_entry.id
    p_entry.owner = c_entry.owner
    p_entry.creator = c_entry.creator
    p_entry.ngroups = c_entry.ngroups
    p_entry.nusers = c_entry.nusers
    p_entry.count = c_entry.count
    p_entry.name = c_entry.name
    return 0

cdef int _ptentry_to_c(prcheckentry * c_entry, PTEntry p_entry) except -1:
    if p_entry is None:
        raise TypeError
        return -1

    c_entry.flags = p_entry.flags
    c_entry.id = p_entry.id
    c_entry.owner = p_entry.owner
    c_entry.creator = p_entry.creator
    c_entry.ngroups = p_entry.ngroups
    c_entry.nusers = p_entry.nusers
    c_entry.count = p_entry.count
    strncpy(c_entry.name, p_entry.name, sizeof(c_entry.name))
    return 0

cdef object kname_re = re.compile(r'^([^.].*?)(?<!\\)(?:\.(.*?))?(?<!\\)@([^@]*)$')

cdef object kname_parse(fullname):
    """Parse a krb4-style principal into a name, instance, and realm."""
    cdef object re_match = kname_re.match(fullname)
    if not re_match:
        return None
    else:
        princ = re_match.groups()
        return tuple([re.sub(r'\\(.)', r'\1', x) if x else x for x in princ])

cdef object kname_unparse(name, inst, realm):
    """Unparse a name, instance, and realm into a single krb4
    principal string."""
    name = re.sub('r([.\\@])', r'\\\1', name)
    inst = re.sub('r([.\\@])', r'\\\1', inst)
    realm = re.sub(r'([\\@])', r'\\\1', realm)
    if inst:
        return '%s.%s@%s' % (name, inst, realm)
    else:
        return '%s@%s' % (name, realm)

cdef class PTS:
    """
    A PTS object is essentially a handle to talk to the server in a
    given cell.

    cell defaults to None. If no argument is passed for cell, PTS
    connects to the home cell.

    sec is the security level, an integer from 0 to 3:
      - 0: unauthenticated connection
      - 1: try authenticated, then fall back to unauthenticated
      - 2: fail if an authenticated connection can't be established
      - 3: same as 2, plus encrypt all traffic to the protection
        server

    The realm attribute is the Kerberos realm against which this cell
    authenticates.
    """
    cdef ubik_client * client
    cdef readonly object cell
    cdef readonly object realm

    def __cinit__(self, cell=None, sec=1):
        cdef afs_int32 code
        cdef afsconf_dir *cdir
        cdef afsconf_cell info
        cdef krb5_context context
        cdef char ** hrealms = NULL
        cdef char * c_cell
        cdef ktc_principal prin
        cdef ktc_token token
        cdef rx_securityClass *sc
        cdef rx_connection *serverconns[MAXSERVERS]
        cdef int i

        initialize_PT_error_table()

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
        pyafs_error(code)

        code = krb5_init_context(&context)
        pyafs_error(code)
        code = krb5_get_host_realm(context, info.hostName[0], &hrealms)
        pyafs_error(code)
        self.realm = hrealms[0]
        krb5_free_host_realm(context, hrealms)
        krb5_free_context(context)

        self.cell = info.name

        if sec > 0:
            strncpy(prin.cell, info.name, sizeof(prin.cell))
            prin.instance[0] = 0
            strncpy(prin.name, "afs", sizeof(prin.name))

            code = ktc_GetToken(&prin, &token, sizeof(token), NULL);
            if code != 0:
                if sec >= 2:
                    # No really - we wanted authentication
                    pyafs_error(code)
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
        pyafs_error(code)

        code = rxs_Release(sc)

    def __dealloc__(self):
        ubik_ClientDestroy(self.client)
        rx_Finalize()

    def _NameOrId(self, ident):
        """
        Given an identifier, convert it to a PTS ID by looking up the
        name if it's a string, or otherwise just converting it to an
        integer.
        """
        if isinstance(ident, basestring):
            return self._NameToId(ident)
        else:
            return int(ident)

    def _NameToId(self, name):
        """
        Converts a user or group to an AFS ID.
        """
        cdef namelist lnames
        cdef idlist lids
        cdef afs_int32 code, id = ANONYMOUSID
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
        if id == ANONYMOUSID:
            code = PRNOENT
        pyafs_error(code)
        return id

    def _IdToName(self, id):
        """
        Convert an AFS ID to the name of a user or group.
        """
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
        if name == str(id):
            code = PRNOENT
        pyafs_error(code)
        return name

    def _CreateUser(self, name, id=None):
        """
        Create a new user in the protection database. If an ID is
        provided, that one will be used.
        """
        cdef afs_int32 code
        cdef afs_int32 cid
        name = name[:PR_MAXNAMELEN].lower()

        if id is not None:
            cid = id

        if id is not None:
            code = ubik_PR_INewEntry(self.client, 0, name, cid, 0)
        else:
            code = ubik_PR_NewEntry(self.client, 0, name, 0, 0, &cid)

        pyafs_error(code)
        return cid

    def _CreateGroup(self, name, owner, id=None):
        """
        Create a new group in the protection database. If an ID is
        provided, that one will be used.
        """
        cdef afs_int32 code, cid

        name = name[:PR_MAXNAMELEN].lower()
        oid = self._NameOrId(owner)

        if id is not None:
            cid = id
            code = ubik_PR_INewEntry(self.client, 0, name, cid, oid)
        else:
            code = ubik_PR_NewEntry(self.client, 0, name, PRGRP, oid, &cid)

        pyafs_error(code)
        return cid

    def _Delete(self, ident):
        """
        Delete the protection database entry with the provided
        identifier.
        """
        cdef afs_int32 code
        cdef afs_int32 id = self._NameOrId(ident)

        code = ubik_PR_Delete(self.client, 0, id)
        pyafs_error(code)

    def _AddToGroup(self, user, group):
        """
        Add the given user to the given group.
        """
        cdef afs_int32 code
        cdef afs_int32 uid = self._NameOrId(user), gid = self._NameOrId(group)

        code = ubik_PR_AddToGroup(self.client, 0, uid, gid)
        pyafs_error(code)

    def _RemoveFromGroup(self, user, group):
        """
        Remove the given user from the given group.
        """
        cdef afs_int32 code
        cdef afs_int32 uid = self._NameOrId(user), gid = self._NameOrId(group)

        code = ubik_PR_RemoveFromGroup(self.client, 0, uid, gid)
        pyafs_error(code)

    def _ListMembers(self, ident):
        """
        Get the membership of an entity.

        If id is a group, this returns the users that are in that
        group.

        If id is a user, this returns the list of groups that user is
        on.

        This returns a list of PTS IDs.
        """
        cdef afs_int32 code, over
        cdef prlist alist
        cdef int i
        cdef object members = []

        cdef afs_int32 id = self._NameOrId(ident)

        alist.prlist_len = 0
        alist.prlist_val = NULL

        code = ubik_PR_ListElements(self.client, 0, id, &alist, &over)

        if alist.prlist_val is not NULL:
            for i in range(alist.prlist_len):
                members.append(alist.prlist_val[i])
            free(alist.prlist_val)

        pyafs_error(code)

        return members

    def _ListOwned(self, owner):
        """
        Get all groups owned by an entity.
        """
        cdef afs_int32 code, over
        cdef prlist alist
        cdef int i
        cdef object owned = []

        cdef afs_int32 oid = self._NameOrId(owner)

        alist.prlist_len = 0
        alist.prlist_val = NULL

        code = ubik_PR_ListOwned(self.client, 0, oid, &alist, &over)

        if alist.prlist_val is not NULL:
            for i in range(alist.prlist_len):
                owned.append(alist.prlist_val[i])
            free(alist.prlist_val)

        pyafs_error(code)

        return owned

    def _ListEntry(self, ident):
        """
        Load a PTEntry instance with information about the provided
        entity.
        """
        cdef afs_int32 code
        cdef prcheckentry centry
        cdef object entry = PTEntry()

        cdef afs_int32 id = self._NameOrId(ident)

        code = ubik_PR_ListEntry(self.client, 0, id, &centry)
        pyafs_error(code)

        _ptentry_from_c(entry, &centry)
        return entry

    def _ChangeEntry(self, ident, newname=None, newid=None, newoid=None):
        """
        Change the name, ID, and/or owner of a PTS entity.

        For any of newname, newid, and newoid which aren't specified
        or ar None, the value isn't changed.
        """
        cdef afs_int32 code
        cdef afs_int32 c_newid = 0, c_newoid = 0
        cdef char * c_newname

        cdef afs_int32 id = self._NameOrId(ident)

        if newname is None:
            newname = self._IdToName(id)
        c_newname = newname
        if newid is not None:
            c_newid = newid
        if newoid is not None:
            c_newoid = newoid

        code = ubik_PR_ChangeEntry(self.client, 0, id, c_newname, c_newoid, c_newid)
        pyafs_error(code)

    def _IsAMemberOf(self, user, group):
        """
        Return True if the given user is a member of the given group.
        """
        cdef afs_int32 code
        cdef afs_int32 flag

        cdef afs_int32 uid = self._NameOrId(user), gid = self._NameOrId(group)

        code = ubik_PR_IsAMemberOf(self.client, 0, uid, gid, &flag)
        pyafs_error(code)

        return bool(flag)

    def _ListMax(self):
        """
        Return a tuple of the maximum user ID and the maximum group
        ID currently assigned.
        """
        cdef afs_int32 code, uid, gid

        code = ubik_PR_ListMax(self.client, 0, &uid, &gid)
        pyafs_error(code)

        return (uid, gid)

    def _SetMaxUserId(self, id):
        """
        Set the maximum currently assigned user ID (the next
        automatically assigned UID will be id + 1)
        """
        cdef afs_int32 code

        code = ubik_PR_SetMax(self.client, 0, id, 0)
        pyafs_error(code)

    def _SetMaxGroupId(self, id):
        """
        Set the maximum currently assigned user ID (the next
        automatically assigned UID will be id + 1)
        """
        cdef afs_int32 code

        code = ubik_PR_SetMax(self.client, 0, id, PRGRP)
        pyafs_error(code)

    def _ListEntries(self, users=None, groups=None):
        """
        Return a list of PTEntry instances representing all entries in
        the PRDB.

        Returns just users by default, but can return just users, just
        groups, or both.
        """
        cdef afs_int32 code
        cdef afs_int32 flag = 0, startindex = 0, nentries, nextstartindex
        cdef prentries centries
        cdef unsigned int i

        cdef object entries = []

        if groups is None or users is True:
            flag |= PRUSERS
        if groups:
            flag |= PRGROUPS

        while startindex != -1:
            centries.prentries_val = NULL
            centries.prentries_len = 0
            nextstartindex = -1

            code = ubik_PR_ListEntries(self.client, 0, flag, startindex, &centries, &nextstartindex)
            if centries.prentries_val is not NULL:
                for i in range(centries.prentries_len):
                    e = PTEntry()
                    _ptentry_from_c(e, <prcheckentry *>&centries.prentries_val[i])
                    entries.append(e)
                free(centries.prentries_val)
            pyafs_error(code)

            startindex = nextstartindex

        return entries

    def _SetFields(self, ident, access=None, groups=None, users=None):
        """
        Update the fields for an entry.

        Valid fields are the privacy flags (access), the group quota
        (groups), or the "foreign user quota" (users), which doesn't
        actually seem to do anything, but is included for
        completeness.
        """
        cdef afs_int32 code
        cdef afs_int32 mask = 0, flags = 0, nusers = 0, ngroups = 0

        cdef afs_int32 id = self._NameOrId(ident)

        if access is not None:
            flags = access
            mask |= PR_SF_ALLBITS
        if groups is not None:
            ngroups = groups
            mask |= PR_SF_NGROUPS
        if users is not None:
            nusers = users
            mask |= PR_SF_NGROUPS

        code = ubik_PR_SetFieldsEntry(self.client, 0, id, mask, flags, ngroups, nusers, 0, 0)
        pyafs_error(code)

    def _AfsToKrb5(self, afs_name):
        """Convert an AFS principal to a Kerberos v5 one."""
        cdef krb5_context ctx = NULL
        cdef krb5_principal princ = NULL
        cdef krb5_error_code code = 0
        cdef char * krb5_princ = NULL
        cdef char *name = NULL, *inst = NULL, *realm = NULL
        cdef object pname, pinst, prealm

        if '@' in afs_name:
            pname, prealm = afs_name.rsplit('@', 1)
            prealm = prealm.upper()
            krb4_name = '%s@%s' % (pname, prealm)
        else:
            krb4_name = '%s@%s' % (afs_name, self.realm)

        pname, pinst, prealm = kname_parse(krb4_name)
        if pname:
            name = pname
        if pinst:
            inst = pinst
        if prealm:
            realm = prealm

        code = krb5_init_context(&ctx)
        try:
            pyafs_error(code)

            code = krb5_425_conv_principal(ctx, name, inst, realm, &princ)
            try:
                pyafs_error(code)

                code = krb5_unparse_name(ctx, princ, &krb5_princ)
                try:
                    pyafs_error(code)

                    return krb5_princ
                finally:
                    if krb5_princ is not NULL:
                        free(krb5_princ)
            finally:
                if princ is not NULL:
                    krb5_free_principal(ctx, princ)
        finally:
            if ctx is not NULL:
                krb5_free_context(ctx)

    def _Krb5ToAfs(self, krb5_name):
        """Convert a Kerberos v5 principal to an AFS one."""
        cdef krb5_context ctx = NULL
        cdef krb5_principal k5_princ = NULL
        cdef char *k4_name, *k4_inst, *k4_realm
        cdef object afs_princ
        cdef object afs_name, afs_realm

        k4_name = <char *>malloc(40)
        k4_name[0] = '\0'
        k4_inst = <char *>malloc(40)
        k4_inst[0] = '\0'
        k4_realm = <char *>malloc(40)
        k4_realm[0] = '\0'

        code = krb5_init_context(&ctx)
        try:
            pyafs_error(code)

            code = krb5_parse_name(ctx, krb5_name, &k5_princ)
            try:
                pyafs_error(code)

                code = krb5_524_conv_principal(ctx, k5_princ, k4_name, k4_inst, k4_realm)
                pyafs_error(code)

                afs_princ = kname_unparse(k4_name, k4_inst, k4_realm)
                afs_name, afs_realm = afs_princ.rsplit('@', 1)

                if k4_realm == self.realm:
                    return afs_name
                else:
                    return '%s@%s' % (afs_name, afs_realm.lower())
            finally:
                if k5_princ is not NULL:
                    krb5_free_principal(ctx, k5_princ)
        finally:
            if ctx is not NULL:
                krb5_free_context(ctx)
