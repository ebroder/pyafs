import collections
from afs import _pts

try:
    SetMixin = collections.MutableSet
except AttributeError:
    SetMixin = object

class PTRelationSet(SetMixin):
    """Collection class for the groups/members of a PTEntry.

    This class, which acts like a set, is actually a view of the
    groups or members associated with a PTS Entry. Changes to this
    class are immediately reflected to the PRDB.

    Attributes:
        _ent: The PTEntry whose groups/members this instance
            represents
        _set: If defined, the set of either groups or members for this
            instance's PTEntry
    """
    def __init__(self, ent):
        """Initialize a PTRelationSet class.

        Args:
            ent: The PTEntry this instance should be associated with.
        """
        super(PTRelationSet, self).__init__()

        self._ent = ent

    def _loadSet(self):
        """Load the membership/groups for this instance's PTEntry.

        If they have not previously been loaded, this method updates
        self._set with the set of PTEntries that are either members of
        this group, or the groups that this entry is a member of.
        """
        if not hasattr(self, '_set'):
            self._set = set(self._ent._pts.getEntry(m) for m in
                            self._ent._pts._ListMembers(self._ent.id))

    def _add(self, elt):
        """Add a new PTEntry to this instance's internal representation.

        This method adds a new entry to this instance's set of
        members/groups, but unlike PTRelationSet.add, it doesn't add
        itself to the other instance's set.

        Args:
            elt: The element to add.
        """
        if hasattr(self, '_set'):
            self._set.add(self._ent._pts.getEntry(elt))

    def _discard(self, elt):
        """Remove a PTEntry to this instance's internal representation.

        This method removes an entry from this instance's set of
        members/groups, but unlike PTRelationSet.discard, it doesn't
        remove itself from the other instance's set.

        Args:
            elt: The element to discard.
        """
        if hasattr(self, '_set'):
            self._set.discard(self._ent._pts.getEntry(elt))

    def __len__(self):
        """Count the members/groups in this set.

        Returns:
            The number of entities in this instance.
        """
        self._loadSet()
        return len(self._set)

    def __iter__(self):
        """Iterate over members/groups in this set

        Returns:
            An iterator that loops over the members/groups of this
                set.
        """
        self._loadSet()
        return iter(self._set)

    def __contains__(self, name):
        """Test if a PTEntry is connected to this instance.

        If the membership of the group hasn't already been loaded,
        this method takes advantage of the IsAMemberOf lookup to test
        for membership.

        This has the convenient advantage of working even when the
        user doens't have permission to enumerate the group's
        membership.

        Args:
            name: The element whose membership is being tested.

        Returns:
            True, if name is a member of self (or if self is a member
                of name); otherwise, False
        """
        name = self._ent._pts.getEntry(name)
        if hasattr(self, '_set'):
            return name in self._set
        else:
            if self._ent.id < 0:
                return self._ent._pts._IsAMemberOf(name.id, self._ent.id)
            else:
                return self._ent._pts._IsAMemberOf(self._ent.id, name.id)

    def __repr__(self):
        self._loadSet()
        return repr(self._set)

    def add(self, elt):
        """Add one new entity to a group.

        This method will add a new user to a group, regardless of
        whether this instance represents a group or a user. The change
        is also immediately reflected to the PRDB.

        Raises:
            TypeError: If you try to add a grop group to a group, or a
                user to a user
        """
        elt = self._ent._pts.getEntry(elt)
        if elt in self:
            return

        if self._ent.id < 0:
            if elt.id < 0:
                raise TypeError(
                    "Adding group '%s' to group '%s' is not supported." %
                    (elt, self._ent))

            self._ent._pts._AddToGroup(elt.id, self._ent.id)

            elt.groups._add(self._ent)
        else:
            if elt.id > 0:
                raise TypeError(
                    "Can't add user '%s' to user '%s'." %
                    (elt, self._ent))

            self._ent._pts._AddToGroup(self._ent.id, elt.id)

            elt.members._add(self._ent)

        self._add(elt)

    def discard(self, elt):
        """Remove one entity from a group.

        This method will remove a user from a group, regardless of
        whether this instance represents a group or a user. The change
        is also immediately reflected to the PRDB.
        """
        elt = self._ent._pts.getEntry(elt)
        if elt not in self:
            return

        if self._ent.id < 0:
            self._ent._pts._RemoveFromGroup(elt.id, self._ent.id)
            elt.groups._discard(self._ent)
        else:
            self._ent._pts._RemoveFromGroup(self._ent.id, elt.id)
            elt.members._discard(self._ent)

        self._discard(elt)

    def remove(self, elt):
        """Remove an entity from a group; it must already be a member.

        If the entity is not a member, raise a KeyError.
        """
        if elt not in self:
            raise KeyError(elt)

        self.discard(elt)


class PTEntry(object):
    """An entry in the AFS protection database.

    PTEntry represents a user or group in the AFS protection
    database. Each PTEntry is associated with a particular connection
    to the protection database.

    PTEntry instances should not be created directly. Instead, use the
    "getEntry" method of the PTS object.

    If a PTS connection is authenticated, it should be possible to
    change most attributes on a PTEntry. These changes are immediately
    propogated to the protection database.

    Attributes:
      id: The PTS ID of the entry
      name: The username or group name of the entry
      count: For users, the number of groups they are a member of; for
        groups, the number of users in that group
      flags: An integer representation of the flags set on a given
        entry
      ngroups: The number of additional groups this entry is allowed
        to create
      nusers: Only meaningful for foreign-cell groups, where it
        indicates the ID of the next entry to be created from that
        cell.
      owner: A PTEntry object representing the owner of a given entry.
      creator: A PTEntry object representing the creator of a given
        entry. This field is read-only.

      groups: For users, this contains a collection class representing
        the set of groups the user is a member of.
      users: For groups, this contains a collection class representing
        the members of this group.
    """
    _attrs = ('id', 'name', 'count', 'flags', 'ngroups', 'nusers')
    _entry_attrs = ('owner', 'creator')

    def __new__(cls, pts, id=None, name=None):
        if id is None:
            if name is None:
                raise TypeError('Must specify either a name or an id.')
            else:
                id = pts._NameToId(name)

        if id not in pts._cache:
            if name is None:
                name = pts._IdToName(id)

            inst = super(PTEntry, cls).__new__(cls)
            inst._pts = pts
            inst._id = id
            inst._name = name
            if id < 0:
                inst.members = PTRelationSet(inst)
            else:
                inst.groups = PTRelationSet(inst)
            pts._cache[id] = inst
        return pts._cache[id]

    def __repr__(self):
        if self.name != '':
            return '<PTEntry: %s>' % self.name
        else:
            return '<PTEntry: PTS ID %s>' % self.id

    def _get_id(self):
        return self._id
    def _set_id(self, val):
        del self._pts._cache[self._id]
        self._pts._ChangeEntry(self.id, newid=val)
        self._id = val
        self._pts._cache[val] = self
    id = property(_get_id, _set_id)

    def _get_name(self):
        return self._name
    def _set_name(self, val):
        self._pts._ChangeEntry(self.id, newname=val)
        self._name = val
    name = property(_get_name, _set_name)

    def _get_krbname(self):
        return self._pts._AfsToKrb5(self.name)
    def _set_krbname(self, val):
        self.name = self._pts._Krb5ToAfs(val)
    krbname = property(_get_krbname, _set_krbname)

    def _get_count(self):
        self._loadEntry()
        return self._count
    count = property(_get_count)

    def _get_flags(self):
        self._loadEntry()
        return self._flags
    def _set_flags(self, val):
        self._pts._SetFields(self.id, access=val)
        self._flags = val
    flags = property(_get_flags, _set_flags)

    def _get_ngroups(self):
        self._loadEntry()
        return self._ngroups
    def _set_ngroups(self, val):
        self._pts._SetFields(self.id, groups=val)
        self._ngroups = val
    ngroups = property(_get_ngroups, _set_ngroups)

    def _get_nusers(self):
        self._loadEntry()
        return self._nusers
    def _set_nusers(self, val):
        self._pts._SetFields(self.id, users=val)
        self._nusers = val
    nusers = property(_get_nusers, _set_nusers)

    def _get_owner(self):
        self._loadEntry()
        return self._owner
    def _set_owner(self, val):
        self._pts._ChangeEntry(self.id, newoid=self._pts.getEntry(val).id)
        self._owner = val
    owner = property(_get_owner, _set_owner)

    def _get_creator(self):
        self._loadEntry()
        return self._creator
    creator = property(_get_creator)

    def _loadEntry(self):
        if not hasattr(self, '_flags'):
            info = self._pts._ListEntry(self._id)
            for field in self._attrs:
                setattr(self, '_%s' % field, getattr(info, field))
            for field in self._entry_attrs:
                setattr(self, '_%s' % field, self._pts.getEntry(getattr(info, field)))


PTS_UNAUTH = 0
PTS_AUTH = 1
PTS_FORCEAUTH = 2
PTS_ENCRYPT = 3


class PTS(_pts.PTS):
    """A connection to an AFS protection database.

    This class represents a connection to the AFS protection database
    for a particular cell.

    Both the umax and gmax attributes can be changed if the connection
    was authenticated by a principal on system:administrators for the
    cell.

    For sufficiently privileged and authenticated connections,
    iterating over a PTS object will yield all entries in the
    protection database, in no particular order.

    Args:
      cell: The cell to connect to. If None (the default), PTS
        connects to the workstations home cell.
      sec: The security level to connect with:
        - PTS_UNAUTH: unauthenticated connection
        - PTS_AUTH: try authenticated, then fall back to
          unauthenticated
        - PTS_FORCEAUTH: fail if an authenticated connection can't be
          established
        - PTS_ENCRYPT: same as PTS_FORCEAUTH, plus encrypt all traffic
          to the protection server

    Attributes:
      realm: The Kerberos realm against which this cell authenticates
      umax: The maximum user ID currently assigned (the next ID
        assigned will be umax + 1)
      gmax: The maximum (actually minimum) group ID currently assigned
        (the next ID assigned will be gmax - 1, since group IDs are
        negative)
    """
    def __init__(self, *args, **kwargs):
        self._cache = {}

    def __iter__(self):
        for pte in self._ListEntries():
            yield self.getEntry(pte.id)

    def getEntry(self, ident):
        """Retrieve a particular PTEntry from this cell.

        getEntry accepts either a name or PTS ID as an argument, and
        returns a PTEntry object with that name or ID.
        """
        if isinstance(ident, PTEntry):
            if ident._pts is not self:
                raise TypeError("Entry '%s' is from a different cell." %
                                elt)
            return ident

        elif isinstance(ident, basestring):
            return PTEntry(self, name=ident)
        else:
            return PTEntry(self, id=ident)

    def getEntryFromKrbname(self, ident):
        """Retrieve a PTEntry matching a given Kerberos v5 principal.

        getEntryFromKrb accepts a krb5 principal, converts it to the
        equivalent AFS principal, and returns a PTEntry for that
        principal."""
        return self.getEntry(self._Krb5ToAfs(ident))

    def expire(self):
        """Flush the cache of PTEntry objects.

        This method will disconnect all PTEntry objects from this PTS
        object and flush the cache.
        """
        for elt in self._cache.keys():
            del self._cache[elt]._pts
            del self._cache[elt]

    def _get_umax(self):
        return self._ListMax()[0]
    def _set_umax(self, val):
        self._SetMaxUserId(val)
    umax = property(_get_umax, _set_umax)

    def _get_gmax(self):
        return self._ListMax()[1]
    def _set_gmax(self, val):
        self._SetMaxGroupId(val)
    gmax = property(_get_gmax, _set_gmax)
