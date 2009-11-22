from afs import _acl
from afs._acl import READ, WRITE, INSERT, LOOKUP, DELETE, LOCK, ADMINISTER, \
    USR0, USR1, USR2, USR3, USR4, USR5, USR6, USR7
from afs._acl import getCallerAccess

_canonical = {
    "read": "rl",
    "write": "rlidwk",
    "all": "rlidwka",
    "mail": "lik",
    "none": "",
}

_reverseCanonical = dict((y, x) for (x, y) in _canonical.iteritems())

_charBitAssoc = [
    ('r', READ),
    ('l', LOOKUP),
    ('i', INSERT),
    ('d', DELETE),
    ('w', WRITE),
    ('k', LOCK),
    ('a', ADMINISTER),
    ('A', USR0),
    ('B', USR1),
    ('C', USR2),
    ('D', USR3),
    ('E', USR4),
    ('F', USR5),
    ('G', USR6),
    ('H', USR7),
]

_char2bit = dict(_charBitAssoc)


def rightsToEnglish(s):
    """Turns a rlwidwka string into a canonical name if possible"""
    if s in _reverseCanonical:
        return _reverseCanonical[s]
    else:
        return ''

def readRights(s):
    """Canonicalizes string rights to bitmask"""
    if s in _canonical: s = _canonical[s]
    return _parseRights(s)

def showRights(r):
    """Takes a bitmask and returns a rwlidka string"""
    s = ""
    for char,mask in _charBitAssoc:
        if r & mask == mask: s += char
    return s

def _parseRights(s):
    """Parses a rwlid... rights tring to bitmask"""
    r = 0
    try:
        for c in s:
            r = r | _char2bit[c]
    except KeyError:
        raise ValueError
    return r

def _parseAcl(inp):
    lines = inp.split("\n")
    npos = int(lines[0].split(" ")[0])
    pos = {}
    neg = {}
    for l in lines[2:]:
        if l == "": continue
        name, acl = l.split()
        if npos:
            npos -= 1
            pos[name] = int(acl)
        else:
            # negative acl
            neg[name] = int(acl)
    return (pos, neg)

def _unparseAcl(pos, neg):
    npos = len(pos)
    nneg = len(neg)
    acl = "%d\n%d\n" % (npos, nneg)
    for p in pos.items():
        acl += "%s\t%d\n" % p
    for n in neg.items():
        acl += "%s\t%d\n" % n
    return acl

class ACL(object):
    def __init__(self, pos, neg):
        """
        ``pos``
            Dictionary of usernames to positive ACL bitmasks
        ``neg``
            Dictionary of usernames to negative ACL bitmasks
        """
        self.pos = pos
        self.neg = neg
    @staticmethod
    def retrieve(dir, follow=True):
        """Retrieve the ACL for an AFS directory"""
        pos, neg = _parseAcl(_acl.getAcl(dir, follow))
        return ACL(pos, neg)
    def apply(self, dir, follow=True):
        """Apply the ACL to a directory"""
        self._clean()
        _acl.setAcl(dir, _unparseAcl(self.pos, self.neg), follow)
    def _clean(self):
        """Clean an ACL by removing any entries whose bitmask is 0"""
        for n,a in self.pos.items():
            if a == 0:
                del self.pos[n]
        for n,a in self.neg.items():
            if a == 0:
                del self.neg[n]
    def set(self, user, bitmask, negative=False):
        """Set the bitmask for a given user"""
        if bitmask < 0 or bitmask > max(_char2bit.values()):
            raise ValueError, "Invalid bitmask"
        if negative:
            self.neg[user] = bitmask
        else:
            self.pos[user] = bitmask
    def remove(self, user, negative=False):
        """Convenience function to removeSet the bitmask for a given user"""
        self.set(user, 0, negative)
        
