import _acl
from _acl import READ, WRITE, INSERT, LOOKUP, DELETE, LOCK, ADMINISTER, \
    USR0, USR1, USR2, USR3, USR4, USR5, USR6, USR7
from _acl import getCallerAccess

_canonical = {
    "read":     "rl",
    "write":    "rwlidwk",
    "all":      "rwlidwka",
    "mail":     "lik",
    "none":     "",
}

_charBitAssoc = [
    ('r', READ),
    ('w', WRITE),
    ('i', INSERT),
    ('l', LOOKUP),
    ('d', DELETE),
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


def crights(s):
    """Canonicalizes string rights to bitmask"""
    if s in _canonical: s = _canonical[s]
    return _parseRights(s)

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
    def retrieve(dir):
        """Retrieve the ACL for an AFS directory"""
        pos, neg = _parseAcl(_acl.getAcl(dir))
        return ACL(pos, neg)

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

