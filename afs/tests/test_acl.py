import nose
import afs.acl as acl

def test_crights():
    assert acl.crights('read') & acl.READ
    assert acl.crights('read') & acl.LOOKUP
    assert not acl.crights('read') & acl.WRITE

def test_retrieve():
    assert acl.ACL.retrieve('/afs/athena.mit.edu/contrib/bitbucket2').pos['system:anyuser'] & acl.WRITE
    assert acl.ACL.retrieve('/afs/athena.mit.edu/user/t/a/tabbott').neg['yuranlu'] & acl.USR0

def test_getCallerAccess():
    assert acl.getCallerAccess('/afs/athena.mit.edu/contrib/bitbucket2') & acl.WRITE

if __name__ == '__main__':
    nose.main()

