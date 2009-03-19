import os
from afs._pts import PTS
import nose

def get_this_cell():
    # Feel free to add more places ThisCell might show up
    to_try = ['/private/var/db/openafs/etc/ThisCell',
              '/etc/openafs/ThisCell',
              '/usr/vice/etc/ThisCell']
    for f in to_try:
        if os.path.isfile(f):
            return open(f).read().strip()

def test_init_home_cell():
    p = PTS()
    assert p.cell == get_this_cell(), "PTS doesn't initialize to ThisCell when none specified."

def test_init_other_cell():
    cell = 'zone.mit.edu'
    p = PTS('zone.mit.edu')
    assert p.cell == cell, "PTS doesn't initialize to provided cell."

def test_user_name_to_id():
    p = PTS()
    name = 'broder'
    id = p._NameToId(name)
    assert id == 41803, "PTS can't convert user name to ID."
    assert p._IdToName(id) == name, "PTS can't convert user ID to name."

def test_group_name_to_id():
    p = PTS()
    name = 'system:administrators'
    id = p._NameToId(name)
    assert id == -204, "PTS can't convert group name to ID."
    assert p._IdToName(id) == name, "PTS can't convert group ID to name."

def test_name_or_id():
    p = PTS()
    name = 'system:administrators'
    id = -204
    assert p._NameOrId(name) == id, "PTS._NameOrId can't identify name."
    assert p._NameOrId(id) == id, "PTS._NameOrId can't identify ID."

if __name__ == '__main__':
    nose.main()
