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

if __name__ == '__main__':
    nose.main()
