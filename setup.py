#!/usr/bin/python

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
import sys
import os

for root in ['/Library/OpenAFS/Tools',
             '/usr/local',
             '/usr/afsws',
             '/usr']:
    if os.path.exists('%s/include/afs/afs.h' % root):
        break

include_dirs = [os.path.join(os.path.dirname(__file__), 'afs'),
                '%s/include' % root]
library_dirs = ['%s/lib' % root,
                '%s/lib/afs' % root]
libraries = ['afsauthent', 'afsrpc', 'resolv']
define_macros = [('AFS_PTHREAD_ENV', None)]

def PyAFSExtension(module):
    return Extension(module,
                     ["%s.pyx" % module.replace('.', '/')],
                     libraries=libraries,
                     include_dirs=include_dirs,
                     library_dirs=library_dirs,
                     define_macros=define_macros)

setup(
    name="PyAFS",
    version="0.0.0",
    description="PyAFS - Python bindings for AFS",
    author="Evan Broder",
    author_email="broder@mit.edu",
    license="GPL",
    requires=['Cython'],
    packages=['afs', 'afs.tests'],
    ext_modules=[
        PyAFSExtension("afs.afs"),
        PyAFSExtension("afs._pts"),
        PyAFSExtension("afs._acl"),
        ],
    cmdclass= {"build_ext": build_ext}
)
