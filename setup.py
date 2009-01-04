#!/usr/bin/python

from setuptools import setup, find_packages
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
libraries = ['bos', 'volser', 'vldb', 'afsrpc', 'afsauthent', 'cmd', 'usd',
             'audit', 'util',
             'util', 'afsrpc', 'util',
             'util', 'afsauthent', 'util',
             'resolv']
extra_objects = []
define_macros = [('AfS_PTHREAD_ENV', None)]

for i, l in enumerate(libraries):
    if l in ('util', 'vlib') and \
            not os.path.exists('%s/lib/afs/lib%s.a' % (root, l)):
        libraries.pop(i)
        extra_objects.append('%s/lib/afs/%s.a' % (root, l))
    elif l == 'com_err':
        libraries.pop(i)
        extra_objects.append('%s/lib/afs/libcom_err.a')

setup(
    name="PyAFS",
    version="0.0.0",
    description="PyAFS - Python bindings for AFS",
    author="Evan Broder",
    author_email="broder@mit.edu",
    license="GPL",
    requires=['Cython'],
    packages=find_packages(),
    ext_modules=[
        Extension("afs._pts",
                  ["afs/_pts.pyx"],
                  libraries=libraries,
                  include_dirs=include_dirs,
                  library_dirs=library_dirs,
                  extra_objects=extra_objects,
                  define_macros=define_macros)
        ],
    cmdclass= {"build_ext": build_ext}
)
