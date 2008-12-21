#!/usr/bin/python

from setuptools import setup, find_packages
from distutils.extension import Extension
from Pyrex.Distutils import build_ext
import sys
import os

for root in ['/Library/OpenAFS/Tools',
             '/usr/local',
             '/usr/afsws',
             '/usr']:
    if os.path.exists('%s/include/afs/afs.h' % root):
        break

include_dirs = ['%s/include' % root]
library_dirs = ['%s/lib' % root,
                '%s/lib/afs' % root]

setup(
    name="PyAFS",
    version="0.0.0",
    description="PyAFS - Python bindings for AFS",
    author="Evan Broder",
    author_email="broder@mit.edu",
    license="MIT",
    requires=['Pyrex'],
    packages=find_packages(),
    ext_modules=[
        Extension("afs._pts",
                  ["afs/_pts.pyx"],
                  libraries=['bos', 'volser', 'vldb', 'afsrpc', 'afsauthent',
                             'cmd', 'usd', 'audit'],
                  include_dirs=include_dirs,
                  library_dirs=library_dirs)
        ],
    cmdclass= {"build_ext": build_ext}
)
