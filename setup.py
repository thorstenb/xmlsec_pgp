#!/usr/bin/env python3

from distutils.core import setup

setup(
    author_email="luke@lukeross.name",
    author="Luke Ross",
    description="xmlenc and xmldsig XML encryption and signing using PGP keys",
    install_requires=["cryptography", "lxml", "pgp", "xmlsec"],
    license="MIT",
    name="xmlsec-pgp",
    packages=["xmlsec-pgp"],
    version="0.1",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 3",
        "Topic :: Text Processing :: Markup :: XML"
    ]
)
