#!/usr/bin/env python3

from distutils.core import setup

setup(
    author_email="luke@lukeross.name",
    author="Luke Ross",
    description="xmlenc and xmldsig XML encryption and signing using PGP keys",
    install_requires=["cryptography", "lxml", "pgpy", "xmlsec"],
    license="MIT",
    name="xmlsec_pgp",
    packages=["xmlsec_pgp"],
    url="https://github.com/lukeross/xmlsec_pgp",
    version="0.1",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 3",
        "Topic :: Text Processing :: Markup :: XML"
    ]
)
