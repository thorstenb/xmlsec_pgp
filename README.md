# xmlsec_pgp

Ability to add XML signatures to documents using PGP keys.

Requires:

- xmlsec
- PGPy
- cryptography

`xmlsec_pgp` provides a replacement SignatureContext() which can accept a
PGPy key, and can then sign and verify as normal.

I haven't been able to find any other implementations to test interoperability
with - feedback welcome.
