# xmlsec_pgp

Ability to encrypt XML and add XML signatures to documents using PGP keys.

Requires:

- xmlsec
- PGPy
- cryptography

`xmlsec_pgp` provides a replacement SignatureContext(), EncryptionContext()
and KeysManager() which can accept PGPy keys, and can then sign, verify,
encrypt and decrypt as normal.

There is also the call `xmlsec_pgp.add_pgp_data(key_info_node)` to make
`<PGPData>` tags which are filled out with the PGP key ID and PGP public key.

I haven't been able to find any other implementations to test interoperability
with - feedback welcome.

This software is licensed under the MIT license. Please see the accompanying
`LICENSE` file.
