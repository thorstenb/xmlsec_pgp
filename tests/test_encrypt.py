import pgpy
import xmlsec
import xmlsec_pgp
from copy import deepcopy
from lxml import etree

# Test PGP key
keyblob = """-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1

lQIGBFcrxWsBBAC3UAvJ8JOOefYqUXASsTy+Ppc4zwqOXfTYOeSJN9WtYX5AuOQ6
cw6TNhalLpOXK6XKqJh2IjIXzpMcS1/C85BSR+EzvnuUyaP+YMr8W92jVp4j69bE
Du2wv6npNqoD8jcsA0rKyAhTH4syM/dLrmE98DUrbldlpMuGECPX4/kUHwARAQAB
/gcDAjn8qArivYAUYKTkqwU9u4lyGaPAs8VMsImY4XRK1wXNXsfT/ohn8Ahx8rVY
wx+PRqUzlkKlb4Xdr0s/EJIjtnlxsvOailcUEhZD/Edhs9XB61ItPWRZmN1melkt
Med0K/XBw5qz2TzfFpPZhb1v6LcB0FfgJ66+RAYoDeufDgF6YMrhksy/Vsp3S+a6
4N+rPn5idq5O9NeoOLT+yDdAU9ExP1VwuHV9WMTOroqKJeF2OYoIm9WgsLgzdE59
nIqU4/Eqd1aJBm8+E0mnxEwEnKbI4KNkKst00EqfNb3Up8FQIWxUFyZrZe/bfy3B
uk3b3gLQRTjProGBMKpvQd/wlUU5DI/v9GG1kiOgnWWgdaVZ0Ek7sMhZcTwijG4V
iEZ8A5mVQYpLNQpcocDgh3IrG0dHUd5Z+EEZBDRlIZFIJVurjOWzjs3ilwvaajfS
iHWbeL86hvlUVWhBL+j1HlL4YZ86JbMsI3CFfhBWOZjlAL14osSG5EK0HFRlc3Qg
VXNlciA8dGVzdEBleGFtcGxlLmNvbT6IvgQTAQIAKAUCVyvFawIbAwUJAAFRgAYL
CQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQjypAUdH0E9epLgP9G1/+OSJdUes+
wd3/BgpmLjudlXEWAVcfxvRZGneccep9yyk/tXtRsyg632NuyDAeRNDZdCTAG4cT
d1cW+ZrlC39OS+8U+AAUR/6BUbsrWODk15s7eN9K76a6IOKodJDwuBEdd2PqGBwv
CT0jniOJWPUYv2s8pO0agw7UWGMS7fSdAgYEVyvFawEEAMM8iVg0DMlJOJT0nhEB
vtTweJHxPvjJgLsfRQlvCeAk5SkZWZMNYqFtqm9z6bj2BhnyXSKE0CAzn1MxlsZ6
9IZBOCvTFTQcZYCuv7U0czkSLs2Po7ULyrJ0SiI/NKcRuXHGvCK7VPwi+dQ93HMA
YLNgarnRuqU3lwu5MrhtNeZNABEBAAH+BwMCOfyoCuK9gBRgfmWRiQsUsSPdE9CG
mhjQp7J9dMA2+X8l+CgiO2SbwHnbvl+XKKhIshcQIjvR+LtvgDQhfCzNRp50gFTT
FMdDzFUIjEaaTex8vqAdWYPr9yJ+UHgTUhSuPyxn5Pv+Vdu2hSj/iW2ixETCbyfE
9kzGal0bZAdbXVDpqhjmklp3UydBmqG5h2bxq/YxTJbfxKMQBm7RL800Gn60QhlS
CNCfYQQkotrig33sXyxCTRd47bi5fimkbh9Yeru9ColP5jAD0Jn760qbNLf7/xSB
rQDCs/I8GYX2kdBYk9Libm7cQa64kD5Z36mtgM4DFB10mC1h5QeZnEBms7Jz/OQ3
ukTYMIa0TOUgcncLn4+JJrFPNLXjOk5WbwAs7HX+12V+WoNhJhUvXLaqGM7+QkTS
e0DIk5BdVqRZxUDID348HPGCmsmURTFD71lFJ3/ufH7kaGNesRpgdZeJaFRQrm/w
JKCW6IrIlKuqci44LvJAa4ilBBgBAgAPBQJXK8VrAhsMBQkAAVGAAAoJEI8qQFHR
9BPXwUUD/i8yy+S9ZcuhVqLnNcW6LsHxThq61uLG+1q87hPXTlK2kw3C9A269Ij8
ARHQhjAIARJC70sBieJ+LL2VVkVXjEgbzjvSGMA7vDWFPI8z/tuqJpJymsGKDlRx
JmIPdDQNVRmdezrwuZSeiRZlN7J3M6t/zrB71GUOBjHKKbnkjJuD
=zrdn
-----END PGP PRIVATE KEY BLOCK-----"""

key, _ = pgpy.PGPKey.from_blob(keyblob)


def test_encrypt_decrypt_xml():
    # Load the public cert
    manager = xmlsec_pgp.KeysManager()
    manager.add_key(key)
    orig_template = etree.fromstring(
        """<Envelope><Data>Hello, World!</Data></Envelope>"""
    )
    template = deepcopy(orig_template)

    assert template is not None
    # Prepare for encryption
    enc_data = xmlsec.template.encrypted_data_create(
        template, xmlsec.Transform.AES128, type=xmlsec.EncryptionType.ELEMENT,
        ns="xenc"
    )

    xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
    key_info = xmlsec.template.encrypted_data_ensure_key_info(
        enc_data, ns="dsig"
    )
    enc_key = xmlsec.template.add_encrypted_key(
        key_info, xmlsec.Transform.RSA_OAEP
    )
    key_info2 = xmlsec.template.encrypted_data_ensure_key_info(enc_key)
    # key_name = xmlsec.template.add_key_name(key_info2)
    xmlsec_pgp.add_pgp_data(key_info2)
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)

    data = template.find('./Data')

    assert data is not None
    # Encrypt!
    enc_ctx = xmlsec_pgp.EncryptionContext(manager)
    enc_ctx.key = xmlsec.Key.generate(
        xmlsec.KeyData.AES, 128, xmlsec.KeyDataType.SESSION
    )
    enc_datsa = enc_ctx.encrypt_xml(enc_data, data)
    assert enc_data is not None
    enc_method = xmlsec.tree.find_child(
        enc_data, xmlsec.Node.ENCRYPTION_METHOD, xmlsec.Namespace.ENC
    )
    assert enc_method is not None
    assert enc_method.get("Algorithm") == \
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
    key_info = xmlsec.tree.find_child(
        enc_data, xmlsec.Node.KEY_INFO, xmlsec.Namespace.DS
    )
    assert key_info is not None
    enc_method = xmlsec.tree.find_node(
        key_info, xmlsec.Node.ENCRYPTION_METHOD, xmlsec.Namespace.ENC
    )
    assert enc_method is not None
    assert enc_method.get("Algorithm") == \
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
    cipher_value = xmlsec.tree.find_node(
        key_info, xmlsec.Node.CIPHER_VALUE, xmlsec.Namespace.ENC
    )
    assert cipher_value is not None

    root = template
    with key.unlock("test"):
        manager = xmlsec_pgp.KeysManager()
        manager.add_key(key)
        enc_ctx = xmlsec_pgp.EncryptionContext(manager)
        enc_data = xmlsec.tree.find_child(
            root, "EncryptedData", xmlsec.Namespace.ENC
        )
        assert enc_data is not None
        decrypted = enc_ctx.decrypt(enc_data)
    assert decrypted.tag == "Data"

    assert etree.tostring(decrypted) == etree.tostring(orig_template[0]), \
        repr([etree.tostring(orig_template[0]), etree.tostring(decrypted)])


if __name__ == "__main__":
    test_encrypt_decrypt_xml()
