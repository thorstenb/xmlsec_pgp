import pgpy
import xmlsec
import xmlsec_pgp
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


def test_sign_generated_template_pem_with_pgp():
    # Load document file.
    template = etree.fromstring(
        '''<Envelope xmlns="urn:envelope">\n  <Data>\n\tHello, World!
           </Data>\n</Envelope>\n'''
    )
    print(etree.tostring(template, pretty_print=True))

    # Create a signature template for RSA-SHA1 enveloped signature.
    signature_node = xmlsec.template.create(
        template,
        xmlsec.Transform.EXCL_C14N,
        xmlsec.Transform.RSA_SHA1)

    assert signature_node is not None

    # Add the <ds:Signature/> node to the document.
    template.append(signature_node)

    # Add the <ds:Reference/> node to the signature template.
    ref = xmlsec.template.add_reference(signature_node, xmlsec.Transform.SHA1)

    # Add the enveloped transform descriptor.
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)

    # Add the <ds:KeyInfo/> and <ds:KeyName/> nodes.
    key_info = xmlsec.template.ensure_key_info(signature_node)
    xmlsec_pgp.add_pgp_data(key_info)

    # Sign the template.
    with key.unlock("test"):
        ctx = xmlsec_pgp.SignatureContext()
        ctx.key = key
        ctx.sign(signature_node)

    out = etree.tostring(template, pretty_print=True)
    print(out)

    signature_node = xmlsec.tree.find_node(template, xmlsec.Node.SIGNATURE)
    ctx = xmlsec_pgp.SignatureContext()
    ctx.key = key
    ctx.verify(signature_node)


def test_sign_verify_binary():
    data = b'\xa8f4dP\x82\x02\xd3\xf5.\x02\xc1\x03\xef\xc4\x86\xabC\xec\xb7>\x8e\x1f\xa3\xa3\xc5\xb9qc\xc2\x81\xb1-\xa4B\xdf\x03>\xba\xd1'
    with key.unlock("test"):
        ctx = xmlsec_pgp.SignatureContext()
        ctx.key = key

        sign = ctx.sign_binary(data, xmlsec.Transform.RSA_SHA1)

    assert sign

    ctx = xmlsec_pgp.SignatureContext()
    ctx.key = key
    ctx.verify_binary(data, xmlsec.Transform.RSA_SHA1, sign)

if __name__ == "__main_":
    test_sign_verify_binary()
    test_sign_generated_template_pem_with_pgp()
