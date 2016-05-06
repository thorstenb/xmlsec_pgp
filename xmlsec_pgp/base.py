import binascii
import xmlsec
from base64 import b64encode
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from lxml import etree


class _Context(object):
    def _pubkey(self, key):
        return key if key.is_public else key.pubkey

    def _pubkey_to_xmlsec(self, key):
        pem = self._pubkey(key)._key.keymaterial.__pubkey__().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
        return xmlsec.Key.from_memory(pem, xmlsec.KeyFormat.PEM)

    def _privkey_to_xmlsec(self, key):
        assert not key.is_public
        pem = key._key.keymaterial.__privkey__().private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        )
        return xmlsec.Key.from_memory(pem, xmlsec.KeyFormat.PEM)

    def _add_key_info(self, pgp_data, key):
        etree.SubElement(
            pgp_data, etree.QName(xmlsec.Namespace.DS, "PGPKeyID")
        ).text = b64encode(
            binascii.unhexlify(key.fingerprint.keyid)
        ).decode("ascii")
        etree.SubElement(
            pgp_data, etree.QName(xmlsec.Namespace.DS, "PGPKeyPacket")
        ).text = b64encode(bytes(key)).decode("ascii")
