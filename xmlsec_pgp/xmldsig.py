import binascii
import xmlsec
from base64 import b64encode
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from lxml import etree


class SignatureContext():
    def __init__(self):
        self.key = None

    @property
    def _pubkey(self):
        return self.key if self.key.is_public else self.key.pubkey

    def _pubkey_to_xmlsec(self):
        pem = self._pubkey._key.keymaterial.__pubkey__().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
        return xmlsec.Key.from_memory(pem, xmlsec.KeyFormat.PEM)

    def _privkey_to_xmlsec(self):
        assert not self.key.is_public
        pem = self.key._key.keymaterial.__privkey__().private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        )
        return xmlsec.Key.from_memory(pem, xmlsec.KeyFormat.PEM)

    def sign_binary(self, data, transform):
        ctx = xmlsec.SignatureContext()
        key = self._privkey_to_xmlsec()
        key.name = "(pgp)"
        ctx.key = key
        return ctx.sign_binary(data, transform)

    def sign(self, sign_node):
        key_info = xmlsec.tree.find_child(sign_node, xmlsec.Node.KEY_INFO)
        pgp_data = xmlsec.tree.find_child(key_info, "PGPData")
        assert len(pgp_data) == 0
        etree.SubElement(
            pgp_data, etree.QName(xmlsec.Namespace.DS, "PGPKeyID")
        ).text = b64encode(
            binascii.unhexlify(self._pubkey.fingerprint.keyid)
        ).decode("ascii")
        etree.SubElement(
            pgp_data, etree.QName(xmlsec.Namespace.DS, "PGPKeyPacket")
        ).text = b64encode(bytes(self._pubkey)).decode("ascii")

        key = self._privkey_to_xmlsec()
        key.name = "(pgp)"
        ctx = xmlsec.SignatureContext()
        ctx.key = key
        return ctx.sign(sign_node)

    def verify_binary(self, data, transform, sign):
        ctx = xmlsec.SignatureContext()
        key = self._pubkey_to_xmlsec()
        key.name = "(pgp)"
        ctx.key = key
        return ctx.verify_binary(data, transform, sign)

    def verify(self, sign_node):
        key_info = xmlsec.tree.find_child(sign_node, xmlsec.Node.KEY_INFO)
        pgp_data = xmlsec.tree.find_child(key_info, "PGPData")
        assert pgp_data is not None
        key = self._pubkey_to_xmlsec()
        key.name = "(pgp)"
        ctx = xmlsec.SignatureContext()
        ctx.key = key
        return ctx.verify(sign_node)


def add_pgp_data(key_info):
    """
    Add a PGPData element to the KeyInfo block
    """
    return etree.SubElement(
        key_info,
        etree.QName(xmlsec.Namespace.DS, "PGPData")
    )
