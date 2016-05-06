import xmlsec
from lxml import etree

from .base import _Context


class SignatureContext(_Context):
    def __init__(self):
        self.key = None
        self.ctx = xmlsec.SignatureContext()

    def register_id(self, node, id_attr="ID", id_ns=None):
        self.ctx.register_id(node, id_attr, id_ns)

    def enable_reference_transform(self, transform):
        self.ctx.enable_reference_transform(transform)

    def enable_signature_transform(self, transform):
        self.ctx.enable_signature_transform(transform)

    def set_enabled_key_data(self, keydata_list):
        self.ctx.set_enabled_key_data(keydata_list)

    def sign_binary(self, data, transform):
        key = self._privkey_to_xmlsec(self.key)
        key.name = "(pgp)"
        self.ctx.key = key
        return self.ctx.sign_binary(data, transform)

    def sign(self, sign_node):
        key_info = xmlsec.tree.find_child(sign_node, xmlsec.Node.KEY_INFO)
        pgp_data = xmlsec.tree.find_child(key_info, "PGPData")
        assert len(pgp_data) == 0
        self._add_key_info(pgp_data, self._pubkey(self.key))

        key = self._privkey_to_xmlsec(self.key)
        key.name = "(pgp)"
        self.ctx.key = key
        return self.ctx.sign(sign_node)

    def verify_binary(self, data, transform, sign):
        key = self._pubkey_to_xmlsec(self.key)
        key.name = "(pgp)"
        self.ctx.key = key
        return self.ctx.verify_binary(data, transform, sign)

    def verify(self, sign_node):
        key_info = xmlsec.tree.find_child(sign_node, xmlsec.Node.KEY_INFO)
        pgp_data = xmlsec.tree.find_child(key_info, "PGPData")
        assert pgp_data is not None
        key = self._pubkey_to_xmlsec(self.key)
        key.name = "(pgp)"
        self.ctx.key = key
        return self.ctx.verify(sign_node)


def add_pgp_data(key_info):
    """
    Add a PGPData element to the KeyInfo block
    """
    return etree.SubElement(
        key_info,
        etree.QName(xmlsec.Namespace.DS, "PGPData")
    )
