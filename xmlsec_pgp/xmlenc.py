import xmlsec
from lxml import etree

from .base import _Context


class KeysManager(object):
    def __init__(self):
        self._keys = []

    def add_key(self, key, name=None):
        self._keys.append((key, name))


class EncryptionContext(_Context):
    def __init__(self, key_manager):
        self.key_manager = key_manager
        self.key = None

    def encrypt_binary(self, enc_node, data):
        return self._do_encryption(enc_node, data, "encrypt_binary")

    def encrypt_xml(self, enc_node, node):
        return self._do_encryption(enc_node, node, "encrypt_xml")

    def encrypt_uri(self, enc_node, uri):
        return self._do_encryption(enc_node, uri, "encrypt_uri")

    def _do_encryption(self, enc_node, data, call_name):
        manager = xmlsec.KeysManager()
        key_list = [
            (k, n if n else "(pgp{})".format(i), bool(n))
            for i, (k, n) in enumerate(self.key_manager._keys)
        ]
        for pgpkey, name, _ in key_list:
            key = self._pubkey_to_xmlsec(pgpkey)
            key.name = name
            manager.add_key(key)

        # We make a KeyName for all PGPData elements so later we can match up
        key_info = xmlsec.tree.find_child(
            enc_node, xmlsec.Node.KEY_INFO
        )
        info_nodes = []
        enc_keys = key_info.findall(
            etree.QName(xmlsec.Namespace.ENC, xmlsec.Node.ENCRYPTED_KEY)
        )
        for enc_key in enc_keys:
            key_info2 = xmlsec.tree.find_child(
                enc_key, xmlsec.Node.KEY_INFO
            )
            if key_info2 is None:
                continue
            pgp_data = xmlsec.tree.find_child(key_info2, "PGPData")
            if pgp_data is None:
                continue

            key_name = xmlsec.tree.find_child(
                key_info2, "KeyName"
            )
            if key_name is not None:
                info_nodes.append((key_name, pgp_data, False))
            else:
                key_name = xmlsec.template.add_key_name(key_info2)
                info_nodes.append((key_name, pgp_data, True))

        enc_ctx = xmlsec.EncryptionContext(manager)
        enc_ctx.key = self.key
        ret = getattr(enc_ctx, call_name)(enc_node, data)

        # Patch up the PGPData elements
        for key_name, pgp_data, remove_key_name in info_nodes:
            if key_name.text:
                key, _, real_name = [
                    k for k in key_list if k[1] == key_name.text
                ][0]
                self._add_key_info(pgp_data, key)

                if not real_name and not remove_key_name:
                    key_name.text = None

            if remove_key_name:
                key_name.getparent().remove(key_name)

        return ret

    def decrypt(self, enc_node):
        manager = xmlsec.KeysManager()
        for pgpkey, name in self.key_manager._keys:
            key = self._privkey_to_xmlsec(pgpkey)
            if name:
                key.name = name
            manager.add_key(key)

        enc_ctx = xmlsec.EncryptionContext(manager)
        return enc_ctx.decrypt(enc_node)
