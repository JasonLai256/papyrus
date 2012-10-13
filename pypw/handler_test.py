# -*- coding:utf-8 -*-

import unittest
import tempfile
import math

from handler import AESHandler


class TestAESHandler(unittest.TestCase):
    
    def setUp(self):
        self.tmpfile = tempfile.NamedTemporaryFile()
        self.handler = AESHandler()
        self.handler.initialize('provide a key', self.tmpfile.name)

    def tearDown(self):
        self.tmpfile.close()

    def test_data_persistance(self):
        self.assertTrue(self.handler.add_record(u'web', u'facebook', u'lol2012'))
        self.assertTrue(self.handler.add_record(u'web', u'google', u'answer42'))
        self.assertTrue(self.handler.add_record(u'银行', u'招商银行', u'money888'))
        # there is a invalid group name, so that the gid would be NaN
        self.assertTrue(self.handler.add_record(u'_rid', u'testgroup', u'test123'))

        self.assertEqual(len(self.handler.data['records']), 4)
        self.assertEqual(self.handler.data['currentID'], 4)
        self.assertEqual(self.handler.data['currentGID'], 2)
        self.assertEqual(len(self.handler._records['_rid']), 4)
        self.assertEqual(len(self.handler._records['_gid']), 3)
        self.assertEqual(len(self.handler._records['_gidmap']), 3)
        self.assertTrue(
            self.handler._records['_gidmap'].has_key('Invalid Group Name')
        )
        
        handler2 = AESHandler()
        handler2.initialize('provide a key', self.tmpfile.name)

        self.assertEqual(self.handler.data['digest'], handler2.data['digest'])
        self.assertEqual(self.handler.data['currentID'], handler2.data['currentID'])
        self.assertEqual(self.handler.data['currentGID'], handler2.data['currentGID'])
        self.assertEqual(len(self.handler.data['records']),
                         len(handler2.data['records']))
        # compare the `handler.data['records']` between two handlers 
        for i in range(len(handler2.data['records'])):
            for key in handler2.data['records'][i]:
                # should be ignore the "not a number" case
                if isinstance(handler2.data['records'][i][key], float) and \
                   math.isnan(handler2.data['records'][i][key]):
                    continue
                self.assertEqual(self.handler.data['records'][i][key],
                                 handler2.data['records'][i][key])

    def test_32byte_key_generate(self):
        key1 = AESHandler.figure_32Byte_key('not enough 32 bytes')
        key2 = AESHandler.figure_32Byte_key('exceed 32 bytes' * 3)
        self.assertTrue(key1.startswith('not enough 32 bytes'))
        self.assertEqual(len(key1), 32)
        self.assertEqual(len(key2), 32)

    def test_encrypt_and_decrypt(self):
        key = AESHandler.figure_32Byte_key('provide a key')
        text = 'test encrypt and decrypt.'
        ciphertext = AESHandler.encrypt(text, key)
        plaintext = AESHandler.decrypt(ciphertext, key)
        self.assertEqual(text, plaintext)


if __name__ == '__main__':
    unittest.main()
