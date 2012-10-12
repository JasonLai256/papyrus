# -*- coding:utf-8 -*-

import unittest
import tempfile

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
        self.assertTrue(self.handler.add_record(u'bank', u'BOA', u'money888'))

        print self.handler.data
        self.assertEqual(len(self.handler.data['records']), 3)
        self.assertEqual(self.handler.data['currentID'], 3)
        self.assertEqual(self.handler.data['currentGID'], 2)
        
        handler2 = AESHandler()
        handler2.initialize('provide a key', self.tmpfile.name)
        
        self.assertDictEqual(self.handler.data, handler2.data)
        self.assertListEqual(self.handler.data['records'],
                             handler2.data['records'])

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
