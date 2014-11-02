# -*- coding:utf-8 -*-

import unittest
import tempfile
from pprint import pprint
import math

from papyrus import AESHandler


class TestAESHandler(unittest.TestCase):

    def setUp(self):
        self.tmpfile = tempfile.NamedTemporaryFile()
        self.handler = AESHandler()
        self.handler.initialize('provide a key', self.tmpfile.name)

    def tearDown(self):
        self.tmpfile.close()


    def test_update_delete(self):
        self.assertTrue(self.handler.add_record(u'bank', u'boa', u'kkk3000'))
        self.assertTrue(self.handler.add_record(u'web', u'google', u'answer42'))
        self.assertTrue(self.handler.add_record(u'web', u'facebook', u'lol2012'))

        # update a record that `id` equals to 1, `gid` equals to 1
        updated = self.handler.records[u'web'][u'google']['updated']
        self.assertTrue(
            self.handler.update_record(1, u'google42', u'a note')
        )
        self.assertEqual(self.handler.data['records'][1]['value'], u'google42')
        self.assertEqual(self.handler.data['records'][0]['note'], None)
        self.assertEqual(self.handler.data['records'][1]['note'], u'a note')
        self.assertEqual(self.handler.data['records'][1]['value'],
                         self.handler.records[u'web'][u'google']['value'])
        self.assertEqual(self.handler.data['records'][1]['note'],
                         self.handler.records[u'web'][u'google']['note'])
        self.assertNotEqual(self.handler.records[u'web'][u'google']['updated'],
                            updated)

        # delete a record that `id` equals to 0 and 2, `gid` equals to 0 and 1
        self.assertEqual(len(self.handler.records['_gid']), 2)
        self.assertTrue(self.handler.delete_record(0))
        self.assertEqual(len(self.handler.records['_gid']), 1)
        self.assertEqual(len(self.handler.records['_gid'][1]), 2)
        self.assertTrue(self.handler.delete_record(2))
        self.assertEqual(len(self.handler.records['_gid']), 1)
        self.assertEqual(len(self.handler.records['_gid'][1]), 1)

        self.assertEqual(len(self.handler.data['records']), 1)
        self.assertFalse(self.handler.records['_rid'].has_key(0))
        self.assertFalse(self.handler.records['_rid'].has_key(2))
        self.assertFalse(self.handler.records['_gid'].has_key(0))
        self.assertTrue(self.handler.records['_gid'].has_key(1))
        self.assertFalse(self.handler.records.has_key(u'bank'))
        self.assertTrue(self.handler.records.has_key(u'web'))
        self.assertFalse(self.handler.records[u'web'].has_key(u'facebook'))


    def test_move(self):
        self.assertTrue(self.handler.add_record(u'bank', u'boa', u'kkk3000'))
        self.assertTrue(self.handler.add_record(u'web', u'google', u'answer42'))
        self.assertTrue(self.handler.add_record(u'web', u'facebook', u'lol2012'))

        self.assertEqual(len(self.handler.records['_gid']), 2)
        self.assertEqual(len(self.handler.records['_rid']), 3)

        # ensure the relationship between the added records
        self.assertEqual(len(self.handler.records['_gid'][0]), 1)
        self.assertEqual(len(self.handler.records['_gid'][1]), 2)
        self.assertTrue( 'boa' in self.handler.records['bank'] )
        self.assertEqual(self.handler.records['_rid'][0]['group'], 'bank')
        self.assertEqual(self.handler.records['_rid'][0]['gid'], 0)
        self.assertTrue( 'google' in self.handler.records['web'] )
        self.assertEqual(self.handler.records['_rid'][1]['group'], 'web')
        self.assertEqual(self.handler.records['_rid'][1]['gid'], 1)
        self.assertTrue( 'facebook' in self.handler.records['web'] )
        self.assertEqual(self.handler.records['_rid'][2]['group'], 'web')
        self.assertEqual(self.handler.records['_rid'][2]['gid'], 1)

        # First operation
        updated = self.handler.records[u'web'][u'google']['updated']
        self.assertTrue( self.handler.move_record(1, 0) )

        self.assertEqual(len(self.handler.records['_gid'][0]), 2)
        self.assertEqual(len(self.handler.records['_gid'][1]), 1)
        self.assertTrue( 'boa' in self.handler.records['bank'] )
        self.assertEqual(self.handler.records['_rid'][0]['group'], 'bank')
        self.assertEqual(self.handler.records['_rid'][0]['gid'], 0)
        self.assertTrue( 'google' in self.handler.records['bank'] )
        self.assertEqual(self.handler.records['_rid'][1]['group'], 'bank')
        self.assertEqual(self.handler.records['_rid'][1]['gid'], 0)
        self.assertTrue( 'facebook' in self.handler.records['web'] )
        self.assertEqual(self.handler.records['_rid'][2]['group'], 'web')
        self.assertEqual(self.handler.records['_rid'][2]['gid'], 1)

        self.assertNotEqual(self.handler.records[u'bank'][u'google']['updated'],
                            updated)

        # Second operation
        updated = self.handler.records[u'bank'][u'google']['updated']
        self.assertTrue( self.handler.move_record(1, 1) )

        self.assertEqual(len(self.handler.records['_gid'][0]), 1)
        self.assertEqual(len(self.handler.records['_gid'][1]), 2)
        self.assertTrue( 'boa' in self.handler.records['bank'] )
        self.assertEqual(self.handler.records['_rid'][0]['group'], 'bank')
        self.assertEqual(self.handler.records['_rid'][0]['gid'], 0)
        self.assertTrue( 'google' in self.handler.records['web'] )
        self.assertEqual(self.handler.records['_rid'][1]['group'], 'web')
        self.assertEqual(self.handler.records['_rid'][1]['gid'], 1)
        self.assertTrue( 'facebook' in self.handler.records['web'] )
        self.assertEqual(self.handler.records['_rid'][2]['group'], 'web')
        self.assertEqual(self.handler.records['_rid'][2]['gid'], 1)

        self.assertNotEqual(self.handler.records[u'web'][u'google']['updated'],
                            updated)

    def test_data_persistance(self):
        self.assertTrue(self.handler.add_record(u'web', u'facebook', u'lol2012'))
        self.assertTrue(self.handler.add_record(u'web', u'google', u'answer42'))
        self.assertTrue(self.handler.add_record(u'银行', u'招商银行', u'money888'))
        # there is a invalid group name, so that the gid would be NaN
        self.assertTrue(self.handler.add_record(u'_rid', u'testgroup', u'test123'))

        self.assertEqual(len(self.handler.data['records']), 4)
        self.assertEqual(self.handler.data['currentID'], 4)
        self.assertEqual(self.handler.data['currentGID'], 2)
        self.assertEqual(len(self.handler.records['_rid']), 4)
        self.assertEqual(len(self.handler.records['_gid']), 3)
        self.assertEqual(len(self.handler.records['_gidmap']), 3)
        self.assertTrue(
            self.handler.records['_gidmap'].has_key('Invalid Group Name')
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
