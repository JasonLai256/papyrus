# -*- coding:utf-8 -*-
"""
    papyrus
    ~~~~~~~

    A safely (use AES256 encrypt/decrypt) simple cmd program that manage
    the infomation of passwords.

    :copyright: (c) 2012 by Jason Lai.
    :license: BSD, see LICENSE for more details.
"""

import os
import json
import cmd
import logging
import hashlib
from datetime import datetime
from collections import defaultdict

from Crypto.Cipher import AES
from Crypto import Random


class AESHandler(object):
    """
    Handler that control and manage the infomations of user, use 
    AES to encrypt/decrypt user infomations
    """

    def __init__(self):
        # Initialize Log
        self.log = logging.getLogger('papyrus')
        # Initialize the attributes of class
        self.initialized = False
        self.filepath = ''
        self.cipher = ''
        self.data = None
        # self._records is a proxy structure mapping to the records of 
        # self.data and is use for better contrive records.
        self._records = defaultdict(dict)

    def initialize(self, cipher, filepath='records.dat'):
        """
        validate the cipher and load the data from outside file.

        :return: True if successfully initialize, else will be False
        """
        self.filepath = filepath
        self.cipher = self.figure_32Byte_key(cipher)
        
        # first initial the program
        if not os.path.exists(self.filepath) or \
                               not os.path.getsize(self.filepath):
            # initiali the self.data and self._records
            self._init_data()
            self.initialized = True
            return self.initialized

        # validate the cipher and load the data
        with open(filepath, 'rb') as f:
            ciphertext = f.read()
            jsondata = self.decrypt(ciphertext, self.cipher)

        try:
            self.data = json.loads(jsondata)
            if self.data['digest'] == self.cipher:
                self.initialized = True
            # initiali the self._records
            self._setup_structure()
        except ValueError:
            self.log.error('Error occur when load the JSON text.')
        except Exception, err:
            self.log.error('Error occur in AESHandler initialized - %s', err)

        return self.initialized

    def write(self):
        """
        encrypt the infomations and dump into outside file.
        """
        jsontext = json.dumps(self.data)
        with open(self.filepath, 'w') as f:
            ciphertext = self.encrypt(jsontext, self.cipher)
            f.write(ciphertext)

    def add_record(self, group, item, value, note=None):
        try:
            record = self._compose_record(group, item, value, note)
            self.write()
            self._adjust_structure(record)
            return True
        except Exception, err:
            self.log.error('Error occur in adding record - %s', err)
            return False

    def update_record(self, record_id, value, note=None):
        if self._records['_rid'].has_key(record_id):
            try:
                record = self._records['_rid'][record_id]
                record['value'] = value
                record['updated'] = datetime.today().isoformat('_')
                if note:
                    record['note'] = note
                self.write()
                return True
            except Exception, err:
                self.log.error('Error occur in updating record - %s', err)
                return False
        else:
            return False

    def delete_record(self, record_id):
        if self._records['_rid'].has_key(record_id):
            try:
                record = self._records['_rid'][record_id]
                rid, gid = record['id'], record['gid']
                group, item = record['group'], record['itemname']
                del self._records['_rid'][rid]
                del self._records[group][item]
                if len(self._records['_gid'][gid]) == 1:
                    del self._records['_gid'][gid]
                    del self._records[group]
                else:
                    # delete the record in the _records['_gid']
                    for i in range(len(self._records['_gid'][gid])):
                        if self._records['_gid'][gid][i]['id'] == rid:
                            del self._records['_gid'][gid][i]
                            break

                # delete the record in the data['records']
                for i in range(len(self.data['records'])):
                    if self.data['records'][i]['id'] == rid:
                        del self.data['records'][i]
                        break
                self.write()
                return True
            except Exception, err:
                self.log.error('Error occur in deleting record - %s', err)
                raise
                return False
        else:
            return False

    @property
    def records(self):
        return self._records

    def _init_data(self):
        structure = {
            'digest': self.cipher,
            'records': [],
            'currentID': 0,
            'currentGID': 0,
        }
        self.data = structure        
        self._setup_structure()

    def _setup_structure(self):
        for record in self.data['records']:
            self._adjust_structure(record)

    def _adjust_structure(self, record):
        rid, gid = record['id'], record['gid']
        group = record['group']
        item = record['itemname']
        self._records['_rid'][rid] = record
        self._records['_gid'].setdefault(gid, []).append(record)
        self._records[group][item] = record

        # groupmap is a helper subdict contain (group, gid) pairs
        if not self._records['_gidmap'].has_key(group):
            self._records['_gidmap'][group] = record['gid']

    def _compose_record(self, group, item, value, note=None):
        created = datetime.today().isoformat('_')
        # handle some state about group id
        if group in ('_rid', '_gid', '_gidmap'):
            group = 'Invalid Group Name'
            gid = float('nan')    # Not a number
        elif self._records.has_key(group):
            gid = self._records['_gidmap'][group]
        else:
            gid = self.data['currentGID']
            self.data['currentGID'] += 1

        record = {
            # the `id` is increase use the currentID field
            'id': self.data['currentID'],
            'gid': gid,
            'group': group,
            'itemname': item,
            'value': value,
            'note': note,
            'created': created,
            'updated': created,
        }
        self.data['currentID'] += 1
        self.data['records'].append(record)
        return record

    @classmethod
    def figure_32Byte_key(cls, text):
        sha = hashlib.sha256()
        sha.update(text)
        digest = sha.hexdigest()[::2]

        if len(text) > 32:
            return digest
        else:
            keystr = text + digest
            return keystr[:32]

    @classmethod
    def encrypt(cls, plaintext, key):
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        msg = iv + cipher.encrypt(plaintext)
        return msg

    @classmethod
    def decrypt(cls, ciphertext, key):
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return cipher.decrypt(ciphertext)[AES.block_size:]


class PapyrusException(Exception):
    """Exception class for papyrus."""
    pass


class Papyrus(cmd.Cmd):
    """A safely (use AES256 encrypt/decrypt) simple cmd program that manage
    the infomation of passwords.
    """

    prompt = u'(papyrus) >>> '
    intro = ("Papyrus: A simple cmd program that manage the infomation of "
             "passwords.\n")

    def __init__(self):
        self.handler = AESHandler()
        cmd.Cmd.__init__(self)

    def onecmd(self, line):
        """
        overriding the onecmd method in base class that change default behavior.
        """
        try:
            return cmd.Cmd.onecmd(self, line)
        except PapyrusException, err:
            # There is use the PapyrusException to transmit failed infomation.
            # Then print the papyrus info's message to the STDOUT.
            # If has any doubt about the codes, please check the cmd source.
            print(err.message)

    def _validate_line(self, line, lengths, cmd):
        err_msg = "\nPlease type `help {0}` get help message!".format(cmd)
        if not line:
            raise PapyrusException(err_msg)
        argv = line.strip().split()
        if len(argv) not in lengths:
            raise PapyrusException(err_msg)

        return argv

    def do_init(self, line):
        """Help message:
        Usage: init init_cipher [filepath]
        
        Initialize the program. This operation should be launched before
        other operations.
        The `filepath` argument is the path of the file contain the infomation
        of passwords. By default, `filepath` is 'records.dat'.
        """
        argv = self._validate_line(line, lengths=(1, 2), cmd='init')
        if not self.handler.initialize(*argv):
            raise PapyrusException("\nFail to initialize the program.")

    def do_ls(self, line):
        """Help message:
        Usage: ls {group | record | `group_name` | `group_id`}
        
        List all the groups or records existing in the current program.
        """
        argv = self._validate_line(line, lengths=(1), cmd='ls')
        target = argv[0]

        if target is 'group':
            # match the group
            for item in self.handler.records:
                if item not in ('_rid', '_gid'):
                    # a dirty hack for figure out group_id
                    gid = self.handler.records[item].values()[0]['gid']    
                    print "({0}, {1})".format(gid, item)

        elif target is 'record':
            # match the record
            for record in self.handler.records['_rid'].values():
                print "({0}, {1})".format(record['rid'], record['itemname'])

        elif target in self.handler.records['_gid']:
            # match the group_id
            for record in self.handler.records['_gid'][target]:
                print "({0}, {1})".format(record['rid'], record['itemname'])

        elif target in self.handler.records:
            # match the group_name
            for itemname in self.handler.records[target].values():
                record = self.handler.records[target][itemname]
                print "({0}, {1})".format(record['rid'], record['itemname'])
        else:
            raise PapyrusException("\nFail to list the '{0}'.".format(target))

    def do_add(self, line):
        """Help message:
        Usage: add group item value [note]

        Add a record to the program.
        """
        argv = self._validate_line(line, lengths=(3, 4), cmd='add')
        if not self.handler.add_record(*argv):
            raise PapyrusException("\nFail to add record to the program.")

    def do_update(self, line):
        """Help message:
        Usage: update record_id value [note]

        Update a record to the program.
        """
        argv = self._validate_line(line, lengths=(2, 3), cmd='update')
        if not self.handler.update_record(*argv):
            raise PapyrusException("\nFail to update record to the program.")

    def do_delete(self, line):
        """Help message:
        Usage: delete record_id

        Delete a record to the program.
        """
        argv = self._validate_line(line, lengths=(1), cmd='delete')
        if not self.handler.delete_record(*argv):
            raise PapyrusException("\nFail to delete record to the program.")

    # def complete_delete(self, text, line, begidx, endidx):
    #     pass

    # def complete_update(self, text, line, begidx, endidx):
    #     pass

    # def complete_ls(self, text, line, begidx, endidx):
    #     pass

    def do_quit(self, line):
        """Help message:
        Usage: quit
        
        Exit the program.
        """
        return True

    def do_EOF(self, line):
        """Exit"""
        return True


if __name__ == '__main__':
    Papyrus().cmdloop()
