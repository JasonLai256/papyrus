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
import sys
import json
import cmd
import logging
import hashlib
import getpass
from datetime import datetime
from collections import defaultdict

from Crypto.Cipher import AES
from Crypto import Random


class AESHandler(object):
    """Handler that control and manage the infomations of user, use 
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
        # self.data and is use for better retrieve records.
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
        """encrypt the infomations and dump into outside file.
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
        record_id = int(record_id)
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
        record_id = int(record_id)
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
    introduction = ("Papyrus: A simple cmd program that manage the infomation of "
             "passwords.\n")

    def preloop(self):
        """Overriding the onecmd method in base class for initialize the 
        program. This operation should be launched before other operations.
        """
        self.handler = AESHandler()
        try:
            self.stdout.write(str(self.introduction)+"\n")
            # First check the Env variable
            if 'PAPYRUS_RECORD_PATH' in os.environ:
                filepath = os.environ['PAPYRUS_RECORD_PATH']
                self.stdout.write(u"From Env, the record file path is `%s`.\n" % filepath)
                self.stdout.flush()
            else:
                self.stdout.write(u"Enter Info's File Path (default `records.dat`): ")
                self.stdout.flush()
                filepath = self.stdin.readline().strip()
                if not filepath:
                    filepath = 'records.dat'
            pw = getpass.getpass(u'Please Enter The Initiali Cipher: ')
            if not self.handler.initialize(pw, filepath):
                sys.exit('ERROR: invalid cipher or unknown exception.')
        except Exception, err:
            print 'ERROR:', err
            sys.exit(1)

    def onecmd(self, line):
        """overriding the onecmd method in base class that change default
        behavior.
        """
        try:
            return cmd.Cmd.onecmd(self, line)
        except PapyrusException, err:
            # There is use the PapyrusException to transmit failed infomation.
            # Then print the papyrus info's message to the STDOUT.
            # If has any doubt about the codes, please check the cmd source.
            print err.message

    def _validate_line(self, line, lengths, cmd):
        line = line.decode('utf-8')
        err_msg = (u"The command `{0} {1}` is incorrect, please type "
                   u"`help {2}` get help message!").format(cmd, line, cmd)
        if not line:
            raise PapyrusException(err_msg)
        if ("'" in line or '"' in line):
            if cmd == 'add' and len(line.split()) >= 4:
                splitnum = 3
            elif cmd == 'update' and len(line.split()) >= 3:
                splitnum = 2
            args = line.split(' ', splitnum)
            args[splitnum] = args[splitnum].strip("'\"")
        else:
            args = line.strip().split()
        if len(args) not in lengths:
            raise PapyrusException(err_msg)

        return args

    def _ls_case_groups(self, target):
        print u"* List all (group_id, group) pairs:"
        for group in self.handler.records:
            if group not in ('_rid', '_gid', '_gidmap'):
                gid = self.handler.records['_gidmap'][group]
                print u"\t({0}, {1})".format(gid, group)

    def _ls_case_records(self, target):
        print u"* List all (record_id, record) pairs:"
        for record in self.handler.records['_rid'].values():
            print u"\t({0}, {1})".format(record['id'], record['itemname'])

    def _ls_case_group_id(self, target):
        groupname = self.handler.records['_gid'][target][0]['group']
        print (u"* List all infomation of the records in Group - `{0}`:\n"
               u"\t(record_id, group, itemname, value)").format(groupname)
        for record in self.handler.records['_gid'][target]:
            enc_value = '****'.join((record['value'][0], record['value'][-1]))
            print u"\t({0}, {1}, {2})".format(record['id'], record['itemname'],
                                              enc_value)

    def _ls_case_group_name(self, target):
        print (u"* List all infomation of the records in Group - `{0}`:\n"
               u"\t(record_id, group, itemname, value)").format(target)
        for itemname in self.handler.records[target].keys():
            record = self.handler.records[target][itemname]
            enc_value = '****'.join((record['value'][0], record['value'][-1]))
            print u"\t({0}, {1}, {2})".format(record['id'], record['itemname'],
                                              enc_value)

    def do_ls(self, line):
        """Help message:
        Usage: ls {groups | records | `group_name` | `group_id`}

        selected args::
          - single `ls` command: default to show all groups
          - `groups`:  literal key word, show all the groups
          - `records`:  literal key word, show all the records
          - group_name: group name, show all the records in the specific group
          - group_id:  group id, show all the records in the specific group
        
        List all the groups or records existing in the current program.
        """
        # single `ls` command, default to show all groups
        if line == '':
            self._ls_case_groups('groups')
            return
        
        args = self._validate_line(line, lengths=(1, 2), cmd='ls')
        target = args[0]
        if target.isdigit():
            target = int(target)

        # match the `group` keyword
        if target == 'groups':
            self._ls_case_groups(target)
        # match the `record` keyword
        elif target == 'records':
            self._ls_case_records(target)
        # match the group_id
        elif target in self.handler.records['_gid']:
            self._ls_case_group_id(target)
        # match the group_name
        elif target in self.handler.records and \
                             target not in ('_rid', '_gid', '_gidmap'):
            self._ls_case_group_name(target)
        else:
            print u"Fail to list the '{0}'.".format(target)
            print u"Usage: ls {groups | records | `group_name` | `group_id`}"

    def do_info(self, line):
        """Help message:
        Usage: info record_id

        args::
          - record_id:  the id of the record, `ls` is a useful command for
                        lookup the record id.

        Show the full infomation about specific record.
        """
        args = self._validate_line(line, lengths=(1,), cmd='info')
        try:
            rid = int(args[0])
            record = self.handler.records['_rid'][rid]
        except ValueError:
            print "The `record_id` should be a integer."
            return
        except KeyError:
            print "The `record_id` - {0} - not exist.".format(rid)
            return
        print u"The infomation of record - `{0}`:".format(rid)
        print u'       id: ', record['id']
        print u'      gid: ', record['gid']
        print u'    group: ', record['group']
        print u'   record: ', record['itemname']
        print u'    value: ', record['value']
        print u'     note: ', record['note']
        print u'  created: ', record['created']
        print u'   update: ', record['updated']

    def do_add(self, line):
        """Help message:
        Usage: add group item value [note]

        args::
          - group:  group name of the record.
          - item:   item name of the record.
          - value:  value of the record. well, there is the place store the password.
          - note(optional):  note of the record, the lengths of the note is unlimit
                             but should be within the quotation marks (' or ").

        Add a record to the program.
        """
        args = self._validate_line(line, lengths=(3, 4), cmd='add')
        if not self.handler.add_record(*args):
            raise PapyrusException(u"Fail to add record to the program.")

    def do_update(self, line):
        """Help message:
        Usage: update record_id value [note]

        args::
          - record_id:  the id of the record, `ls` is a useful command for
                        lookup the record id.
          - note(optional):  note of the record, the lengths of the note is unlimit
                             but should be within the quotation marks (' or ").

        Update a record to the program.
        """
        args = self._validate_line(line, lengths=(2, 3), cmd='update')
        if not self.handler.update_record(*args):
            raise PapyrusException(u"Fail to update record to the program.")

    def do_delete(self, line):
        """Help message:
        Usage: delete record_id

        args::
          - record_id:  the id of the record, `ls` is a useful command for
                        lookup the record id.

        Delete a record to the program.
        """
        args = self._validate_line(line, lengths=(1,), cmd='delete')
        if not self.handler.delete_record(*args):
            raise PapyrusException(u"Fail to delete record to the program.")

    # def complete_update(self, text, line, begidx, endidx):
    #     clist = []
    #     for record in self.handler.records['_rid'].values():
    #         rid, itemname = record['id'], record['itemname']
    #         clist.append(u"({0}, {1})".format(rid, itemname))

    #     if not text:
    #         completions = clist[:]
    #         return completions

    # def complete_ls(self, text, line, begidx, endidx):
    #     clist = [u'groups', u'records']
    #     for group, gid in self.handler.records['_gidmap'].items():
    #         clist.append(u"({0}, {1})".format(gid, group))

    #     if not text:
    #         completions = clist[:]
    #         return completions

    # def complete_info(self, text, line, begidx, endidx):
    #     clist = []
    #     for record in self.handler.records['_rid'].values():
    #         rid, itemname = record['id'], record['itemname']
    #         clist.append(u"({0}, {1})".format(rid, itemname))

    #     if not text:
    #         completions = clist[:]
    #         return completions

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
