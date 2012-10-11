# -*- coding:utf-8 -*-
"""
    pypw.handler
    ~~~~~~~~~~~~

    Implements the actually handling object for pypw.

    :copyright: (c) 2012 by Jason Lai.
    :license: BSD, see LICENSE for more details.
"""

from Crypto.Cipher import AES
from Crypto import Random

import os
import json
import logging
import hashlib
from datetime import datetime
from collections import defaultdict


class AESHandler(object):
    """
    Handler that control and manage the infomations of user, use 
    AES to encrypt/decrypt user infomations
    """

    def __init__(self):
        # Initialize Log
        self.log = logging.getLogger('pypw')
        # Initialize the attributes of class
        self.initialized = False
        self.filepath = ''
        self.cipher = ''
        self.data = None
        # self.records is a proxy structure mapping to the records of 
        # self.data and is use for better contrive records.
        self.records = defaultdict(dict)

    def initialize(self, cipher, filepath='records.dat'):
        """
        validate the cipher and load the data from outside file.

        :return: True if successfully initialize, else will be False
        """
        self.filepath = filepath
        self.cipher = self.figure_32Byte_key(cipher)
        
        # first initial the program
        if not os.path.existx(self.filepath):
            self.data = compose_structure(cipher)
            self.initialized = True
            return self.initialized

        # validate the cipher and load the data
        with open(filepath, 'rb') as f:
            ciphertext = f.read()
            jsondata = self.decrypt(ciphertext, key)

        try:
            self.data = json.loads(jsondata)
            if self.data['digest'] == self.cipher:
                self.initialized = True
            # initiali the self.data and self.records
            self._init_data()
        except ValueError:
            self.log.error('Error occur when load the JSON text.')
        except Exception, err:
            self.log.error('Error occur in AESHandler initialized - %s', err)

        return self.initialized

    def write(self):
        """
        encrypt the infomations and dumps into outside file.
        """
        jsontext = json.dumps(self.data)
        with open(self.filepath, 'w') as f:
            ciphertext = self.encrypt(jsontext, self.cipher)
            f.write(ciphertext)

    def add_record(group, item, value, note):
        try:
            record = self._compose_record(group, item, value, note)
            self.data['records'].append(record)
            self.data['currentID'] += 1
            self.data['currentGID'] += 1
            self.write()
            self._adjust_structure(record)
        except Exception, err:
            self.log.error('Error occur in adding record - %s', err)
            return False
        return True

    def update_record(group, item, value, note):
        try:
            # TODO: complete the method
            self.write()
        except Exception, err:
            self.log.error('error occur in updating record - %s', err)
            return False
        return True

    @property
    def records(self):
        pass

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
        rid = record['id']
        gid = record['gid']
        group = record['group']
        item = record['itemname']
        self.records['rid'][rid] = record
        self.records['gid'].setdefault(gid, []).append(record)
        self.records[group][item] = record

    def _compose_record(group, item, value, note=None):
        created = datetime.today().isoformat('_')
        record = {
            'id': self.data['currentID'] + 1,
            'gid': self.data['currentGID'] + 1,
            'group': group,
            'itemname': item,
            'value': value,
            'note': note,
            'created': created,
            'updated': created,            
        }
        return record

    @classmethod
    def figure_32Byte_key(cls, text):
        sha = hashlib.sha256()
        sha.update(text)
        return sha.hexdigest()[::2]

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
