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


class Handler(object):
    """
    Handlers control and manage the infomations of user.
    """

    def __init__(self):
        # Initialize Log
        self.log = logging.getLogger('pypw')
        # Initialize the attributes of class
        self.initialized = False
        self.filepath = ''
        self.data = None

    def initialize(self, cipher, filepath=None):
        """
        validate the cipher and load the data from outside file.

        :return: True if successfully initialize, else will be False
        """
        raise NotImplementedError

    def write(self):
        """
        encrypt the infomations and dumps into outside file.
        """
        raise NotImplementedError

    def add_record(group, record, value, update=False):
        raise NotImplementedError

    @property
    def records(self):
        raise NotImplementedError

    @classmethod
    def figure_32Byte_key(cls, text):
        sha = hashlib.sha256()
        sha.update(text)
        return sha.hexdigest()[::2]


class AESHandler(Handler):
    """
    Hander use AES to encrypt/decrypt user infomations
    """

    def __init__(self):        
        self.cipher = ''
        self.data = None
        super(AESHandler, self).__init__()

    def initialize(self, cipher, filepath='records.dat'):
        self.filepath = filepath
        self.cipher = self.figure_32Byte_key(cipher)
        
        # first initial the program
        if not os.path.existx(self.filepath):
            self._initial_data()
            self.initialized = True
            return self.initialized

        # validate the cipher and load the data
        with open(filepath, 'rb') as f:
            ciphertext = f.read()
        jsondata = self.decrypt(ciphertext, key)
        try:
            self.data = json.loads(jsondata)
        except ValueError:
            return self.initialized

        if self.data['digest'] == self.cipher:
            self.initialized = True

        return self.initialized

    def _initial_data(self):
        pass

    def write(self):
        pass

    def add_record(group, record, value, update=False):
        pass

    @property
    def records(self):
        pass

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
                
