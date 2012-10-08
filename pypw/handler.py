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
import logging


class Handler(object):
    """
    Handlers control and manage the infomations of user.
    """

    def __init__(self):
        # Initialize Log
        self.log = logging.getLogger('pypw')
        self.filepath = ''

    def initialize(self, cipher, filepath=None):
        """
        validate the cipher and load the data from outside file.
        """
        raise NotImplementedError

    def write(self):
        """
        encrypt the infomations and dumps into outside file.
        """
        raise NotImplementedError

    def add_item(group, item, value, update=False):
        raise NotImplementedError

    @property
    def items(self):
        raise NotImplementedError


class AESHandler(Handler):
    """
    Hander use AES to encrypt/decrypt user infomations
    """

    def __init__(self):
        self.key = b''

    def initialize(self, cipher, filepath='records.dat'):
        if not os.path.existx(filepath):
            self._init_struct()
            return

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
        
