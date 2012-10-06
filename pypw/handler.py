# -*- coding:utf-8 -*-
"""
    pypw.handler
    ~~~~~~~~~~~~

    Implements the actually handling object for pypw.

    :copyright: (c) 2012 by Jason Lai.
    :license: BSD, see LICENSE for more details.
"""

import logging


class Handler(object):
    """
    Handlers control and manage the infomations of user.
    """

    def __init__(self):
        # Initialize Log
        self.log = logging.getLogger('pypw')

    def initialize(self, cipher):
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

    
