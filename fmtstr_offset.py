#!/usr/bin/env python3

import gdb

class fmtstr_offset(gdb.Command):
    """auto find offset for format string attack"""
    def __init__(self):
        super(self.__class__, self).__init__("fmtstr_offset", gdb.COMMAND_USER)

    def invoke(self, args, from_tty):
        raise NotImplementedError("Not implemented yet.")