#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
import os

#context.terminal = ['tmux', 'splitw', '-h']
context.terminal = [ os.path.join(os.path.expanduser("~"),
                   '.dotfiles/scripts/open_term.sh') ]

context.arch = "{ARCH}"
context.os   = "{OS}"

BIN_NAME     = "{BINARY}"
IS_VM        = {IS_VM}
VM_NAME      = "{VM_NAME}"

HOST         = "{HOST}"
PORT         = {PORT}

GDB_CMD = '''
'''

def exploit(p):
    p.interactive()

if __name__ == "__main__":

    e = ELF(BIN_NAME)

    if '1' in sys.argv:
        p = remote(HOST, PORT)
    else:
        if IS_VM:
            _ssh = ssh('fr0zn', VM_NAME)

            if 'debug' in sys.argv:
                p = gdb.debug(BIN_NAME, GDB_CMD, ssh=_ssh)
            else:
                p = _ssh.process(BIN_NAME)
                if 'attach' in sys.argv:
                    gdb.attach(p, GDB_CMD)
        else:
            if 'debug' in sys.argv:
                p = gdb.debug(BIN_NAME, GDB_CMD)
            else:
                p = process(BIN_NAME)
                if 'attach' in sys.argv:
                    gdb.attach(p, GDB_CMD)

        exploit(p)
