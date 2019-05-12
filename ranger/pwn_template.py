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

IS_VM        = {IS_VM}
VM_NAME      = "{VM_NAME}"

BIN_NAME     = "{BINARY}"
LIBC_NAME    = "./libc.so.6"

HOST         = "{HOST}"
PORT         = {PORT}

GDB_CMD = '''
'''

def exploit(p):
    p.interactive()

if __name__ == "__main__":

    e = ELF(BIN_NAME)

    if (os.path.isfile(LIBC_NAME)):
        libc = ELF(LIBC_NAME)
        env  = dict(LD_PRELOAD = LIBC_NAME)
    else:
        libc = None
        env  = dict()

    if '1' in sys.argv:
        p = remote(HOST, PORT)
    else:
        if IS_VM:
            _ssh = ssh('fr0zn', VM_NAME)

            if 'debug' in sys.argv:
                p = gdb.debug(BIN_NAME, GDB_CMD, ssh=_ssh, env=env)
            else:
                p = _ssh.process(BIN_NAME, env=env)
                if 'attach' in sys.argv:
                    gdb.attach(p, GDB_CMD)
        else:
            if 'debug' in sys.argv:
                p = gdb.debug(BIN_NAME, GDB_CMD, env=env)
            else:
                p = process(BIN_NAME, env=env)
                if 'attach' in sys.argv:
                    gdb.attach(p, GDB_CMD)

    exploit(p)
