#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
import sys
import distutils.spawn

if distutils.spawn.find_executable('termite'):
    context.terminal = ['termite', '-e']
else:
    context.terminal = ['tmux', 'splitw', '-h']

context.arch = "{ARCH}"

HOST = "{HOST}"
PORT = {PORT}

GDB_CMD = '''
'''

def exploit(p):
    p.interactive()

if __name__ == "__main__":

    e = ELF("{BINARY}")

    context.binary = "{BINARY}"

    if '1' in sys.argv:
        p = remote(HOST, PORT)
    else:
        p = process("{BINARY}")

        if 'gdb' in sys.argv:
            gdb.attach(p, GDB_CMD)
        else:

    exploit(p)
