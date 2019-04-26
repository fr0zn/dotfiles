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

GDB_CMD = '''
'''

HOST = "{HOST}"
PORT = {PORT}

def exploit(p):
    p.interactive()

if __name__ == "__main__":

    e = ELF("{BINARY}")

    context.binary = "{BINARY}"

    if '1' in sys.argv:
        p = remote(HOST, PORT)
    else:
        if 'gdb' in sys.argv:
            p = gdb.debug("{BINARY}", GDB_CMD)
        else:
            p = process("{BINARY}")

    exploit(p)
