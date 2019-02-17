import os

template = '''#!/usr/bin/env python2
from pwn import *
import sys
import distutils.spawn

if distutils.spawn.find_executable('termite'):
    context.terminal = ['termite', '-e']
else:
    context.terminal = ['tmux', 'splitw', '-h']

DEBUG = False

GDB_CMD = \'\'\'
\'\'\'

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
'''

class Skeleton(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "skel"
    _syntax_  = "{:s}".format(_cmdline_)

    def do_invoke(self, argv):

        if len(argv) < 2:
            err("Invalid number of arguments")
            return

        tmp_dir = os.path.dirname(get_filepath())
        tmp = template.format(HOST=argv[0], PORT=argv[1], BINARY=get_filename())
        open(tmp_dir + '/exploit.py','w').write(tmp)

register_external_command(Skeleton())
