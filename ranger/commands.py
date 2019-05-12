import os
import subprocess
from ranger.core.loader import CommandLoader
from ranger.api.commands import Command
import ranger.api
import platform

import lief

class compress(Command):
    def execute(self):
        """ Compress marked files to current directory """
        cwd = self.fm.thisdir
        marked_files = cwd.get_selection()

        if not marked_files:
            return

        def refresh(_):
            cwd = self.fm.get_directory(original_path)
            cwd.load_content()

        original_path = cwd.path
        parts = self.line.split()
        au_flags = parts[1:]

        descr = "compressing files in: " + os.path.basename(parts[1])
        obj = CommandLoader(args=['apack'] + au_flags + \
                [os.path.relpath(f.path, cwd.path) for f in marked_files], descr=descr)

        obj.signal_bind('after', refresh)
        self.fm.loader.add(obj)

        self.fm.execute_console("unmark")

    def tab(self):
        """ Complete with current folder name """

        extension = ['.zip', '.tar.gz', '.rar', '.7z']
        return ['compress ' + os.path.basename(self.fm.thisdir.path) + ext for ext in extension]

class extract(Command):
    def execute(self):
        """ Extract copied files to current directory """
        copied_files = tuple(self.fm.copy_buffer)
        # Check for copied files, if not check for selected
        if not copied_files:
            cwd = self.fm.thisdir
            copied_files = tuple(cwd.get_selection())

        if not copied_files:
            return

        def refresh(_):
            cwd = self.fm.get_directory(original_path)
            cwd.load_content()

        one_file = copied_files[0]
        cwd = self.fm.thisdir
        original_path = cwd.path
        au_flags = ['-X', cwd.path]
        au_flags += self.line.split()[1:]
        au_flags += ['-e']

        self.fm.copy_buffer.clear()
        self.fm.cut_buffer = False
        if len(copied_files) == 1:
            descr = "extracting: " + os.path.basename(one_file.path)
        else:
            descr = "extracting files from: " + os.path.basename(one_file.dirname)
        obj = self.fm.run(['aunpack'] + au_flags \
                + [f.path for f in copied_files])

        self.fm.execute_console("unmark")

class umount(Command):
    def execute(self):
        cwd = self.fm.thisdir
        marked_files = cwd.get_selection()

        if not marked_files:
            return

        if platform.system() == 'Darwin':
            self.fm.run(["sudo","diskutil","umountDisk"] + [f.path for f in marked_files])
        else:
            self.fm.run(["sudo","umount"] + [f.path for f in marked_files])

class mount(Command):
    def execute(self):
        cwd = self.fm.thisdir

        device = self.arg(1)
        if not device:
            self.fm.notify("Error: no device specified", bad=True)
            return

        marked_files = cwd.get_selection()

        if len(marked_files) == 1:
            to_mount = marked_files[0].path
        else:
            to_mount = cwd.path

        self.fm.run(["sudo","mount"] + [device, to_mount])

    def tab(self):
         return self._tab_directory_content()

old_hook_init = ranger.api.hook_init

def hook_init(fm):
    def fasd_add():
        fm.execute_console("shell fasd --add '" + fm.thisfile.path + "'")
    fm.signal_bind('execute.before', fasd_add)
    return old_hook_init(fm)

ranger.api.hook_init = hook_init

class z(Command):
    """
    :fasd

    Jump to directory using fasd
    """
    def execute(self):
        import subprocess
        arg = self.rest(1)
        if arg:
            directory = subprocess.check_output(["fasd", "-d"]+arg.split(), universal_newlines=True).strip()
            self.fm.cd(directory)

class pwn(Command):
    def execute(self):
        cwd = self.fm.thisdir
        marked_files = cwd.get_selection()
        binary = marked_files[0]

        action = self.arg(1)
        if not action:
            self.fm.notify("Error: no action specified", bad=True)
            return
        if action in ['skel', 'templ', 'template', 't']:
            host = self.arg(2)
            port = self.arg(3)
            if not host or not port:
                host = ""
                port = 0
                self.fm.notify("Info: no host or port specified")

            VM_NAME = ""
            IS_VM   = False
            b = lief.parse(binary.path)
            if 'EXE_FORMATS' in str(b.format):
                if str(b.format) == 'EXE_FORMATS.ELF':
                    VM_NAME = "u16"
                    OS = 'linux'
                    arch = str(b.header.machine_type)
                    IS_VM = True
                    if arch == 'ARCH.x86_64':
                        ARCH = 'amd64'
                    elif arch == 'ARCH.i386':
                        ARCH = 'i386'
                    elif arch == 'ARCH.ARM':
                        ARCH = 'arm'
                    elif arch == 'ARCH.AARCH64':
                        ARCH = 'aarch64'
                    else:
                        self.fm.notify("Error: No supported elf architecture", bad=True)
                elif str(b.format) == 'EXE_FORMATS.MACHO':
                    OS = 'freebsd'
                    cpu = str(b.header.cpu_type)
                    if cpu == 'CPU_TYPES.x86_64':
                        ARCH = 'amd64'
                    elif cpu == 'CPU_TYPES.x86':
                        ARCH = 'i386'
                    else:
                        self.fm.notify("Error: No supported macho cpu", bad=True)
                elif str(b.format) == 'EXE_FORMATS.PE':
                    OS = 'windows'
                    machine = str(b.header.machine)
                    if machine == 'MACHINE_TYPES.AMD64':
                        ARCH = 'amd64'
                    elif machine == 'MACHINE_TYPES.I386':
                        ARCH = 'i386'
                    else:
                        self.fm.notify("Error: No supported PE machine", bad=True)
                else:
                    self.fm.notify("Error: No supported format", bad=True)

                pwn_template = open(os.path.expanduser("~/.dotfiles/ranger/pwn_template.py")).read()

                fmt_template = pwn_template.format(
                        ARCH=ARCH,
                        OS=OS,
                        IS_VM=IS_VM,
                        VM_NAME=VM_NAME,
                        BINARY="./" + binary.basename,
                        HOST=host,
                        PORT=port,
                        )
                sol_file = os.path.join(str(cwd),'exploit.py')
                open(sol_file,'w').write(fmt_template)

            else:
                self.fm.notify("Error: no executable selected", bad=True)
                return
        elif action == 'vm':
            subaction = self.arg(2)
            if subaction:
                if subaction in ['s', 'start']:
                    vm = self.arg(3)
                    if vm:
                        cmd = "VBoxManage startvm {} --type headless".format(vm).split(' ')
                        self.fm.execute_command(cmd)
                elif subaction in ['stop']:
                    vm = self.arg(3)
                    if vm:
                        cmd = "VBoxManage controlvm {} poweroff".format(vm).split(' ')
                        self.fm.execute_command(cmd)
                elif subaction in ['p','pause']:
                    vm = self.arg(3)
                    if vm:
                        cmd = "VBoxManage controlvm {} pause".format(vm).split(' ')
                        self.fm.execute_command(cmd)
                elif subaction in ['r','resume']:
                    vm = self.arg(3)
                    if vm:
                        cmd = "VBoxManage controlvm {} resume".format(vm).split(' ')
                        self.fm.execute_command(cmd)
                else:
                    self.fm.notify("Error: unknown command", bad=True)
            else:
                self.fm.notify("Error: no subaction specified", bad=True)

        # if not device:
            # self.fm.notify("Error: no device specified", bad=True)
            # return


        # if len(marked_files) == 1:
            # to_mount =
        # else:AARCH64
            # to_mount = cwd.path

        # self.fm.run(["sudo","mount"] + [device, to_mount])

    def tab(self):
         return self._tab_directory_content()

class up(Command):
    def execute(self):
        if self.arg(1):
            scpcmd = ["scp", "-r"]
            scpcmd.extend([f.realpath for f in self.fm.thistab.get_selection()])
            _vm_path = self.arg(1)
            if ":" not in self.arg(1):
                _vm_path += ":"
            scpcmd.append(_vm_path)
            self.fm.execute_command(scpcmd)
            self.fm.notify("Uploaded!")

    def tab(self):
        import os.path
        try:
            import paramiko
        except ImportError:
            """paramiko not installed"""
            return

        try:
            with open(os.path.expanduser("~/.ssh/config")) as file:
                paraconf = paramiko.SSHConfig()
                paraconf.parse(file)
        except IOError:
            """cant open ssh config"""
            return

        hosts = paraconf.get_hostnames()
        # remove any wildcard host settings since they're not real servers
        hosts.discard("*")
        return (self.start(1) + host + ":" for host in hosts)

class ssh(Command):
    def execute(self):
        if self.arg(1):
            self.fm.execute_console("shell $HOME/.dotfiles/scripts/open_term.sh ssh " + self.arg(1))
    def tab(self):
        import os.path
        try:
            import paramiko
        except ImportError:
            """paramiko not installed"""
            return

        try:
            with open(os.path.expanduser("~/.ssh/config")) as file:
                paraconf = paramiko.SSHConfig()
                paraconf.parse(file)
        except IOError:
            """cant open ssh config"""
            return

        hosts = paraconf.get_hostnames()
        # remove any wildcard host settings since they're not real servers
        hosts.discard("*")
        return (self.start(1) + host + ":" for host in hosts)
