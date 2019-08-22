import os
import subprocess
from ranger.core.loader import CommandLoader
from ranger.api.commands import Command
import ranger.api
import platform
import argparse

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
            parser = argparse.ArgumentParser()
            parser.add_argument('host', nargs='?', default="")
            parser.add_argument('port', nargs='?', default=0)
            parser.add_argument("--vm", help="Sets the vm to use", default="u16")
            parser.add_argument("--libc", help="Sets the libc to use", default="")
            _args = parser.parse_args(self.args[2:])
            if not _args.host or _args.port == 0:
                self.fm.notify("Info: no host or port specified")

            IS_VM   = False
            VM_LIBC = None
            b = lief.parse(binary.path)
            if 'EXE_FORMATS' in str(b.format):
                if str(b.format) == 'EXE_FORMATS.ELF':
                    OS = 'linux'
                    arch = str(b.header.machine_type)
                    IS_VM = True
                    if arch == 'ARCH.x86_64':
                        ARCH = 'amd64'
                        VM_LIBC = "/lib/x86_64-linux-gnu/libc.so.6"
                    elif arch == 'ARCH.i386':
                        ARCH = 'i386'
                        VM_LIBC = "/lib/i386-linux-gnu/libc.so.6"
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

                libc_to_use = 'libc-vm.so'

                if IS_VM:
                    _bin_upload = [binary.basename]
                    if os.path.isfile(_args.libc):
                        _bin_upload.append(_args.libc)
                        libc_to_use = _args.libc
                    elif VM_LIBC and _args.libc == 'vm':
                        self.fm.execute_console('down {} {} {}'.format(_args.vm, VM_LIBC, 'libc-vm.so'))
                        _bin_upload.append('libc-vm.so')
                    _bin_upload = ' '.join(_bin_upload)
                    self.fm.execute_console('up {} {}'.format(_args.vm, _bin_upload))

                fmt_template = pwn_template.format(
                        ARCH=ARCH,
                        OS=OS,
                        IS_VM=IS_VM,
                        VM_NAME=_args.vm,
                        BINARY="./" + binary.basename,
                        LIBC_NAME="./"+libc_to_use,
                        HOST=_args.host,
                        PORT=_args.port,
                        )
                sol_file = os.path.join(str(cwd),'exploit.py')
                if not os.path.isfile(sol_file):
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

    def tab(self, tabnum):
        from os.path import sep

        option =  self.arg(1)
        suboption =  self.arg(2)

        ret = ['pwn']
        options = ['vm', 'template']

        if option == 'vm':
            import subprocess
            ret = ' '.join(['pwn', 'vm', suboption])
            out = subprocess.check_output('VBoxManage list vms'.split(' ')).split('\n')
            vms = []
            for line in out:
                line = line.strip()
                if line != '':
                    vm = line.split('"')[1].strip()
                    vms.append(vm)
            ret = [' '.join([ret,vm]) for vm in vms]
            # print ret
        elif option in ['skel', 'templ', 'template', 't']:
            from os.path import dirname, basename, expanduser, join

            cwd = self.fm.thisdir.path

            rel_dest = self.rest(len(self.args))

            # expand the tilde into the user directory
            if rel_dest.startswith('~'):
                rel_dest = expanduser(rel_dest)

            # define some shortcuts
            abs_dest = join(cwd, rel_dest)
            abs_dirname = dirname(abs_dest)
            rel_basename = basename(rel_dest)
            rel_dirname = dirname(rel_dest)

            try:
                directory = self.fm.get_directory(abs_dest)

                # are we at the end of a directory?
                if rel_dest.endswith('/') or rel_dest == '':
                    if directory.content_loaded:
                        # Take the order from the directory object
                        names = [f.basename for f in directory.files]
                        if self.fm.thisfile.basename in names:
                            i = names.index(self.fm.thisfile.basename)
                            names = names[i:] + names[:i]
                    else:
                        # Fall back to old method with "os.walk"
                        _, dirnames, filenames = next(os.walk(abs_dest))
                        names = sorted(dirnames + filenames)

                # are we in the middle of the filename?
                else:
                    if directory.content_loaded:
                        # Take the order from the directory object
                        names = [f.basename for f in directory.files
                                 if f.basename.startswith(rel_basename)]
                        if self.fm.thisfile.basename in names:
                            i = names.index(self.fm.thisfile.basename)
                            names = names[i:] + names[:i]
                    else:
                        # Fall back to old method with "os.walk"
                        _, dirnames, filenames = next(os.walk(abs_dirname))
                        names = sorted([name for name in (dirnames + filenames)
                                        if name.startswith(rel_basename)])
            except (OSError, StopIteration):
                # os.walk found nothing
                pass
            else:
                # no results, return None
                if not names:
                    return None

                # one result. append a slash if it's a directory
                if len(names) == 1:
                    path = join(rel_dirname, names[0])
                    slash = '/' if os.path.isdir(path) else ''
                    return self.start(len(self.args)) + path + slash

                # more than one result. append no slash, so the user can
                # manually type in the slash to advance into that directory
            return (self.start(len(self.args)) + join(rel_dirname, name) for name in names)
        elif option == None or option == '':
            ret = [' '.join(['pwn',opt]) for opt in options]
        return ret

class down(Command):
    def execute(self):
        if self.arg(1):
            scpcmd = "scp"
            _dst = self.arg(3)
            if _dst == '':
                _dst = '.'
            scpcmd += " " + self.arg(1) + ':' + self.arg(2) + " " + _dst
            self.fm.execute_command(scpcmd)
            self.fm.notify("Downloaded!")

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
        return (self.start(1) + host for host in hosts)

class up(Command):
    def execute(self):
        if self.arg(1):
            scpcmd = ["scp", "-r"]
            if not self.arg(2):
                scpcmd.extend([f.realpath for f in self.fm.thistab.get_selection()])
            else:
                scpcmd.extend(self.args[2:])
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
            self.fm.execute_console('shell $HOME/.dotfiles/scripts/open_term.sh "ssh ' + self.arg(1) + '"')
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

class fzf_select(Command):
    """
    :fzf_select

    Find a file using fzf.

    With a prefix argument select only directories.

    See: https://github.com/junegunn/fzf
    """
    def execute(self):
        import subprocess
        import os.path
        if self.quantifier:
            # match only directories
            command="find -L . \( -path '*/\.*' -o -fstype 'dev' -o -fstype 'proc' \) -prune \
            -o -type d -print 2> /dev/null | sed 1d | cut -b3- | fzf +m"
        else:
            # match files and directories
            command="find -L . \( -path '*/\.*' -o -fstype 'dev' -o -fstype 'proc' \) -prune \
            -o -print 2> /dev/null | sed 1d | cut -b3- | fzf +m"
        fzf = self.fm.execute_command(command, universal_newlines=True, stdout=subprocess.PIPE)
        stdout, stderr = fzf.communicate()
        if fzf.returncode == 0:
            fzf_file = os.path.abspath(stdout.rstrip('\n'))
            if os.path.isdir(fzf_file):
                self.fm.cd(fzf_file)
            else:
                self.fm.select_file(fzf_file)
                
                
fd_deq = deque()
class fd_search(Command):
    """:fd_search [-d<depth>] <query>

    Executes "fd -d<depth> <query>" in the current directory and focuses the
    first match. <depth> defaults to 1, i.e. only the contents of the current
    directory.
    """

    def execute(self):
        import subprocess
        from ranger.ext.get_executables import get_executables
        if not 'fd' in get_executables():
            self.fm.notify("Couldn't find fd on the PATH.", bad=True)
            return
        if self.arg(1):
            if self.arg(1)[:2] == '-d':
                depth = self.arg(1)
                target = self.rest(2)
            else:
                depth = '-d1'
                target = self.rest(1)
        else:
            self.fm.notify(":fd_search needs a query.", bad=True)
            return

        # For convenience, change which dict is used as result_sep to change
        # fd's behavior from splitting results by \0, which allows for newlines
        # in your filenames to splitting results by \n, which allows for \0 in
        # filenames.
        null_sep = {'arg': '-0', 'split': '\0'}
        nl_sep = {'arg': '', 'split': '\n'}
        result_sep = null_sep

        process = subprocess.Popen(['fd', result_sep['arg'], depth, target],
                    universal_newlines=True, stdout=subprocess.PIPE)
        (search_results, _err) = process.communicate()
        global fd_deq
        fd_deq = deque((self.fm.thisdir.path + os.sep + rel for rel in
            sorted(search_results.split(result_sep['split']), key=str.lower)
            if rel != ''))
        if len(fd_deq) > 0:
            self.fm.select_file(fd_deq[0])

class fd_next(Command):
    """:fd_next

    Selects the next match from the last :fd_search.
    """

    def execute(self):
        if len(fd_deq) > 1:
            fd_deq.rotate(-1) # rotate left
            self.fm.select_file(fd_deq[0])
        elif len(fd_deq) == 1:
            self.fm.select_file(fd_deq[0])

class fd_prev(Command):
    """:fd_prev

    Selects the next match from the last :fd_search.
    """

    def execute(self):
        if len(fd_deq) > 1:
            fd_deq.rotate(1) # rotate right
            self.fm.select_file(fd_deq[0])
        elif len(fd_deq) == 1:
            self.fm.select_file(fd_deq[0])
            
            
class fzf_rga_documents_search(Command):
    """
    :fzf_rga_search_documents
    Search in PDFs, E-Books and Office documents in current directory.
    Allowed extensions: .epub, .odt, .docx, .fb2, .ipynb, .pdf.

    Usage: fzf_rga_search_documents <search string>
    """
    def execute(self):
        if self.arg(1):
            search_string = self.rest(1)
        else:
            self.fm.notify("Usage: fzf_rga_search_documents <search string>", bad=True)
            return

        import subprocess
        import os.path
        from ranger.container.file import File
        command="rga '%s' . --rga-adapters=pandoc,poppler | fzf +m | awk -F':' '{print $1}'" % search_string
        fzf = self.fm.execute_command(command, universal_newlines=True, stdout=subprocess.PIPE)
        stdout, stderr = fzf.communicate()
        if fzf.returncode == 0:
            fzf_file = os.path.abspath(stdout.rstrip('\n'))
            self.fm.execute_file(File(fzf_file))
