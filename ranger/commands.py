import os
import subprocess
from ranger.core.loader import CommandLoader
from ranger.api.commands import Command
import platform

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

class z(Command):
    def execute(self):
        if not self.arg(1):
            return
        _dir = self.arg(1)
        process = subprocess.Popen('/bin/bash', stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        command = 'source $HOME/.antigen/bundles/rupa/z/z.sh; _z -e {}'.format(_dir)
        out, err = process.communicate(command)
        if out and out != "":
            self.fm.cd(out.strip())

class pwn(Command):
    def execute(self):
        cwd = self.fm.thisdir
        marked_files = cwd.get_selection()
        binary = marked_files[0]

        action = self.arg(1)
        if not action:
            self.fm.notify("Error: no action specified", bad=True)
            return
        if action == 'skel' or action == 'templ' or action == 'template':
            host = self.arg(2)
            port = self.arg(3)
            if not host or not port:
                self.fm.notify("Error: no host or port specified", bad=True)
                return
            if "x-" in binary.filetype:
                selected_type = subprocess.check_output(["file",binary.path])
                # 64
                if "x86-64" in selected_type or "x86_64" in selected_type:
                    ARCH = 'amd64'
                # 32
                else:
                    ARCH = 'i386'
                #TODO: ARM

                pwn_template = open(os.path.expanduser("~/.dotfiles/ranger/pwn_template.py")).read()

                fmt_template = pwn_template.format(
                        ARCH=ARCH,
                        BINARY="./" + binary.basename,
                        HOST=host,
                        PORT=port,
                        )
                sol_file = os.path.join(str(cwd),'exploit.py')
                open(sol_file,'w').write(fmt_template)

            else:
                self.fm.notify("Error: no executable selected", bad=True)
                return

        # if not device:
            # self.fm.notify("Error: no device specified", bad=True)
            # return


        # if len(marked_files) == 1:
            # to_mount =
        # else:
            # to_mount = cwd.path

        # self.fm.run(["sudo","mount"] + [device, to_mount])

    def tab(self):
         return self._tab_directory_content()
