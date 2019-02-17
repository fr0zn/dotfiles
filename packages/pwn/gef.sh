install_gef(){
    clone_src https://github.com/hugsy/gef.git gef
    echo "source $DOTFILE_SRC/gef/gef.py" > $DOTFILE_PATH/gdb/inits/gef.gdbinit
    echo "source $DOTFILE_PATH/gdb/gef/skel.py" >> $DOTFILE_PATH/gdb/inits/gef.gdbinit
}

post_gef_ubuntu(){
    # ubuntu gdb uses python3 by default
    install piputils pip3
}
