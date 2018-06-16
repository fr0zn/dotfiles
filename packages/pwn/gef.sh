install_gef(){
    clone_src https://github.com/hugsy/gef.git gef
    echo "source $DOTFILE_SRC/gef/gef.py" > $DOTFILE_PATH/gdb/inits/gef.gdbinit
}
