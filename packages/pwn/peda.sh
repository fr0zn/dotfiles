install_peda(){
    clone_src https://github.com/longld/peda.git peda
    echo "source $DOTFILE_SRC/peda/peda.py" > $DOTFILE_PATH/gdb/inits/peda.gdbinit
}
