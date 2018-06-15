install_peda(){
    clone_src https://github.com/longld/peda.git
    add_line "$HOME/.gdbinit" "source $DOTFILE_SRC/peda/peda.py"
}
