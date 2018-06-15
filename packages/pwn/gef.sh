install_gef(){
    clone_src https://github.com/hugsy/gef.git
    add_line "$HOME/.gdbinit" "source $DOTFILE_SRC/gef/gef.py"
}
