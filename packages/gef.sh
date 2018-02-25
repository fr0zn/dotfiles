install_gef(){
    clone https://github.com/hugsy/gef.git "$DOTFILE_SRC/gef"
    add_line "$HOME/.gdbinit" "source $DOTFILE_SRC/gef/gef.py"
}
