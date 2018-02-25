install_gef(){
    clone https://github.com/hugsy/gef.git "$DOTFILE_SRC/gef"
    echo "$DOTFILE_SRC/gef/gef.py" >> $HOME/.gdbinit
}
