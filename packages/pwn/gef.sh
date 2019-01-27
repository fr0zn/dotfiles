pre_gef_ubuntu(){
    install_package cmake pkg-config
}

install_gef(){
    clone_src https://github.com/hugsy/gef.git gef
    echo "source $DOTFILE_SRC/gef/gef.py" > $DOTFILE_PATH/gdb/inits/gef.gdbinit
}

post_gef_ubuntu(){
    install piputils pre pip3
}
