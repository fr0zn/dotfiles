pre_gef(){
    program_must_exist pip3
    sudo -H pip3 install capstone
    sudo -H pip3 install filebytes
    sudo -H pip3 install keystone-engine
    sudo -H pip3 install ropper
}

install_gef(){
    clone_src https://github.com/hugsy/gef.git gef
    echo "source $DOTFILE_SRC/gef/gef.py" > $DOTFILE_PATH/gdb/inits/gef
}
