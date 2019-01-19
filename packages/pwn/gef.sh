install_gef(){
    clone_src https://github.com/hugsy/gef.git gef
    echo "source $DOTFILE_SRC/gef/gef.py" > $DOTFILE_PATH/gdb/inits/gef.gdbinit
}

post_gef(){
    sudo pip3 install unicorn
    sudo pip3 install capstone
    sudo pip3 install keystone-engine
    sudo pip3 install ropper
}
