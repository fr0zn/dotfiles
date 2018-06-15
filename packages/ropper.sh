pre_ropper(){
    program_must_exist cmake
}

install_ropper_macos(){
    pip install capstone
    pip install filebytes
    pip install keystone-engine
    pip install ropper
}

install_ropper_ubuntu(){
    sudo pip install capstone
    sudo pip install filebytes
    sudo pip install keystone-engine
    sudo pip install ropper
}
