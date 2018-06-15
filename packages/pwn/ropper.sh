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
    sudo -H pip install capstone
    sudo -H pip install filebytes
    sudo -H pip install keystone-engine
    sudo -H pip install ropper
}
