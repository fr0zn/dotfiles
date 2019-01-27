pre_piputils(){
    install_package cmake
}

pre_piputils_ubuntu(){
    install_package cmake pkg-config
}

pip2_piputils_ubuntu(){
    pre_piputils_ubuntu
    sudo pip install unicorn
    sudo pip install capstone
    sudo pip install keystone-engine
    sudo pip install ropper
}

pip3_piputils_ubuntu(){
    pre_piputils_ubuntu
    sudo pip3 install unicorn
    sudo pip3 install capstone
    sudo pip3 install keystone-engine
    sudo pip3 install ropper
}
