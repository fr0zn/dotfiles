install_node_ubuntu(){
    curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
    sudo apt-get install -y nodejs
}

install_node_macos(){
    msg_debug "Install node"
    install_package node
}
