install_docker_arch(){
    msg_debug "Install docker"
    install_package docker
    sudo systemctl enable docker
}

install_docker_ubuntu(){
    msg_debug "Install docker"
    install_package install apt-transport-https ca-certificates curl gnupg2 software-properties-common curl
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    DB_SYNC=0
    install_package docker-ce
}
