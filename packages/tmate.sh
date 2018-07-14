install_tmate_macos(){
    install_package tmate
}

install_tmate_arch(){
    install_aur tmate
}

install_tmate_ubuntu(){
    install_package software-properties-common
    sudo add-apt-repository -y ppa:tmate.io/archive
    DB_SYNC=0
    install_package tmate
}
