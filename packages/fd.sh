install_fd(){
    install_package fd
}

install_fd_ubuntu(){
    clean wget https://github.com/sharkdp/fd/releases/download/v8.0.0/fd_8.0.0_amd64.deb -O /tmp/fd.deb
    sudo_run dpkg -i /tmp/fd.deb
}
