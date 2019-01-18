install_pyenv_macos(){
    install_package pyenv
}

install_pyenv_ubuntu(){
    install_package make build-essential libssl-dev zlib1g-dev libbz2-dev \
libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
xz-utils tk-dev libffi-dev liblzma-dev python-openssl
    curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash
}

post_pyenv(){
    msg_debug "Post pyenv"
    #pyenv install 2.7.15
    #pyenv install 3.6.5
}
