install_pyenv_macos(){
    install_package pyenv
}

install_pyenv_ubuntu(){
    curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash
}

post_pyenv(){
    msg_debug "Post pyenv"
    #pyenv install 2.7.15
    #pyenv install 3.6.5
}
