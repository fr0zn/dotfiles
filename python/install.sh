symlink_python(){
    symlink_file "python/pythonrc" "$HOME/.pythonrc"
}

pyenv_python(){
    install pyenv
}

install_python_arch(){
    install_package python
    install_package python-pip

    install_package python2
    install_package python2-pip
}

install_python_ubuntu(){
    install_package python
    install_package python-pip

    install_package python3
    install_package python3-pip
}

dev_python_ubuntu(){
    install_package python-dev
    install_package python3-dev
}
