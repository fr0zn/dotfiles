symlink_python(){
    symlink_file "python/pythonrc" "$HOME/.pythonrc"
}

install_python_ubuntu(){
    install_package python
    install_package python-pip

    install_package python3
    install_package python3-pip
}
