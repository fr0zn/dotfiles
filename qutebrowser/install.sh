pre_qutebrowser_ubuntu(){
    msg_debug "Pre-Install qutebrowser"
    install_package libglib2.0-0 libgl1 libfontconfig1 libx11-xcb1 libxi6 libxrender1 libdbus-1-3 tox
}

install_qutebrowser_arch(){
    install_package qutebrowser

}

install_qutebrowser_ubuntu(){
    msg_debug "Install qutebrowser"
    clone_src https://github.com/qutebrowser/qutebrowser.git qutebrowser
    pushd $DOTFILE_SRC/qutebrowser
    tox -e mkvenv-pypi
    #tox -e mkvenv-pypi-old

}

post_qutebrowser_ubuntu(){
    sudo_run echo "'#!/bin/bash'" '>' /usr/local/bin/qutebrowser
    sudo_run echo "'$DOTFILE_SRC/qutebrowser/.venv/bin/python3 -m qutebrowser \"\$@\"'" '>>' /usr/local/bin/qutebrowser
    sudo_run chmod +x /usr/local/bin/qutebrowser
}
