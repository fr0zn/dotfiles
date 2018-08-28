pre_qutebrowser_ubuntu(){
    msg_debug "Pre-Install qutebrowser"
    install_package libglib2.0-0 libgl1 libfontconfig1 libx11-xcb1 libxi6 libxrender1 libdbus-1-3
}

install_qutebrowser_ubuntu(){
    msg_debug "Install qutebrowser"
    clone_src https://github.com/qutebrowser/qutebrowser.git qutebrowser
    pushd $DOTFILE_SRC/qutebrowser
    # tox -e mkvenv-pypi
    tox -e mkvenv-pypi-old

}

post_qutebrowser_ubuntu(){
    echo '#!/bin/bash' > $DOTFILE_PATH/bin/qutebrowser
    echo "$DOTFILE_SRC/qutebrowser/.venv/bin/python3 -m qutebrowser \"\$@\"" >> $DOTFILE_PATH/bin/qutebrowser
    chmod +x $DOTFILE_PATH/bin/qutebrowser
}
