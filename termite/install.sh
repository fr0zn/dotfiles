symlink_termite_ubuntu(){
    msg_debug "Symlink termite"
    mkdir -p $HOME/.config/termite
    symlink_file "termite/config" "$HOME/.config/termite"
}

install_termite_ubuntu(){
    msg_debug "Install termite"
    install_package g++ libgtk-3-dev gtk-doc-tools gnutls-bin valac intltool libpcre2-dev libglib3.0-cil-dev libgnutls28-dev libgirepository1.0-dev libxml2-utils gperf
    pushd $DOTFILE_SRC
    git clone --recursive https://github.com/thestinger/termite.git
    git clone https://github.com/thestinger/vte-ng.git
    echo export LIBRARY_PATH="/usr/include/gtk-3.0:$LIBRARY_PATH"
    pushd vte-ng && ./autogen.sh && make && sudo make install
    popd
    pushd termite && make && sudo make install
    sudo ldconfig
    sudo mkdir -p /lib/terminfo/x; sudo ln -s \
    /usr/local/share/terminfo/x/xterm-termite \
    /lib/terminfo/x/xterm-termite
    popd
    sudo update-alternatives --install /usr/bin/x-terminal-emulator x-terminal-emulator /usr/local/bin/termite 6
    popd
}
