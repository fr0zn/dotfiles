pre_rofi_ubuntu(){
    sudo add-apt-repository -y ppa:aguignard/ppa
    DB_SYNC=0
    install_package libxcb-xrm-dev bison flex pkg-config libxcb1-dev libxcb-keysyms1-dev libpango1.0-dev libxcb-util0-dev libxcb-icccm4-dev libyajl-dev libstartup-notification0-dev libxcb-randr0-dev libev-dev libxcb-cursor-dev libxcb-xinerama0-dev libxcb-xkb-dev libxkbcommon-dev libxkbcommon-x11-dev autoconf librsvg2-dev
}

install_rofi_ubuntu(){
    pushd $DOTFILE_SRC
    local version="1.5.1"
    wget https://github.com/DaveDavenport/rofi/releases/download/${version}/rofi-${version}.tar.gz
    tar -xvf rofi-${version}.tar.gz
    pushd rofi-${version}
    # check
    wget https://github.com/libcheck/check/releases/download/0.12.0/check-0.12.0.tar.gz
    tar -xvf check-0.12.0
    pushd check-0.12.0
    ./configure
    make
    sudo make install
    popd
    # end check
    ./configure
    sudo make install
    popd
    popd
}

symlink_rofi_ubuntu() {
    mkdir -p $HOME/.config/rofi/
    symlink_file "rofi/config.rasi" "$HOME/.config/rofi/config.rasi"

}
