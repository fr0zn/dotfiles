pre_rofi_ubuntu(){
    sudo add-apt-repository -y ppa:aguignard/ppa
    DB_SYNC=0
    install_package libxcb-xrm-dev bison flex pkg-config libxcb1-dev libxcb-keysyms1-dev libpango1.0-dev libxcb-util0-dev libxcb-icccm4-dev libyajl-dev libstartup-notification0-dev libxcb-randr0-dev libev-dev libxcb-cursor-dev libxcb-xinerama0-dev libxcb-xkb-dev libxkbcommon-dev libxkbcommon-x11-dev autoconf librsvg2-dev libxcb-ewmh-dev check
}

install_rofi_ubuntu(){
    pushd $DOTFILE_SRC
    local version="1.5.1"
    wget https://github.com/DaveDavenport/rofi/releases/download/${version}/rofi-${version}.tar.gz
    tar -xvf rofi-${version}.tar.gz
    pushd rofi-${version}
    # check
    wget https://github.com/libcheck/check/releases/download/0.12.0/check-0.12.0.tar.gz
    tar -xvf check-0.12.0.tar.gz
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

install_rofi_arch() {
    install_package rofi

}

symlink_rofi() {
    mkdir -p $HOME/.config/rofi/
    symlink_file "rofi/config.rasi" "$HOME/.config/rofi/config.rasi"

}

pass_rofi() {
    clone_src https://github.com/carnager/rofi-pass rofi-pass
    pushd $DOTFILE_SRC/rofi-pass
    sudo make install
    popd
    mkdir -p $HOME/.config/rofi-pass
    symlink_file "rofi/config/rofi-pass" "$HOME/.config/rofi-pass/config"
}

bw_rofi(){
    clone_src https://github.com/mattydebie/bitwarden-rofi.git bitwarden-rofi
    pushd $DOTFILE_SRC/bitwarden-rofi
    sudo install -D --mode=755 --group=root --owner=root bwmenu /usr/local/bin/bwmenu
    popd
}

buku_rofi() {
    clone_src https://github.com/carnager/buku_run buku_run
    pushd $DOTFILE_SRC/buku_run
    sudo make install
    popd
}

post_rofi() {
    bw_rofi
    #pass_rofi
    #buku_rofi
}
