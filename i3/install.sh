install_i3_arch(){
    install_package i3-gaps xorg-xinit xorg-server libglvnd i3blocks ttf-hack feh compton
}

install_i3_ubuntu(){
    install_package i3 i3blocks xinit feh x11-xserver-utils compton
}

gaps_i3_ubuntu(){
    install_package libxcb1-dev libxcb-keysyms1-dev libpango1.0-dev \
    libxcb-util0-dev libxcb-icccm4-dev libyajl-dev \
    libstartup-notification0-dev libxcb-randr0-dev \
    libev-dev libxcb-cursor-dev libxcb-xinerama0-dev \
    libxcb-xkb-dev libxkbcommon-dev libxkbcommon-x11-dev \
    autoconf libxcb-xrm-dev i3blocks xinit feh x11-xserver-utils

    clone_src https://www.github.com/Airblader/i3 i3-gaps
    pushd $DOTFILE_SRC/i3-gaps
    autoreconf --force --install
    rm -rf build/
    mkdir -p build && cd build/
    ../configure --prefix=/usr --sysconfdir=/etc --disable-sanitizers
    make
    sudo make install
    popd
}

lock_i3_ubuntu(){

    install_package imagemagick libxcb-composite0-dev libjpeg-turbo8-dev libpam0g-dev xautolock

    clone_src https://github.com/meskarune/i3lock-fancy i3lock-fancy
    pushd $DOTFILE_SRC/i3lock-fancy
    sudo make install
    popd

    clone_src https://github.com/PandorasFox/i3lock-color.git i3lock-color
    pushd $DOTFILE_SRC/i3lock-color
    autoreconf -i
    ./configure
    make
    sudo make install
    popd
}

symlink_i3(){
    mkdir -p $HOME/.config/i3
    mkdir -p $HOME/.config/dunst
    symlink_file "i3/config" "$HOME/.config/i3"
    symlink_file "i3/i3blocks.conf" "$HOME/.i3blocks.conf"
    symlink_file "i3/dunstrc" "$HOME/.config/dunst"
}

symlink-min_i3(){
    mkdir -p $HOME/.config/i3
    mkdir -p $HOME/.config/dunst
    symlink_file "i3/config-min" "$HOME/.config/i3/config"
    symlink_file "i3/i3blocks.conf-min" "$HOME/.i3blocks.conf"
    symlink_file "i3/dunstrc" "$HOME/.config/dunst"
}
