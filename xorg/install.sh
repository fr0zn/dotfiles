install_xorg_arch(){
    sudo_run 'cp "xorg/50-vmmouse.conf"  /etc/X11/xorg.conf.d/50-vmmouse.conf'
}
