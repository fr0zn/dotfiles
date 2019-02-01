symlink_buku(){
    mkdir -p $HOME/.local/share/
    symlink_path "buku/db" "$HOME/.local/share/buku"
}

install_buku_ubuntu(){
    install_package buku
}

install_buku_arch(){
    install_aur buku
}
