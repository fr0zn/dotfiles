symlink_buku(){
    mkdir -p $HOME/.local/share/
    symlink_path "buku/db" "$HOME/.local/share/buku"
}

install_buku(){
    install_package buku
}
