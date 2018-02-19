install_skhd_macos(){
    install_package koekeishiya/formulae/skhd
}

post_skhd_macos(){
    brew services restart skhd
}
