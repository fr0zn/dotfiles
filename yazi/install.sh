install_yazi_macos(){
    install_package yazi ffmpeg sevenzip jq poppler fd ripgrep fzf zoxide imagemagick font-symbols-only-nerd-font
}

install_yazi_arch(){
    install_package yazi ffmpeg p7zip jq poppler fd ripgrep fzf zoxide imagemagick
}

symlink_yazi(){
    mkdir -p "$HOME/.config/yazi/"
    symlink_file "yazi/yazi.toml" "$HOME/.config/yazi/"
}
