install_fzf(){
    SHELL=/bin/zsh
    clone_src https://github.com/junegunn/fzf.git fzf
    pushd $DOTFILE_SRC/fzf
    ./install --all > /dev/null 2>&1
}

post_fzf(){
    install_package fd
}
