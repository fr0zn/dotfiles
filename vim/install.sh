backup_vim(){
    backup_file "$HOME/.vimrc"
}

symlink_vim(){
    symlink_file "vim/vimrc" "$HOME/.vimrc"
}

install_vim_ubuntu(){
    sudo add-apt-repository -y ppa:jonathonf/vim
    DB_SYNC=0
    install_package vim
}

install_vim(){
    install_package "vim"
}

post_vim(){
    # Install vim-plug
    curl -fsLo $HOME/.vim/autoload/plug.vim --create-dirs \
        https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim

    program_must_exist "vim"

    mkdir -p ~/.vim/backup 2> /dev/null
    mkdir -p ~/.vim/swap 2> /dev/null
    mkdir -p ~/.vim/undo 2> /dev/null

    vim +PlugInstall +qall
}


