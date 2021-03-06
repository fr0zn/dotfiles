backup_vim(){
    backup_file "$HOME/.vimrc"
}

symlink_vim(){
    symlink_file "vim/vimrc" "$HOME/.vimrc"
}

install_vim_ubuntu(){
    install_package software-properties-common
    sudo_run add-apt-repository -y ppa:jonathonf/vim
    sudo_run apt-get update
    sudo_run apt-get install -y vim
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


