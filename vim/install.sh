backup_vim(){
    backup_file "$HOME/.vimrc"
}

symlink_vim(){
    symlink_file "vim/vimrc" "$HOME/.vimrc"
}

install_vim(){
    program_must_exist "vim"
    # Install vim-plug
    curl -fsLo $HOME/.vim/autoload/plug.vim --create-dirs \
        https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
}

post_vim(){
    mkdir -p ~/.vim/backup 2> /dev/null
    mkdir -p ~/.vim/swap 2> /dev/null
    mkdir -p ~/.vim/undo 2> /dev/null

    vim +PlugInstall +qall
}


