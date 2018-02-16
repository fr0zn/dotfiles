program_must_exist "vim"

# Install vim-plug
curl -fsLo $HOME/.vim/autoload/plug.vim --create-dirs \
    https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim

mkdir -p ~/.vim/backup 2> /dev/null
mkdir -p ~/.vim/swap 2> /dev/null
mkdir -p ~/.vim/undo 2> /dev/null

# vim plugins
vim +PlugInstall +qall
