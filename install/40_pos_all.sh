touch $HOME/.z

mkdir -p ~/.vim/backup 2> /dev/null
mkdir -p ~/.vim/swap 2> /dev/null
mkdir -p ~/.vim/undo 2> /dev/null

# vim plugins
vim +PlugInstall +qall

# Set zsh default and run-it
msg_info "Changing the default shell to /bin/zsh (Enter password): "
chsh -s /bin/zsh
