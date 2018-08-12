uname_out=`uname`

if [[ "$uname_out" == "Darwin" ]]; then
    $HOME/.dotfiles/scripts/macos/open_term.sh $HOME/.dotfiles/scripts/macos/open_path_linux.sh ${@}
fi
