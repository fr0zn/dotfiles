$DOTFILE_REPO=https://github.com/e0d1n/dotfiles.git
$DOTFILE_DESTINATION=$HOME/e0d1n-dotfiles

msg() {
    printf '%b\n' "$1" >&2
}

action() {
    if [[ "$ret" -eq '0' ]]; then
        msg "\33[32m[✔]\33[0m ${1}"
    else
        msg "\33[31m[✘]\33[0m ${1}: ${2}"
    fi
}

lnif() {
    if [ -e "$1" ]; then
        ln -sf "$1" "$2"
    fi
    ret="$?"
}

program_exists() {

    local ret='0'
    command -v $1 >/dev/null 2>&1 || { local ret='1'; }

    # fail on non-zero return value
    if [ "$ret" -ne 0 ]; then
        return 1
    fi

    return 0
}

program_must_exist() {

    program_exists $1
    ret="$?"

    # throw error on non-zero return value
    if [ "$ret" -ne 0 ]; then
        action "Not Found" "You must have '$1' installed to continue."
    fi
}

function symlink(){
    lnif $DOTFILE_DESTINATION $1
}

function clone(){
    FROM=$1
    WHERE=$2

    ERROR=$(git clone $FROM $WHERE 2>&1 >/dev/null)
    ret=$?
    action "$WHERE" "$ERROR"

}

backup() {
    msg "Attempting to back up your original configuration."
    today=`date +%Y%m%d_%s`
    for i in "$@"; do
        [ -e "$i" ] && [ ! -L "$i" ] && mv -v "$i" "$i.$today";
    done
    ret="$?"
    action "Your original configuration has been backed up."
}

program_must_exist "vim"
program_must_exist "tmux"
program_must_exist "python"
program_must_exist "zsh"
program_must_exist "curl"

# backup old configurations
backup "$HOME/.vimrc" \
       "$HOME/.vim"
       "$HOME/.tmux.conf" \
       "$HOME/.zshrc" \


clone $DOTFILE_REPO $DOTFILE_DESTINATION
clone https://github.com/jimeh/tmux-themepack.git $HOME/.tmux-themepack

# Set zsh default
chsh -s /bin/zsh

# Install Oh my zsh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

# Install vim-plug
curl -fLo $HOME/.vim/autoload/plug.vim --create-dirs \
    https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim

symlink "$HOME/.vimrc"
symlink "$HOME/.tmux.conf"
symlink "$HOME/.zshrc"
