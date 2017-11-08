# Path to dotfiles
e0d1n_DOTFILE_PATH=$HOME/.e0d1n-dotfiles
e0d1n_SCRIPTS_PATH=$e0d1n_DOTFILE_PATH/scripts
e0d1n_CONFIG_PATH=$e0d1n_DOTFILE_PATH/config

ZSH_THEME="afowler"
plugins=(git colored-man-pages z)

# Path to oh-my-zsh installation.
export ZSH=$HOME/.oh-my-zsh
source $ZSH/oh-my-zsh.sh

# FZF config file
[ -f ~/.fzf.zsh ] && source ~/.fzf.zsh

unamestr=`uname`

# Load ZSHRC config
source $e0d1n_CONFIG_PATH/all_zshrc.conf

# MacOS configs
if [[ "$unamestr" == "Darwin" ]]; then
    source $e0d1n_CONFIG_PATH/darwin_zshrc.conf
else
# Linux configs
    source $e0d1n_CONFIG_PATH/linux_zshrc.conf
    # Docker configs
    if [ -f /.dockerenv ]; then
        source $e0d1n_CONFIG_PATH/docker_zshrc.conf
    fi
fi

