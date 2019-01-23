alias c="clear"

alias ll="ls -lh"
alias la="ls -lAh"
alias l="ls -lah"

alias grep='grep --color=auto'
alias egrep='egrep --color=auto'

# https://unix.stackexchange.com/questions/1045/getting-256-colors-to-work-in-tmux
#alias tmux='tmux -2'

alias gs='git status '
alias ga='git add '
alias gb='git branch '
alias gc='git commit'
alias gd='git diff'
# alias go='git checkout '
alias gk='gitk --all&'
alias gx='gitx --all'

alias server='python -m SimpleHTTPServer'

# BINDS
# Enable vim like
if [ -n "$ZSH_VERSION" ]; then

    function zle-keymap-select zle-line-init
    {
        # change cursor shape in iTerm2
        case $KEYMAP in
            vicmd)      print -n -- "\E]50;CursorShape=0\C-G";;  # block cursor
            viins|main) print -n -- "\E]50;CursorShape=2\C-G";;  # line cursor
        esac

        zle reset-prompt
        zle -R
    }

    function zle-line-finish
    {
        print -n -- "\E]50;CursorShape=0\C-G"  # block cursor
    }

    zle -N zle-line-init
    zle -N zle-line-finish
    zle -N zle-keymap-select
    bindkey -v

elif [ -n "$BASH_VERSION" ]; then
    set -o vi
fi
