# Path to oh-my-zsh installation.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/Library/TeX/texbin:/opt/metasploit-framework/bin"
export ZSH=$HOME/.oh-my-zsh
export ANDROID_HOME=/usr/local/opt/android-sdk

ZSH_THEME="muse"
plugins=(git colored-man z)
source $ZSH/oh-my-zsh.sh


[ -f ~/.fzf.zsh ] && source ~/.fzf.zsh

if [[ -n $SSH_CONNECTION ]]; then
  export EDITOR='vim'
else
  export EDITOR='gvim'
fi

export COPYFILE_DISABLE=true
export EDITOR='vim'
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

alias c="clear"
alias flaix="mplayer http://flaixbacmob.streaming-pro.com:8006/ 2> /dev/null"

unamestr=`uname`
if [[ "$unamestr" == "Darwin" ]]; then
    alias rm="trash"
    alias service="brew services"
    alias mount="diskutil mount"
    alias umount="diskutil umountDisk"
else
    alias rm="rm -i"
fi

# Set docker hostname to distinguish between host and container
if [ -f /.dockerenv ]; then
    PROMPT='%{$fg_bold[green]%}%M: %{$reset_color%}%{$PROMPT_SUCCESS_COLOR%}%~%{$reset_color%}%{$GIT_PROMPT_INFO%}$(git_prompt_info)$(virtualenv_prompt_info)%{$GIT_DIRTY_COLOR%}$(git_prompt_status) %{$reset_color%}%{$PROMPT_PROMPT%}ᐅ%{$reset_color%} '
fi

# https://unix.stackexchange.com/questions/1045/getting-256-colors-to-work-in-tmux
alias tmux='tmux -2'

function mkctf(){
    mkdir exploiting
    mkdir crypto
    mkdir web
    mkdir reversing
    mkdir forensic
    mkdir misc
}

function rfc (){
    url="https://www.ietf.org/rfc"
    if [[ -z $1 ]]; then
        echo "RFC no specified"
    else
        b=$(curl -LsD h $url/rfc$1.txt)
        h=$(<h)
        echo $h | grep '200 OK' > /dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo $b | less
        else
            echo "RFC not found"
        fi
    fi
}

alias server='python -m SimpleHTTPServer'

function extract_shellcode(){
    if [[ -z $1 ]]; then
        echo "Usage extract_shellcode binary_file"
    else
        for i in $(objdump -d $1 -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
    fi
}

function docker-start(){
    eval $(docker-machine env default)
}

function docker-stop(){
    unset DOCKER_TLS
    unset DOCKER_HOST
    unset DOCKER_CERT_PATH
    unset DOCKER_MACHINE_NAME
}

#Create a new directory and enter it
function mk() {
    mkdir -p "$@" && cd "$@"
}
# Open man page as PDF
function manpdf() {
    man -t "${1}" | open -f -a /Applications/Preview.app/
}

function box(){
    ESC="\x1B["
    RESET=$ESC"39m"
    RED=$ESC"31m"
    GREEN=$ESC"32m"
    BLUE=$ESC"34m"

    if [[ -z ${1} ]]; then
        echo -e "${RED}Missing argument box name.${RESET}"
        echo -e "Usage: $0 name [-r][-v path]."
    else

        box_name=${1}
        case $box_name in
            [^a-zA-Z0-9]* ) echo "Name not ok : should start with [a-zA-Z0-9], got $box_name"
            echo -e "Usage: $0 name [-r][-v path]."
            return
            ;;
            *[^a-zA-Z0-9_.-]* ) echo "Name not ok : special character not allowed, only [a-zA-Z0-9_.-] got $box_name"
            echo -e "Usage: $0 name [-r][-v path]."
            return
            ;;
        esac

        # start docker env
        eval $(docker-machine env default)
        # Check if container is already running
        is_present=`docker ps -aqf "name=${box_name}"`
        if [[ ! -z $is_present ]]; then
            # If container exists, then start it
            echo -e "${BLUE}${box_name} is already present, starting it${RESET}"
            docker start ${box_name} &> /dev/null
        else

            RM=""
            SHARE_PATH=""
            OPTIND=2
            while getopts ":r :v:" opt; do
              case $opt in
                r)
                  RM="--rm"
                  ;;
                v)
                  SHARE_PATH=$(cd ${OPTARG} && pwd)
                  if [[ $? != 0 ]]; then
                    return
                  fi
                  ;;
                \?)
                  echo "Invalid option: -$OPTARG" >&2
                  ;;
              esac
            done

            echo -e "${BLUE}Creating docker: $box_name${RESET}"
            SHARE_CMD=""
            if [[ ! -z $SHARE_PATH ]]; then
                echo -e "${BLUE}Sharing path: $SHARE_PATH${RESET}"
                SHARE_CMD=$(echo -e "-v$SHARE_PATH:/root/files")
            fi
            if [[ ! -z $RM ]]; then
                echo -e "${RED}Docker will be removed after exiting${RESET}"
            fi

            # Create docker container and run in the background
            docker run --privileged -it \
                $RM\
                $SHARE_CMD\
                -d \
                -h ${box_name} \
                --name ${box_name} \
                e0d1n/pwnbox

            # Create a workdir for this box
            docker exec ${box_name} mkdir /root/files

            # Get a shell
            echo -e "${GREEN}                         ______               ${RESET}"
            echo -e "${GREEN}___________      ___________  /___________  __${RESET}"
            echo -e "${GREEN}___  __ \\_ | /| / /_  __ \\_  __ \\  __ \\_  |/_/${RESET}"
            echo -e "${GREEN}__  /_/ /_ |/ |/ /_  / / /  /_/ / /_/ /_>  <  ${RESET}"
            echo -e "${GREEN}_  .___/____/|__/ /_/ /_//_.___/\\____//_/|_|  ${RESET}"
            echo -e "${GREEN}/_/                           by e0d1n  ${RESET}"
            echo ""
        fi
        docker attach ${box_name}
    fi
}
