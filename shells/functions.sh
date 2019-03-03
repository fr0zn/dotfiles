#Create a new directory and cd into
mk() {
    mkdir -p "$1" && cd "$1"
}

mkctf(){
    mkdir exploiting
    mkdir crypto
    mkdir web
    mkdir reversing
    mkdir forensic
    mkdir misc
}

rfc (){
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

extract_shellcode(){
    if [[ -z $1 ]]; then
        echo "Usage extract_shellcode binary_file"
    else
        for i in $(objdump -d $1 |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
    fi
}

# Load the box and dbox function
. $SCRIPTS_PATH/dbox.sh
. $SCRIPTS_PATH/vm/vm.sh
. $SCRIPTS_PATH/box.sh

. $SCRIPTS_PATH/theme_switch.sh

# GDB switch
gdbs() {
    $DOTFILE_PATH/gdb/gdbs.sh ${@}

}

bootstrap() {
    $DOTFILE_PATH/manual.sh
}

# Inspect git log with fzf, ctrl + d to see diff
gl() {
  git log --graph --color=always \
      --format="%C(auto)%h%d %s %C(black)%C(bold)%cr" "$@" |
  fzf --ansi --no-sort --reverse --tiebreak=index --bind=ctrl-s:toggle-sort \
      --bind "ctrl-d:execute:
                (grep -o '[a-f0-9]\{7\}' | head -1 |
                xargs -I % sh -c 'git show --color=always % | less -R') << 'FZF-EOF'
                {}
FZF-EOF"
}
