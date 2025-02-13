#Create a new directory and cd into
mk() {
    mkdir -p "$1" && cd "$1"
}

mkctf(){
    mkdir pwn
    mkdir crypto
    mkdir web
    mkdir re
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
#. $SCRIPTS_PATH/box.sh

. $SCRIPTS_PATH/theme_switch.sh

. $SCRIPTS_PATH/bb.sh

# GDB switch
gdbs() {
    $DOTFILE_PATH/gdb/gdbs.sh ${@}

}

bootstrap() {
    $DOTFILE_PATH/bootstrap.sh INTERACTIVE
}

# Inspect git log with fzf, ctrl + d to see diff
function y() {
	local tmp="$(mktemp -t "yazi-cwd.XXXXXX")" cwd
	yazi "$@" --cwd-file="$tmp"
	if cwd="$(command cat -- "$tmp")" && [ -n "$cwd" ] && [ "$cwd" != "$PWD" ]; then
		builtin cd -- "$cwd"
	fi
	rm -f -- "$tmp"
}
