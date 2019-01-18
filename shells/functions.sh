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

# Load the box function
. $SCRIPTS_PATH/box.sh

# GDB switch
gdbs() {
    $DOTFILE_PATH/gdb/gdbs.sh ${@}

}

bootstrap() {
    $DOTFILE_PATH/manual.sh
}