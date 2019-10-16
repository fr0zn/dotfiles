function crtsh() {
    if [[ ! -z $1 ]]; then
        curl -s "https://crt.sh/?q=%25.$1" | grep $1 | grep TD | sed -e 's/<//g' | sed -e 's/>//g' | sed -e 's/TD//g' | sed -e 's/\///g' | sed -e 's/ //g' | sed -n '1!p' | sort -u
    fi
}

function certspotter() {
    if [[ ! -z $1 ]]; then
          curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1
    fi
}
