dbox(){
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

            echo -e "${BLUE}Creating container: $box_name${RESET}"
            SHARE_CMD=""
            if [[ ! -z $SHARE_PATH ]]; then
                echo -e "${BLUE}Sharing path: $SHARE_PATH${RESET}"
                SHARE_CMD=$(echo -e "-v$SHARE_PATH:/root/files")
            fi
            if [[ ! -z $RM ]]; then
                echo -e "${RED}This container will be removed after exiting${RESET}"
            fi

            # Create docker container and run in the background
            docker run --privileged -it \
                $RM\
                $SHARE_CMD\
                -d \
                -h ${box_name} \
                --name ${box_name} \
                fr0zn/pwnbox

            # Create a workdir for this box
            # Already created by the container
            # docker exec ${box_name} mkdir /root/files

            # Get a shell
            # echo -e "${GREEN}                         ______               ${RESET}"
            # echo -e "${GREEN}___________      ___________  /___________  __${RESET}"
            # echo -e "${GREEN}___  __ \\_ | /| / /_  __ \\_  __ \\  __ \\_  |/_/${RESET}"
            # echo -e "${GREEN}__  /_/ /_ |/ |/ /_  / / /  /_/ / /_/ /_>  <  ${RESET}"
            # echo -e "${GREEN}_  .___/____/|__/ /_/ /_//_.___/\\____//_/|_|  ${RESET}"
            # echo -e "${GREEN}/_/                           by fr0zn  ${RESET}"
            # echo ""
        fi
        docker attach ${box_name}
    fi
}
