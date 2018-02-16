# Available functions:

# --- install ---

# Runs the script 'install.sh' contained in the <program_name> folder
# ex: `install vim`

# --- install_package ---

# Calls function install_package, that will try to install the given
# package with root permissions.
# ex: `install_package curl`

# --- backup ---

# Creates a copy of the file/s given in as argument
# ex: `backup "$HOME/.vimrc"`

# --- clone ---

# Clones the specified repo as argument 1 to the folder in argument 2,if
# the folder containing the repo already exists, then it will pull instead.
# ex: `clone $REPO "$HOME/destination"`

# --- symlink ---

# It will softlink the file from argument 1 to the path specified at
# argument 2, if the file already exists it will override it
# ex: `symlink "vim/vimrc" "$HOME/.vimrc"`

# --- program_must_exist ---

# Tries to install the last version of the program as argument. It will make
# sure it was installed, exiting if not.
# ex: `program_must_exist "vim"`

# --- program_exists ---

# Returns 0 if program exists, 1 if not.
# ex: ```program_exists "brew"
#     if [[ $? -ne 0 ]]; then
#         # Do whatever
#     fi
#     ```
