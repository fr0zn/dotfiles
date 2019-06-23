# fr0zn dotfiles

Contains a bootstrap system, custom made, that is able to install programs and its configuration in a fancy and easy way

# Bootstrap

The bootstrap process (`bootstrap.sh`) clones the repository named `$DOTFILE_REPO` under your `$DOTFILE_PATH` directory. It also detect which operating system are you running on and stores that identifier on `$OS_TYPE` (In order to add more supported distros, see [Adding distros](#adding-distros)). The global variables can be seen in `bootstrap.sh`.

The process is very simple, it reads all the `install.sh` files found under the `$DOTFILE_PATH` path (the `install.sh` file is described in [install.sh](#install-sh)). After that, it detects the current distro and asks the user if he wants to proceed with the installation. The installation reads the `bootstrap` file and executes the commands specified under the distro function `install_<distro>`. The commands that can be used inside the bootstrap system can be found in [Commands](#commands)).

The most used one is the `install` command, which will execute the `install.sh` steps for the specified package as argument (See [install.sh](#install-sh))

A custom command name `bootstrap` will be configured that will let you run commands (see [Commands](#commands)).

## Structure

There exist two types of program folders:

- Programs **with** configuration files. (Can be found inside the root directory of the dotfiles)
- Programs **without** configuration files. (Can be found inside the `packages` directory)

> The structure can be changed as you like with custom hierarchies.


### Install sh

This is valid for both, programs with and without configuration.

Inside packages there exist one file called `install.sh` . This file contains a template that can be understood by the bootstrap system (`bootstrap.sh`) and let you specify some steps to be run on that specific program. The default steps are defined in `bootstrap.sh` as `STEPS="pre backup symlink install post"`. Once the installation process begins, the installation for that binary, initialized with the `install` command, will follow the steps specified in the `STEPS` variable (This can be customized and manually specified for each program, see [Custom Steps](#custom-steps)).

An example of such file is shown below, note the steps name:

```
# vim/install.sh

pre_vim(){
  # Executed in all distros
}

backup_vim(){
  # Executed in all distros
}

symlink_vim(){
  # Executed in all distros
}

install_vim_ubuntu(){
  # Only executed in ubuntu
}

install_vim_macos(){
  # Only executed in macOS
}

install_vim(){
  # Executed in all distros, but NO ubuntu or macos
}

post_vim(){
  # Executed in all distros
}
```
> You don't need to have all the default steps functions. If the function is not used, it can be safely removed.

As seen, `install.sh` can perform different functions depending on the `step` and the `distro`. The function is named `<step>_<package>_<distro>`. You can create custom steps, see [Custom Steps](#custom-steps)).

#### Creating a package template (aka install.sh)

In order to create an `install` package you can run the `helper.sh` script. It will prompt you for the type of package (with/without configuration files) and the name of it. It will also ask if this package is going to be available for only one specific OS/distro or will be a common package.

This will create the `install.sh` with the package name and the appropriate distro details. This file will be stored under packages in case of `without configuration` or with a folder named the same as the package name if `with configuration` was specified.

# Commands

They can be executed anywhere during the bootstrap process. In order to execute manual command without the order specified in the `bootstrap` file run the `manual.sh` script. It contains a prompt inside the bootstrap process that will let you run the following commands:

- `add_app_login` (macOs only): Adds the application on login

```
# Firefox will get executed after login
add_app_login "Firefox"
```

- `backup_file`: Backups the file under `$DOTFILE_BACKUP` with a timestamp appended.

```
# Backups vimrc file
backup_file "$HOME/.vimrc"
```

- `backup_path`: Backups the full directory under `$DOTFILE_BACKUP` with a timestamp appended.

```
# Backups vim folder
backup_path "$HOME/.vim"
```

- `clean`: Redirects the command stdout to `/dev/null`. It can be combined with other commands.

```
clean 'apt-get update'
# Combination, with sudo_run
clean sudo_run make install
```

- `clone`: Clones the repo to the destination specified, updates if exist.

```
clone https://github.com/zsh-users/antigen.git $HOME/.antigen
```

- `clone_src`: Clones the repo into `$DOTFILE_SRC` with the specified name, updates if exist.

```
# Clones the repo i3 into $DOTFILE_SRC/i3-gaps
clone_src https://www.github.com/Airblader/i3 i3-gaps
```

- `install`: Executes the default steps from the `install.sh` of the package given as argument. If more arguments are given, the will be interpreted as custom steps and only those will get executed. If the function is not found, it will be skipped.

```
# Install vim default steps-> pre, backup, symlink, install, post.
install vim
# Install vim custom steps, only the ones specified `connect` and `backup`
install vim connect backup
```

- `install_package`: Executes the corresponding package manager (`apt-get`, `brew`, `pacman`) and installs the package/packages given as argument

```
install_package git ssh gdb gdb-multiarch
```

- `install_cask` (macOS only): Installs a cask package

```
# Installs Firefox as macOS app
install_cask firefox
```

- `install_aur` (arch only): Installs a package from the arch AUR, cloning the repo inside the `$DOTFILE_SRC` path.

```
# Installs tmate from the arch AUR
install_aur tmate
```

- `is_package_installed`: Returns 0 if the package if installed, 1 otherwise. It is able to use the correct package manager depending on the distro.

- `is_app_installed` (macOS only): Returns 0 if the app is present, 1 otherwise.

- `program_must_exist`: Makes sure a binary is found in the `$PATH` and is installed. If the program is not found, the bootstrap process will terminate.

```
# Makes sure git is installed
program_must_exist "git"
```

- `msg-info`: Prints a message with a blue `==>`. If `"in"` is specified as the second argument, the message will be printed with a `  ->` instead (Tabbed message).

```
msg-info "Installing vim from ..."
msg-ok "Step x was successfully" "in"

==> Installing vim from ...
  -> Step x was successfully
```

  Variations exist such as:

  - `msg-debug`: Only if `$DEBUG` is set to 1
  - `msg-ok`: Prints green arrows instead of blue ones
  - `msg-error`: Prints `==> ERROR:` in red before the message
 
- `symlink_file`: Creates a symlink relative to the current directory to a destination (Useful in package with config files). It will override the symlink if exists.

```
# Inside vim/install.sh in the symlink step
symlink_file "vim/vimrc" "$HOME/.vimrc"
```

- `sudo_run`: Executes a command as `root` or prompts for user sudoer permissions in a fancy way.

```
sudo_run make install
```

- `sync_database`: It can be called directly previously setting the variable `$DB_SYNC` to `0`. This function will get called automatically on the `install_package` command, and if the variable is set as `DB_SYNC=0` the package manager will perform a repo update (`apt-get update`, `brew update` ...)

# Custom steps

Add the wanted step inside the `install.sh` of the package name.

```
# fancy/install.sh
nicestep_fancy_ubuntu() {
  # This will be executed only on ubuntu
}
nicestep_fancy_macos() {
  # This will be executed only on macos
}
```

In order to use it, it can be manually executed though the `manual.sh` script or inside the `bootstrap` file as:

```
install fancy nicestep
```

## Adding distros

# Installation

```bash
bash <(curl -L http://dotfiles.fr0zn.pw)
```

## MacOS

![](https://i.imgur.com/lUtuob6.png)
