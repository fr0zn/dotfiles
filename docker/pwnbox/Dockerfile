FROM ubuntu:16.04
MAINTAINER fr0zn

ENV DEBIAN_FRONTEND noninteractive

RUN dpkg --add-architecture i386
RUN apt-get update && apt-get -y upgrade

RUN apt-get install locales

# Set the locale
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

#-------------------------------------#
# Install packages from Ubuntu repos  #
#-------------------------------------#
RUN apt-get install -y sudo git lsb-release

#-------------------------------------#
# Install using dotfiles bootstrap    #
#-------------------------------------#

RUN git clone https://github.com/fr0zn/dotfiles ~/.dotfiles
RUN ~/.dotfiles/bootstrap.sh ~/.dotfiles/bootstrap/pwnbox.sh

RUN apt-get -y autoremove
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENTRYPOINT ["/bin/bash"]
