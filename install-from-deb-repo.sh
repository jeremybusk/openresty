
#!/bin/bash
# https://openresty.org/en/linux-packages.html

# import our GPG key:
wget -qO - https://openresty.org/package/pubkey.gpg | sudo apt-key add -

# for installing the add-apt-repository command
# (you can remove this package and its dependencies later):
sudo apt-get -y install software-properties-common

# add the our official APT repository:
sudo add-apt-repository -y "deb http://openresty.org/package/ubuntu $(lsb_release -sc) main"

sudo apt-get update

sudo apt-get install openresty

opm -h 
