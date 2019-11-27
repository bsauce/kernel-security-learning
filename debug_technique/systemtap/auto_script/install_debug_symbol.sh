#!/bin/bash

sudo cat > /etc/apt/sources.list.d/ddebs.list << EOF
deb http://ddebs.ubuntu.com/ precise main restricted universe multiverse
EOF

sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys ECDCAD72428D7C01
sudo apt-get update

if [ ! -f get-dbgsym ] 
then
    wget https://raw.githubusercontent.com/soarpenguin/systemtap-script/master/get-dbgsym
fi

chmod +x get-dbgsym
./get-dbgsym