#!/bin/bash

#Install additional packages needed for the PI
apt-get update
apt-get install autossh whois dnsutils -y
#wget https://github.com/spinnyhatkid/ReverseSSHClientFiles/archive/master.zip
#unzip master.zip
mkdir -p ~/.ssh
#mv -t ~/.ssh ReverseSSHClientFiles-master/*
#rm -r *master*
ssh-keygen -f ~/.ssh/id_rsa -t rsa -N ''
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 640 ~/.ssh/authorized_keys

#Extra tunnel aliases
echo "alias ec2SSH='ssh -fNR'" >> ~/.bashrc
echo "alias ec2AutoSSH='autossh -M 0 -fNR'" >> ~/.bashrc

#Configure ssh
sed -i -e 's/#AuthorizedKeysFile/AuthorizedKeysFile/g' /etc/ssh/sshd_config
sed -i -e 's/#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config
echo 'GatewayPorts yes' >> /etc/ssh/sshd_config

cp ~/.ssh/authorized_keys ~/.ssh/known_hosts

#Configure postgresql to allow password based connections
sed -i -e 's/connections only/connections only\nlocal\tall\t\tmsf3\t\t\t\t\tpassword/' /etc/postgresql/9.5/main/pg_hba.conf
sed -i -e 's/4 local connections:/4 local connections:\nhost\tall\t\tmsf3\t\t0.0.0.0\/0\t\tpassword/' /etc/postgresql/9.5/main/pg_hba.conf
update-rc.d postgresql enable

#Configure rc.local and systemctl for startup script to run on boot as a service
mv *.py /etc/
mv startup.sh /etc/init.d/
mv startup.service /etc/systemd/system/
sudo update-rc.d -f startup.sh defaults
systemctl daemon-reload
systemctl enable service.status
sed -i 's/^exit 0/whois $(dig +short myip.opendns.com @resolver1.opendns.com) > \/tmp\/netInfo.tmp\n\nexit 0/' /etc/rc.local
#sed -i 's/^exit 0/python2 \/etc\/startup.py\n\nexit 0/' /etc/rc.local
#cp /etc/rc2.d/S04rc.local /etc/rc1.d/

reboot now
