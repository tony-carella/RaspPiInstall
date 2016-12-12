#!/usr/bin/python2

import subprocess

#Static IP of Host
serverIP = '54.147.171.243'

#Run bash commands
def bash_call(cmd):
    return subprocess.call(['/bin/bash', '-c', cmd])

def bash_command(cmd):
    return subprocess.check_output(['/bin/bash', '-c', cmd])

interface = bash_command("ip -o link show | awk '{print $2,$9}' | grep UP").split(":")[0]

#Convert netmask to CIDR
def get_net_size(netmask):
    binary = ''
    for octet in netmask:
        binary += bin(int(octet))[2:].zfill(8)
    return str(len(binary.rstrip('0')))

#Obtain IP and Netmask of running device
while True:
    ip = bash_command("ifconfig %s | grep 'inet ' | awk '{ print $2 }'" % (interface)).rstrip('\n')
    #ip = bash_command("ifconfig %s | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'" % (interface)).rstrip('\n')
    if ip != "":
        break
netmask = bash_command("ifconfig %s | grep netmask | awk '{ print $4 }'" % (interface)).split('.')
#netmask = bash_command("ifconfig %s | grep Mask: | cut -d: -f4" % (interface)).split('.')

addr = '%s/%s' % (ip, get_net_size(netmask))

#Determine allowed SSH connections and establish connection to remote apache server
ports = map(str, range(29000,30000))
while True:
    str = bash_command("ssh %s 'netstat -l' | grep %s | wc -c" % (serverIP, ports[0]))
    if str.rstrip('\n') == "0":
        bash_call("autossh -M 0 -fNR %s:localhost:5432 %s" % (ports[0], serverIP))
        bash_call("autossh -M 0 -fNR %s:localhost:22 %s" % (int(ports[0]) + 1000, serverIP))
        break
    ports.pop(0)
    if len(ports) == 0:
        break

#Starting openvas
bash_call("redis-server /etc/redis/redis.conf")
bash_call("openvassd")
bash_call("openvasmd")
bash_call("gsad -p 9392")

#Run scan
bash_call("msfconsole -q -x 'db_connect msf3:msf3@localhost/msf3; db_nmap %s -A; exit -y'" % (addr))
