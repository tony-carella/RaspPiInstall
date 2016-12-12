#!/usr/bin/python2

import subprocess
import re
import time
from optparse import OptionParser

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

#Get scan type from user
ip_addr = "Undefined"
type = ''
usage = "usage: %prog [options] arg"
parser = OptionParser(usage)
parser.add_option("-t", "--type", action="store", type="string", dest="scantype", help="s: task status, o: OpenVas scan, os: Stop scan/Delete task, op: Pause Scan, or: Resume scan, m: metasploit nmap")
parser.add_option("-i", "--ip", action="store", type="string", dest="ip_addr", help="IPv4 addr for o and m scan")

(options, args) = parser.parse_args()
if options.scantype is not None:
    type = options.scantype
if options.ip_addr is not None and re.match("^(\d{1,3}.){3}\d{1,3}$", options.ip_addr):
    ip_addr = options.ip_addr

	
#Obtain IP and Netmask of running device
while True:
    ip = bash_command("ifconfig %s | grep 'inet ' | awk '{ print $2 }'" % (interface)).rstrip('\n')
    #ip = bash_command("ifconfig %s | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'" % (interface)).rstrip('\n')
    if ip != "":
        break
netmask = bash_command("ifconfig %s | grep netmask | awk '{ print $4 }'" % (interface)).split('.')
#netmask = bash_command("ifconfig %s | grep Mask: | cut -d: -f4" % (interface)).split('.')

addr = '%s/%s' % (ip, get_net_size(netmask))

regex = '\S{8}-(\S{4}-){3}\S{12}'                     #ID format
username = 'NKU'                                      #OMP Username
password = '0362187f-a222-4fc9-b7e7-d6311d0c71d5'     #OMP Password

#View status of tasks
if type == 's':
    status = bash_command("omp -u %s -w %s -G" % (username, password))
    if status != "":
        print status.split("  ")[1]

#OpenVas scan
if type == 'o' and ip_addr != "Undefined":
    scan_type = '74db13d6-7489-11df-91b9-002264764cea'    #Full and very deep ultimate
    format_id = 'a994b278-1f62-11e1-96ac-406186ea4fc5'    #XML
    xml_file = "/tmp/openvas_scan.xml"                    #Report File
	
    #Get or make task/target
    task_id = re.search(regex, bash_command("omp -u %s -w %s --xml='<get_tasks details=\"1\" />'" % (username, password)))
    if task_id is not None:
        target_id = re.search(regex, bash_command("omp -u %s -w %s -iX '<get_targets tasks=\"1\" />' | grep \"target id\" | tail -n 1" % (username, password))).group()
        task_id = task_id.group()
    else:
        target_id = re.search(regex, bash_command("omp -u %s -w %s --xml='<create_target><name>Network Scan</name><hosts>%s</hosts></create_target>'" % (username, password, ip_addr))).group()
        task_id = re.search(regex, bash_command("omp -u %s -w %s --xml='<create_task><name>Scan Task</name><comment>Deep and Quick scan</comment><config id=\"%s\" /><target id=\"%s\" /></create_task>'" % (username, password, scan_type, target_id))).group()

    #Run scan
    bash_call("omp -u %s -w %s --xml='<start_task task_id=\"%s\" />'" % (username, password, task_id))
    is_done = re.search('Done', bash_command("omp -u %s -w %s --xml='<get_tasks task_id=\"%s\" details=\"1\" />'" % (username, password, task_id)))

    while is_done is None:
        is_done = re.search('Done', bash_command("omp -u %s -w %s --xml='<get_tasks task_id=\"%s\" details=\"1\" />'" % (username, password, task_id)))
        time.sleep(5)

    #Get report and cleanup
    report_id = re.search(regex, bash_command("omp -u %s -w %s -iX '<get_tasks task_id=\"%s\" />' | grep \"report id\"" % (username, password, task_id))).group()
    bash_call("omp -u %s -w %s --xml='<get_reports report_id=\"%s\" format=\"XML\" />' > %s" % (username, password, report_id, xml_file))

    bash_call("omp -u %s -w %s --xml='<delete_task task_id=\"%s\" />'" % (username, password, task_id))
    bash_call("omp -u %s -w %s --xml='<delete_target target_id=\"%s\" />'" % (username, password, target_id))
    bash_call("omp -u %s -w %s --xml='<delete_report report_id=\"%s\" />'" % (username, password, report_id))

    bash_call("msfconsole -q -x 'db_connect msf3:msf3@localhost/msf3; db_import %s; exit -y'" % (xml_file))
	
#OpenVas Stop Scan And Delete Task
if type == 'os':
    task_id = re.search(regex, bash_command("omp -u %s -w %s --xml='<get_tasks details=\"1\" />'" % (username, password)))
    if task_id is not None:
        target_id = re.search(regex, bash_command("omp -u %s -w %s -iX '<get_targets tasks=\"1\" />' | grep \"target id\" | tail -n 1" % (username, password))).group()
        
        task_id = task_id.group()
        bash_call("omp -u %s -w %s --xml='<delete_task task_id=\"%s\" />'" % (username, password, task_id))
        bash_call("omp -u %s -w %s --xml='<delete_target target_id=\"%s\" />'" % (username, password, target_id))
	
#OpenVas Stop (Pause) Scan
if type == 'op':
    task_id = re.search(regex, bash_command("omp -u %s -w %s --xml='<get_tasks details=\"1\" />'" % (username, password)))
    if task_id is not None:
        task_id = task_id.group()
        bash_call("omp -u %s -w %s --xml='<stop_task task_id=\"%s\" />'" % (username, password, task_id))

#OpenVas Resume Scan
if type == 'or':
    task_id = re.search(regex, bash_command("omp -u %s -w %s --xml='<get_tasks details=\"1\" />'" % (username, password)))
    if task_id is not None:
        task_id = task_id.group()
        bash_call("omp -u %s -w %s --xml='<resume_task task_id=\"%s\" />'" % (username, password, task_id))
		
#Metasploit nmap
if type == 'm':
    bash_call("msfconsole -q -x 'db_connect msf3:msf3@localhost/msf3; db_nmap %s -A; exit -y'" % (addr))
