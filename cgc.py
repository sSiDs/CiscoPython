Python requirements:
To use this backup script you will need to have the following :

Python 3
Netmiko/Paramiko
TFTP Server (I use TFTPD)
The Python script:
import paramiko
import netmiko
import sys

def copyConfiguration(tftp_server, tftp_directory, device_name):
    print("  Copying Configuration... ", end="")
    sys.stdout.flush()
    command = f'copy running-config tftp://{tftp_server}/{tftp_directory}/{device_name}.conf'
    output = net_connect.send_command_timing(command)
    while( ']' in output or ')' in output or '!' in output ):
        if("nter vrf" in output):
            if("opied" in output or "omplete" in output or "uccessful" in output):
                break
            output = net_connect.send_command_timing('management')
            continue
        if("ource filename" in output):
            if("opied" in output or "omplete" in output or "uccessful" in output):
                break
            continue
        if("remote host" in output):
            if("opied" in output or "omplete" in output or "uccessful" in output):
                break
            output = net_connect.send_command_timing('\r\n')
            continue
        if("estination filename" in output):
            if("opied" in output or "omplete" in output or "uccessful" in output):
                break
            output = net_connect.send_command_timing('\r\n')
            continue
        if("opied" in output or "omplete" in output or "uccessful" in output):
            break
    print("COMPLETE")


#Arguments
device_name = sys.argv[1]
device_ip = sys.argv[2]
tftp_server = sys.argv[3]
tftp_directory = sys.argv[4]
device_username = sys.argv[5]
device_password = sys.argv[6]
enable_password = sys.argv[7]
device_protocol = sys.argv[8]

if(device_protocol == "ssh"):
    target = {
        'device_type': 'cisco_ios',
        'ip':   device_ip,
        'username': device_username,
        'password': device_password,
        'port' : 22,          # optional, defaults to 22
        'secret': enable_password,     # optional, defaults to ''
        'verbose': False,       # optional, defaults to False
    }
else:
    target = {
        'device_type': 'cisco_ios_telnet',
        'ip':   device_ip,
        'password': device_password,
        'port' : 23,          # optional, defaults to 22
        'secret': enable_password,     # optional, defaults to ''
        'verbose': False,       # optional, defaults to False
    }   

print("### Starting software backup of " + device_name + " (" + device_ip + ")")
net_connect = netmiko.ConnectHandler(**target)
net_connect.enable()
print("  Saving Configuration")
net_connect.save_config()

copyConfiguration(tftp_server, tftp_directory, device_name)
Breaking down the script:
To run the backup script you will need to use the following parameters:

device_name
device_ip
tftp_server
tftp_directory
device_username
device_password
enable_password
device_protocol
The script is then executed with the following command:

./backupConfig.py Switch_A 192.168.0.25 192.168.14.60 backups/switches bob password enable ssh
Or if you wish to use telnet use this:

./backupConfig.py Switch_A 192.168.0.25 192.168.14.60 backups/switches bob password enable telnet
Image of the completed script output
Whilst testing, I found that the initial copy command runs best with a send_command_timing function as this will allow for a longer delay between executing the command and retrieving the output.

while( ']' in output or ')' in output or '!' in output ):
	if("nter vrf" in output):
		if("opied" in output or "omplete" in output or "uccessful" in output):
			break
		output = net_connect.send_command_timing('management')
		continue
	if("ource filename" in output):
		if("opied" in output or "omplete" in output or "uccessful" in output):
			break
		continue
	if("remote host" in output):
		if("opied" in output or "omplete" in output or "uccessful" in output):
			break
		output = net_connect.send_command_timing('\r\n')
		continue
	if("estination filename" in output):
		if("opied" in output or "omplete" in output or "uccessful" in output):
			break
		output = net_connect.send_command_timing('\r\n')
		continue
	if("opied" in output or "omplete" in output or "uccessful" in output):
		break
print("COMPLETE")
To capture all the prompts from the copy run-configuration tftp command I use a loop which is checking the output for the required text. You may notice I skip the first character as this could be capitalised and it’s quicker to leave this character out than it to convert the string to lower case.

So this is how I backup the configuration from each device within my organisation. In future posts, I will document the script I use to compile a list of devices from a MySQL database, build a log from the backup process and copy the configuration files to a centralised area.

If anyone has ideas on how to improve the script, please comment below.
