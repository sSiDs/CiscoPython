#!/usr/bin/env python
#
# required python libraries: pexpect, requests, tftpy, scp
#
# TODO:
# - ssh public key authentication for cisco devices
# - option to specify custom port
#


import os
import sys
import pexpect
import filecmp
import shutil
import time
import ftplib
import requests
import tftpy
import paramiko
import shlex
import subprocess

from optparse import OptionParser
from scp import SCPClient
from requests.auth import HTTPBasicAuth
from requests.auth import HTTPDigestAuth

# suppress warning from urrlib: "InsecureRequestWarning: Unverified HTTPS request is being made."
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def gen_backup_path (hostname, backup_dir, custom_folder=""):

    if custom_folder:
        backup_path = backup_dir + custom_folder + "/"
    else:
        backup_path = backup_dir + hostname + "/"

    # generate initial backup filename: backup_path/HOSTNAME/0001.cfg
    configname = 1
    configbackup = "{0:0>4d}".format(configname);
    newfile = backup_path + configbackup + ".cfg"

    # if backup file exists count +1 to generate new backup filename
    while os.path.isfile(newfile):
        configname += 1
        configbackup = "{0:0>4d}".format(configname);
        newfile = backup_path + configbackup + ".cfg"

    # backup filename -1 is the last backup
    configname -= 1
    lastconfigbackup = "{0:0>4d}".format(configname);
    lastfile = backup_path + lastconfigbackup + ".cfg"

    return[newfile, lastfile, backup_path]


def http_command (hostname, user, password, newfile, filename):

    host_backup_dir = os.path.dirname(newfile)

    if not os.path.exists(host_backup_dir):
        os.makedirs(host_backup_dir)

    url = "http://" + hostname + "/" + filename
    r = requests.get(url)
    s_auth = r.headers.get('www-authenticate')
    if s_auth and 'basic' in s_auth.lower():
        r = requests.get(url, auth=HTTPBasicAuth(user, password))
    elif s_auth and 'digest' in s_auth.lower():
        r = requests.get(url, auth=HTTPDigestAuth(user, password))

    if r.status_code == 200:
        with open(newfile, "wb") as http_output:
            http_output.write(r.content)
    else:
        print "HTTP Error: " + str(r.status_code)
        sys.exit(1)


def https_command (hostname, user, password, newfile, filename):

    host_backup_dir = os.path.dirname(newfile)

    if not os.path.exists(host_backup_dir):
        os.makedirs(host_backup_dir)

    url = "https://" + hostname + "/" + filename
    r = requests.get(url, verify=False)
    s_auth = r.headers.get('www-authenticate')

    if s_auth and 'basic' in s_auth.lower():
        r = requests.get(url, auth=HTTPBasicAuth(user, password), verify=False)
    elif s_auth and 'digest' in s_auth.lower():
        r = requests.get(url, auth=HTTPDigestAuth(user, password), verify=False)

    if r.status_code == 200:
        with open(newfile, "wb") as http_output:
            http_output.write(r.content)
    else:
        print "HTTP Error: " + str(r.status_code)
        sys.exit(1)


def ftp_command (hostname, user, password, newfile, filename):

    host_backup_dir = os.path.dirname(newfile)

    if not os.path.exists(host_backup_dir):
        os.makedirs(host_backup_dir)

    ftp = ftplib.FTP(hostname)
    ftp.set_pasv(False)
    ftp.login(user, password)

    with open(newfile, "wb") as f:
        ftp.retrbinary('RETR %s' % filename, f.write)


def tftp_command (hostname, newfile, lastfile):

    host_backup_dir = os.path.dirname(newfile)

    if not os.path.exists(host_backup_dir):
        os.makedirs(host_backup_dir)

    client = tftpy.TftpClient(hostname, 69)
    client.download("startup-config", newfile)


def scp_command (hostname, user, password, newfile, filename):

    dir = os.path.dirname(newfile)

    if not os.path.exists(dir):
        os.makedirs(dir)

    sftpcall = subprocess.Popen(shlex.split("sshpass -p "+ password + " scp -q -o PreferredAuthentications=password " + user + "@" + hostname + ":" + filename + " " + newfile))
    out, err = sftpcall.communicate()

    if sftpcall.returncode != 0:
        print "scp Error " + str(sftpcall.returncode)
        sys.exit(2)


def ssh_command (hostname, user, password, enable, platform):

    # https://pexpect.readthedocs.org/en/latest/overview.html#find-the-end-of-line-cr-lf-conventions

    string_to_remove1 = ""
    string_to_remove2 = ""
    string_to_remove3 = ""
    string_to_remove4 = ""

    ssh_newkey = "Are you sure you want to continue connecting"
    child = pexpect.spawn("ssh -o PreferredAuthentications=password -l %s %s"%(user, hostname))
    i = child.expect([pexpect.TIMEOUT, ssh_newkey, "assword: "])
    if i == 0:
        print "SSH connection timeout"
        sys.exit(3)
    elif i == 1:
        child.sendline ("yes")
        child.expect ("assword: ")
        child.sendline(password)
    else:
        child.sendline(password)

    if platform == "asa":
        if enable:
            child.expect(">")
            child.sendline("enable")
            child.expect("Password")
            child.sendline(enable)
        child.expect("#")
        child.sendline("term pager 0")
        child.expect("#")
        child.sendline("more system:running-config")
        child.expect(": end")
        shrun = child.before
        child.sendline("exit")
        out = shrun.split("\r\n")
        for i in out:
            if "Written by" in i:
                string_to_remove1 = i + "\r\n"
                break
        # remove unwanted strings and convert tty/windows line endings to unix line endigs
        return shrun.replace(" more system:running-config\r\n", "") \
                    .replace(string_to_remove1, "") \
                    .replace("\r\n", "\n") + ": end"
    if platform == "pix":
        if enable:
            child.expect(">")
            child.sendline("enable")
            child.expect("Password")
            child.sendline(enable)
        child.expect("#")
        child.sendline("sh startup-config")
        child.expect("Cryptochecksum:")
        shrun = child.before
        child.sendline("exit")
        return shrun.replace("\r\n", "\n")
    if platform == "ios":
        if enable:
            child.expect(">")
            child.sendline("enable")
            child.expect("Password")
            child.sendline(enable)
        child.expect("#")
        child.sendline("term length 0")
        child.expect("#")
        child.sendline("show startup-config")
        child.expect("end\r\n")
        shrun = child.before
        child.sendline("exit")
        out = shrun.split("\r\n")
        for i in out:
            if "Load for " in i:
                string_to_remove1 = i + "\r\n"
                break
        for i in out:
            if "Time source is NTP" in i:
                string_to_remove2 = i + "\r\n"
                break
        for i in out:
            if "uncompressed" in i:
                string_to_remove3 = i + "\r\n"
                break
        for i in out:
            if "Uncompressed" in i:
                string_to_remove4 = i + "\r\n"
                break
        return shrun.replace(string_to_remove1, "") \
                    .replace(string_to_remove2, "") \
                    .replace(string_to_remove3, "") \
                    .replace(string_to_remove4, "") \
                    .replace("show startup-config\r\n", "") \
                    .replace("\r\n", "\n") + "end"
    if platform == "nxos":
        if enable:
            child.expect(">")
            child.sendline("enable")
            child.expect("Password")
            child.sendline(enable)
        child.expect("#")
        child.sendline("term length 0")
        child.expect("#")
        child.sendline("show startup-config")
        child.expect_exact("# ", timeout=120)
        shrun = child.before
        child.sendline("exit")
        out = shrun.split("\r\n")
        for i in out:
            if "!Time:" in i:
                string_to_remove1 = i + "\r\n"
                break
        return shrun.replace(string_to_remove1, "").replace("\r\n", "\n")
    if platform == "iosxr":
        if enable:
            child.expect(">")
            child.sendline("enable")
            child.expect("Password")
            child.sendline(enable)
        child.expect("#")
        child.sendline("term length 0")
        child.expect("#")
        child.sendline("show running-config")
        child.expect_exact("end", timeout=120)
        shrun = child.before
        child.sendline("exit")
        out = shrun.split("\r\n")
        del out[1] # remove current time from output
        return "\n".join(out) # convert output back to a string


def telnet_command (hostname, user, password, enable, platform):

    string_to_remove1 = ""
    string_to_remove2 = ""
    string_to_remove3 = ""
    string_to_remove4 = ""

    child = pexpect.spawn("telnet %s "%(hostname))
    if user:
        child.expect("Username: ")
        child.sendline(user)
    i = child.expect([pexpect.TIMEOUT, "Password: "])
    if i == 0:
        print "Telnet connection timeout"
        sys.exit(3)
    else:
        child.sendline(password)

    if platform == "ios":
        if enable:
            child.expect(">")
            child.sendline("enable")
            child.expect("Password")
            child.sendline(enable)
        child.expect("#")
        child.sendline("term length 0")
        child.expect("#")
        child.sendline("show startup-config")
        child.expect("end\r\n")
        shrun = child.before
        child.sendline("exit")
        out = shrun.split("\r\n")
        for i in out:
            if "Load for " in i:
                string_to_remove1 = i + "\r\n"
                break
        for i in out:
            if "Time source is NTP" in i:
                string_to_remove2 = i + "\r\n"
                break
        for i in out:
            if "uncompressed" in i:
                string_to_remove3 = i + "\r\n"
                break
        for i in out:
            if "Uncompressed" in i:
                string_to_remove4 = i + "\r\n"
                break
        return shrun.replace(string_to_remove1, "") \
                    .replace(string_to_remove2, "") \
                    .replace(string_to_remove3, "") \
                    .replace(string_to_remove4, "") \
                    .replace("show startup-config\r\n", "") \
                    .replace("\r\n", "\n") + "end"
    if platform == "pix":
        if enable:
            child.expect(">")
            child.sendline("enable")
            child.expect("Password")
            child.sendline(enable)
        child.expect("#")
        child.sendline("sh startup-config")
        child.expect("Cryptochecksum:")
        shrun = child.before
        child.sendline("exit")
        return shrun.replace("\r\n", "\n")


def ironport_command (hostname, user, password, newfile):

    ssh_newkey = "Are you sure you want to continue connecting"
    child = pexpect.spawn("ssh -o PreferredAuthentications=password -l %s %s"%(user, hostname))
    i = child.expect([pexpect.TIMEOUT, ssh_newkey, "assword:"])
    if i == 0:
        print "SSH connection timeout"
        sys.exit(3)
    elif i == 1:
        child.sendline ("yes")
        child.expect ("assword:")
        child.sendline(password)
    else:
        child.sendline(password)

    child.expect(">")
    child.sendline("saveconfig no") # passwords saved in cleartext
    child.expect(">")
    ironport_backup_filename = child.before.split(" ")[4]
    child.sendline("exit")

    host_backup_dir = os.path.dirname(newfile)

    if not os.path.exists(host_backup_dir):
        os.makedirs(host_backup_dir)

    ssh = paramiko.SSHClient()
    ssh.load_host_keys(os.path.expanduser(os.path.join("~", ".ssh", "known_hosts")))
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=user, password=password)
    scpclient = SCPClient(ssh.get_transport(), socket_timeout=15.0)
    scpclient.get("./configuration/" + ironport_backup_filename, newfile)
    ssh.close()

    strings = ("Current Time", "Time Remaining")
    with open(newfile, "r") as f:
        lines = f.readlines()

    with open(newfile, "w") as f:
        for line in lines:
            if not any(s in line for s in strings):
                f.write(line)


def backupconfig (device_config, newfile):

    host_backup_dir = os.path.dirname(newfile)
    if not os.path.exists(host_backup_dir):
        os.makedirs(host_backup_dir)

    with open(newfile, "w") as f:
        f.write(device_config)


def remove_changed (newfile, lastfile, backup_path):

    latest_backup_name = "latest.cfg"

   # if old backup exists compare it with the new file
    if os.path.isfile(lastfile):
        if filecmp.cmp(newfile, lastfile):
            # if the config backup has not changed it is not needed
            os.remove(newfile)
            shutil.copyfile(lastfile, backup_path + latest_backup_name)
            return lastfile
        else:
            # else leave newfile and copy latest backup
            shutil.copyfile(newfile, backup_path + latest_backup_name)
            return newfile
    else:
        # initial backup
        shutil.copyfile(newfile, backup_path + latest_backup_name)
        return newfile


def main ():

    help_message = "\n tool for automated config backup\n" \
                   "\n 'configbackup.py --help' for more information\n"
    usage = "\n %prog --ftp -s <host> -u [username] -p [password] -f <file> -d <backup_dir> -c [custom_folder]" \
            "\n %prog --tftp -s <host> -d <backup_dir> -c [custom_folder]" \
            "\n %prog --http -s <host> -u [username] -p [password] -f <file> -d <backup_dir> -c [custom_folder]" \
            "\n %prog --https -s <host> -u [username] -p [password] -f <file> -d <backup_dir> -c [custom_folder]" \
            "\n %prog --scp -s <host> -u [username] -p [password] -f <file> -d <backup_dir> -c [custom_folder]" \
            "\n %prog --ssh-ios -s <host> -u <username> -p <password> -e [enable-password] -d <backup_dir> -c [custom_folder]" \
            "\n %prog --ssh-asa -s <host> -u <username> -p <password> -e [enable-password] -d <backup_dir> -c [custom_folder]" \
            "\n %prog --ssh-pix -s <host> -u <username> -p <password> -e [enable-password] -d <backup_dir> -c [custom_folder]" \
            "\n %prog --ssh-nxos -s <host> -u <username> -p <password> -e [enable-password] -d <backup_dir> -c [custom_folder]" \
            "\n %prog --ssh-iosxr -s <host> -u <username> -p <password> -e [enable-password] -d <backup_dir> -c [custom_folder]" \
            "\n %prog --telnet-ios -s <host> -u [username] -p <password> -e [enable-password] -d <backup_dir> -c [custom_folder]" \
            "\n %prog --telnet-pix -s <host> -u [username] -p <password> -e [enable-password] -d <backup_dir> -c [custom_folder]" \
            "\n %prog --ironport -s <host> -u <username> -p <password> -d <backup_dir> -c [custom_folder]"

    parser = OptionParser(usage=usage)
    # main backup options
    parser.add_option("--ftp",
                  action="store_true", dest="ftp",
                  help="ftp connect")
    parser.add_option("--tftp",
                  action="store_true", dest="tftp",
                  help="tftp connect")
    parser.add_option("--http",
                  action="store_true", dest="http",
                  help="http connect")
    parser.add_option("--https",
                  action="store_true", dest="https",
                  help="https connect")
    parser.add_option("--scp",
                  action="store_true", dest="scp",
                  help="scp connect")
    parser.add_option("--ssh-ios",
                  action="store_true", dest="ssh_ios",
                  help="ssh connect for cisco ios (show startup-config)")
    parser.add_option("--ssh-asa",
                  action="store_true", dest="ssh_asa",
                  help="ssh connect for cisco asa (more system:running-config)")
    parser.add_option("--ssh-pix",
                  action="store_true", dest="ssh_pix",
                  help="ssh connect for cisco pix (show startup-config)")
    parser.add_option("--ssh-nxos",
                  action="store_true", dest="ssh_nxos",
                  help="ssh connect for cisco nxos (show startup-config)")
    parser.add_option("--ssh-iosxr",
                  action="store_true", dest="ssh_iosxr",
                  help="ssh connect for cisco ios-xr (show running-config)")
    parser.add_option("--telnet-ios",
                  action="store_true", dest="telnet_ios",
                  help="telnet connect for cisco ios (show startup-config)")
    parser.add_option("--telnet-pix",
                  action="store_true", dest="telnet_pix",
                  help="telnet connect for cisco pix (show startup-config)")
    parser.add_option("--ironport",
                  action="store_true", dest="ironport",
                  help="ssh connect and scp for cisco ironport (wsa/esa)")
    # backup parameters
    parser.add_option("-d",
                  dest="backupdir",
                  help="specify backup directory")
    parser.add_option("-s",
                  dest="hostname",
                  help="hostname or ip address")
    parser.add_option("-u",
                  dest="user",
                  help="username")
    parser.add_option("-p",
                  dest="password",
                  help="password")
    parser.add_option("-e",
                  dest="enable",
                  help="enable password")
    parser.add_option("-f",
                  dest="filename",
                  help="filename or path")
    parser.add_option("-c",
                  dest="custom_folder",
                  help="custom backup folder name, default is HOSTNAME")

    (options, args) = parser.parse_args()


    msg_invalid_args = "Invalid arguments"

    if options.ftp:
        if options.hostname and options.filename and options.backupdir:
            hostname = options.hostname.upper()
            user = options.user
            password = options.password
            filename = options.filename
            backup_dir = options.backupdir
            custom_folder = options.custom_folder
            newfile, lastfile, backup_path, = gen_backup_path(hostname, backup_dir, custom_folder)
            ftp_command(hostname, user, password, newfile, filename)
            saved_config = remove_changed(newfile, lastfile, backup_path)
        else:
            print msg_invalid_args
            sys.exit(3)
    elif options.tftp:
        if options.hostname and options.backupdir:
            hostname = options.hostname.upper()
            backup_dir = options.backupdir
            custom_folder = options.custom_folder
            newfile, lastfile, backup_path, = gen_backup_path(hostname, backup_dir, custom_folder)
            tftp_command(hostname, newfile, lastfile)
            saved_config = remove_changed(newfile, lastfile, backup_path)
        else:
            print msg_invalid_args
            sys.exit(3)
    elif options.http:
        if options.hostname and options.filename and options.backupdir:
            hostname = options.hostname.upper()
            user = options.user
            password = options.password
            filename = options.filename
            backup_dir = options.backupdir
            custom_folder = options.custom_folder
            newfile, lastfile, backup_path, = gen_backup_path(hostname, backup_dir, custom_folder)
            http_command(hostname, user, password, newfile, filename)
            saved_config = remove_changed(newfile, lastfile, backup_path)
        else:
            print msg_invalid_args
            sys.exit(3)
    elif options.https:
        if options.hostname and options.filename and options.backupdir:
            hostname = options.hostname.upper()
            user = options.user
            password = options.password
            filename = options.filename
            backup_dir = options.backupdir
            custom_folder = options.custom_folder
            newfile, lastfile, backup_path, = gen_backup_path(hostname, backup_dir, custom_folder)
            https_command(hostname, user, password, newfile, filename)
            saved_config = remove_changed(newfile, lastfile, backup_path)
        else:
            print msg_invalid_args
            sys.exit(3)
    elif options.scp:
        if options.hostname and options.filename and options.backupdir:
            hostname = options.hostname.upper()
            user = options.user
            password = options.password
            filename = options.filename
            backup_dir = options.backupdir
            custom_folder = options.custom_folder
            newfile, lastfile, backup_path, = gen_backup_path(hostname, backup_dir, custom_folder)
            scp_command(hostname, user, password, newfile, filename)
            saved_config = remove_changed(newfile, lastfile, backup_path)
        else:
            print msg_invalid_args
            sys.exit(3)
    elif options.ssh_ios:
        if options.hostname and options.user and options.password and options.backupdir:
            hostname = options.hostname.upper()
            user = options.user
            password = options.password
            enable = options.enable
            backup_dir = options.backupdir
            custom_folder = options.custom_folder
            platform = "ios"
            newfile, lastfile, backup_path, = gen_backup_path(hostname, backup_dir, custom_folder)
            ssh_connection = ssh_command(hostname, user, password, enable, platform)
            backupconfig(ssh_connection, newfile)
            saved_config = remove_changed(newfile, lastfile, backup_path)
        else:
            print msg_invalid_args
            sys.exit(3)
    elif options.ssh_asa:
        if options.hostname and options.user and options.password and options.backupdir:
            hostname = options.hostname.upper()
            user = options.user
            password = options.password
            enable = options.enable
            backup_dir = options.backupdir
            custom_folder = options.custom_folder
            platform = "asa"
            newfile, lastfile, backup_path, = gen_backup_path(hostname, backup_dir, custom_folder)
            ssh_connection = ssh_command(hostname, user, password, enable, platform)
            backupconfig(ssh_connection, newfile)
            saved_config = remove_changed(newfile, lastfile, backup_path)
        else:
            print msg_invalid_args
            sys.exit(3)
    elif options.ssh_pix:
        if options.hostname and options.user and options.password and options.backupdir:
            hostname = options.hostname.upper()
            user = options.user
            password = options.password
            enable = options.enable
            backup_dir = options.backupdir
            custom_folder = options.custom_folder
            platform = "pix"
            newfile, lastfile, backup_path, = gen_backup_path(hostname, backup_dir, custom_folder)
            ssh_connection = ssh_command(hostname, user, password, enable, platform)
            backupconfig(ssh_connection, newfile)
            saved_config = remove_changed(newfile, lastfile, backup_path)
        else:
            print msg_invalid_args
            sys.exit(3)
    elif options.ssh_nxos:
        if options.hostname and options.user and options.password and options.backupdir:
            hostname = options.hostname.upper()
            user = options.user
            password = options.password
            enable = options.enable
            backup_dir = options.backupdir
            custom_folder = options.custom_folder
            platform = "nxos"
            newfile, lastfile, backup_path, = gen_backup_path(hostname, backup_dir, custom_folder)
            ssh_connection = ssh_command(hostname, user, password, enable, platform)
            backupconfig(ssh_connection, newfile)
            saved_config = remove_changed(newfile, lastfile, backup_path)
        else:
            print msg_invalid_args
            sys.exit(3)
    elif options.ssh_iosxr:
        if options.hostname and options.user and options.password and options.backupdir:
            hostname = options.hostname.upper()
            user = options.user
            password = options.password
            enable = options.enable
            backup_dir = options.backupdir
            custom_folder = options.custom_folder
            platform = "iosxr"
            newfile, lastfile, backup_path, = gen_backup_path(hostname, backup_dir, custom_folder)
            ssh_connection = ssh_command(hostname, user, password, enable, platform)
            backupconfig(ssh_connection, newfile)
            saved_config = remove_changed(newfile, lastfile, backup_path)
        else:
            print msg_invalid_args
            sys.exit(3)
    elif options.telnet_ios:
        if options.hostname and options.password and options.backupdir:
            hostname = options.hostname.upper()
            user = options.user
            password = options.password
            enable = options.enable
            backup_dir = options.backupdir
            custom_folder = options.custom_folder
            platform = "ios"
            newfile, lastfile, backup_path, = gen_backup_path(hostname, backup_dir, custom_folder)
            telnet_connection = telnet_command(hostname, user, password, enable, platform)
            backupconfig(telnet_connection, newfile)
            saved_config = remove_changed(newfile, lastfile, backup_path)
        else:
            print msg_invalid_args
            sys.exit(3)
    elif options.telnet_pix:
        if options.hostname and options.password and options.backupdir:
            hostname = options.hostname.upper()
            user = options.user
            password = options.password
            enable = options.enable
            backup_dir = options.backupdir
            custom_folder = options.custom_folder
            platform = "pix"
            newfile, lastfile, backup_path, = gen_backup_path(hostname, backup_dir, custom_folder)
            telnet_connection = telnet_command(hostname, user, password, enable, platform)
            backupconfig(telnet_connection, newfile)
            saved_config = remove_changed(newfile, lastfile, backup_path)
        else:
            print msg_invalid_args
            sys.exit(3)
    elif options.ironport:
        if options.hostname and options.user and options.password and options.backupdir:
            hostname = options.hostname.upper()
            user = options.user
            password = options.password
            backup_dir = options.backupdir
            custom_folder = options.custom_folder
            newfile, lastfile, backup_path, = gen_backup_path(hostname, backup_dir, custom_folder)
            ironport_command(hostname, user, password, newfile)
            saved_config = remove_changed(newfile, lastfile, backup_path)
        else:
            print msg_invalid_args
            sys.exit(3)
    else:
        print help_message
        sys.exit(3)

    print "Configbackup successful: " + saved_config
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print str(error)
        sys.exit(3)
