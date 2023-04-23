import sys
import time
import paramiko 
import os
import cmd



HOST = '192.168.100.1'
USER = 'user'
PASSWORD = 'password'
secret = 'password'

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(HOST, username=USER, password=PASSWORD)

chan = client.invoke_shell()
time.sleep(1)
chan.send('en\n')
chan.send(secret +'\n')
time.sleep(1)
chan.send('term len 0\n')
time.sleep(1)
chan.send('sh run\n')
time.sleep(10)
output = chan.recv(99999)
time.sleep(3)
print output
time.sleep(10)

client.close()
