import paramiko
import json
import hashlib

def ssh_connect():
    server = '192.168.1.102'
    username = 'iplo'
    password = '171202'

    execute = 'ifconfig'

    client = paramiko.SSHClient()
    client.load_system_host_keys()

    client.connect(server, username=username, password=password)
    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(execute)
    ssh_stdin.close()


if __name__ == "__main__":
    ssh_connect()