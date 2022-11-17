import requests
import paramiko
from paramiko import SSHClient, AutoAddPolicy ,RSAKey
from io import StringIO
ip_list=["10.23.1.0/24"]
import tempfile
import os
from scp import SCPClient, SCPException
import json
import subprocess
from pathlib import Path
 
directory = "/usr/local/bin/"


def get_home_directory():
    return str(Path.home())

home_dir = get_home_directory() + "/"

def start_scan(binary_path):
    print("Initiating Scan on {} servers".format(len(ip_list)))
    for ip_address in ip_list:
        print("Scanning {}".format(ip_address))
        cli_command = {
            "operation": "remote_scan",
            "ip_address": ip_address,
            "scan_type": "CIDR Scan",
            "full_scan": "False", 
            "jump_server_ip": "20.39.54.112",
            "additional_args":"-o"
        }
        argument_dict = {}
        argument_dict[cli_command.get("operation")] = {}
        operation = cli_command.get("operation")
        additional_args = [cli_command.get("additional_args").strip()]
        acc_username = cli_command.get("user_email")
        acc_password = cli_command.get("password")
        jwt_token = cli_command.get("jwt_token")
        acc_api_key = cli_command.get("acc_api_key")

        for key in cli_command.keys():
            if key not in ["operation", "additional_args"]:
                argument_dict[operation][key] = cli_command[key]
        
        credential_string = "{},{},{}".format(acc_username, acc_password, acc_api_key)
        argument_dict = json.dumps(argument_dict)
        
        cli_process = subprocess.Popen([binary_path, "-cm", argument_dict]+additional_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = cli_process.communicate()
        if error:
            print("Error in scan {}".format(error))
            return False
        print(output)
        print("Scan completed on {}".format(ip_address))
    print("Scan Task for remote cli scan completed for user {}".format("Ascent"))
    transfer_status = transfer_reports()
    return transfer_status

def transfer_reports():
    server_creds = {
        "ip_address": "20.168.231.227",
        "username": "ubuntu",
        "ssh-file-path": r"daemon_lab_public_machine_key.pem"
    }
    ssh_client = get_ssh_client(server_creds, timeout=30)
    if not ssh_client:
        print("Failed to connect to server {}".format(server_creds.get("ip_address")))
        return False
    else:
        print("Successfully connected to server {}".format(server_creds.get("ip_address")))
        scp_put_data(ssh_client, "/etc/secops_cli", home_dir)
        command = "sudo cp -r {}secops_cli /etc".format(home_dir)
        ssh_execute_command(command,ssh_client)
        command = "sudo rm -rf {}secops_cli".format(home_dir)
        ssh_execute_command(command,ssh_client)
        ssh_client.close()
        command = "sudo rm -rf /etc/secops_cli"
        subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("Successfully transferred the reports to the jump server")
        return True

def get_ssh_client(server_creds, timeout=10):
    ssh_client = ssh_connect_private_key(
        server_creds["ip_address"],
        server_creds["username"],
        server_creds["ssh-file-path"],
        None,
        timeout,
    )
    return ssh_client

def ssh_connect_private_key(ip_address, username, ssh_key, passphrase=None, timeout=None):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        pkey=paramiko.RSAKey.from_private_key_file(ssh_key)
        host=ip_address
        username=username
        
        client.connect(host, username=username, pkey=pkey)
        return client
        
    except Exception as ex:
        print(ex)
        print("Failed to connect to ssh client using key")
        return None

def scp_put_data(ssh_client, files, remote_path, recursive=False):
    try:
        scp_client = SCPClient(ssh_client.get_transport())
        scp_client.put(files,remote_path,True)
        print("Uploaded files %s remotely at path %s",files,remote_path)
    except SCPException as ex:
       print("Error uploading files %s remotely at path \
                        %s. Exception : %s ", files, remote_path, str(ex))
       
    finally:
        if scp_client:
            scp_client.close()

def ssh_execute_command(command, ssh_client):
    try:
        stdin,stdout,stderr=ssh_client.exec_command(command)
        stdout.channel.recv_exit_status()
        print("Executed remote command %s succesfully",command)
    except SSHException as ex:
        print("Error executing remote command %s. Exception: %s",command, str(ex))
        raise Forbidden("SSH exec command error ", str(ex))

def check_binary():
    if os.name == "nt":
        binary_path = directory + os.sep + "secops_cli_windows-latest.exe"
        # check if binary exists
        if not os.path.isfile(binary_path):
            return False
    else:
        dir_files = os.listdir(directory)
        if "secops_cli_ubuntu-20.04" in dir_files:
            binary_name = "secops_cli_ubuntu-20.04"
            print("Found binary for ubuntu 20.04")
        elif "secops_cli_ubuntu-18.04" in dir_files:
            binary_name = "secops_cli_ubuntu-18.04"
            print("Found binary for ubuntu 18.04")
        else:
            print("No binary found for ubuntu")
            return False

        binary_path = os.path.join(directory, binary_name)

    return binary_path

def upload_results():
    #upload the results to the server
    cli_command = {
        "operation":"upload",
        "acc_username":"client_2@gmail.com",
        "acc_password":"Test@1234",
        "acc_api_key":"vx7eLUSnq0ze9B1LuwCfjjTzy2TVfXSCI5IhOPne0fk",
        "additional_args":"-u"

    }
    command_url="https://{}:{}/run_task".format("20.168.231.227","5678")
    print("Starting upload")
    response = requests.post(command_url, json=cli_command)
    if response.status_code != 200:
            command_url="http://{}:{}/run_task".format("20.168.231.227","5678")
            print("Sending command to hop server {}".format(command_url))
            response = requests.post(command_url, json=cli_command)
            if response.status_code != 200:
                print("upload failed ")
                print("Error while sending command to hop server {} -- {}".format(hop_server_ip, response.text))
                return
        
    print(response.json().get("Info"))
    # if response jsonhas info check if info is a list if so then check if it has any elements if the stripped elements contains Upload successful
    if response.json().get("Info"):
        if isinstance(response.json().get("Info"), list):
            if any("Upload successful" in s.strip()  for s in response.json().get("Info")):
                print("upload successful ")
            else:
                print("upload failed ")
                return
        else:
            if "Upload successful" in response.json().get("Info").strip():
                print("upload successful ")
            else:
                print("upload failed ")
                return
    else:
        print("upload failed , No info found in response")
        return



if __name__ == "__main__":
    binary_path = check_binary()
    if binary_path:
        sucecss = start_scan(binary_path)
    if sucecss:
        upload_results()
