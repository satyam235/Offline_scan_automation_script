import warnings
warnings.filterwarnings("ignore")

import requests
import paramiko
from paramiko import SSHClient, AutoAddPolicy ,RSAKey
from io import StringIO
import tempfile
import os
from scp import SCPClient, SCPException
import json
import subprocess
from pathlib import Path
import argparse
from rich.console import Console
CIDR_LIST = [
    {
        "cidr": "10.0.1.0/24", 
        "server_name": "TESTEXT"
    },
    {
        "cidr": "192.168.9.0/24", 
        "server_name": "TESTINT"
    }
]

console = Console()
args = None
 
directory = "/usr/local/bin/"
def get_home_directory():
    return str(Path.home())

home_dir = get_home_directory() + "/"


def printer(msg, fail=False):
    if not args:
        disable_color = True
    else:
        disable_color = False
    if not disable_color:
        if not fail:
            console.print(msg, style = "green")
        else:
            console.print(msg, style = "red")
    else:
        print(msg)


def start_scan(binary_path):
    verbose = args.verbose
    if args.debug:
        printer("Total CIDR's to scan {}".format(len(CIDR_LIST)))
    for cidr in CIDR_LIST:
        if verbose:
            printer("Performing Assesment on {}".format(cidr.get("cidr")))
        cli_command = {
            "operation": "remote_scan",
            "ip_address": cidr.get("cidr"),
            "scan_type": "CIDR Scan",
            "full_scan": "False", 
            "jump_server_ip": JUMP_SERVER_IP,
            "additional_args":"-o",
            "server_name": cidr.get("server_name")   
        }
        if args.debug:
            printer("CLI command {}".format(cli_command))
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
            printer("Error in scanning {}".format(cidr),True)
            printer("Error {}".format(error),True)
            return False
        if args.debug:
            printer("Output of scan {}".format(output))
        if verbose:
            printer("Scan completed on {}".format(cidr.get("cidr")))
    printer("Scan Task for remote cli scan completed for user {}".format("Ascent"))
    print("----------------------------------------")
    
    transfer_status = transfer_reports()
    return transfer_status

   

def transfer_reports():
    try:
        verbose = args.verbose
        debug = args.debug
        
        if verbose:
            printer("Initiating transfer of reports")
        server_creds = {
            "ip_address": JUMP_SERVER_IP,
            "username": USERNAME,
            "ssh-file-path": SSH_KEY_PATH,
            "password": PASSWORD
        }
        if debug:
            printer("Connecting to server")
            printer("Server creds {}".format(server_creds))
        
        if args.ssh_key:
            ssh_client = get_ssh_client(server_creds, timeout=30)
        elif args.password:
            ssh_client = ssh_connect_password(
                server_creds["ip_address"],
                server_creds["username"],
                server_creds["password"],
                timeout=30
            )
        else:
            printer("No authentication method provided",True)
            return False

        if not ssh_client:
            printer("Failed to connect to server {}".format(server_creds.get("ip_address")),True)
            return False
        else:
            # get home dir from server
            stdin,stdout,stderr=ssh_client.exec_command("echo $HOME")
            stdout.channel.recv_exit_status()
            home_dir = stdout.read().decode("utf-8").strip()
            if debug:
                printer("Home dir of server is {}".format(home_dir))
            if verbose:
                printer("Connected to server {}".format(server_creds.get("ip_address")))
            
            scp_put_data(ssh_client, "/etc/secops_cli", home_dir)
            command = "sudo cp -r {}/secops_cli /etc".format(home_dir)
            ssh_execute_command(command,ssh_client)
            command = "sudo rm -rf {}/secops_cli".format(home_dir)
            ssh_execute_command(command,ssh_client)
            ssh_client.close()
            command = "sudo rm -rf /etc/secops_cli/offline_reports"
            subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if verbose:
                printer("Transfer of reports completed")
            print("----------------------------------------")
            return True
    except Exception as e:
        printer("Error in transfer of reports {}".format(e),True)
        return False
    
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
    debug = args.debug
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        pkey=paramiko.RSAKey.from_private_key_file(ssh_key)
        host=ip_address
        username=username
        
        client.connect(host, username=username, pkey=pkey, port = 26)
        return client
        
    except Exception as ex:
        if debug:
            printer("Error in connecting to server {}".format(ex),True)
        return None

def ssh_connect_password(ip_address, username, password, timeout=None):
    try:
        debug = args.debug
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        ssh_client.connect(
            hostname=ip_address,
            username=username,
            password=password, 
            look_for_keys=False,
            timeout=timeout
            )
        
        print("Connected to ssh client using password")
        return ssh_client
    except Exception as ex:
        if debug:
            printer("Error in connecting to server {}".format(ex),True)
        return None

def scp_put_data(ssh_client, files, remote_path, recursive=False):
    debug = args.debug
    try:
        scp_client = SCPClient(ssh_client.get_transport())
        scp_client.put(files,remote_path,True)
        if debug:
            printer("Successfully transferred files to server")
        
    except SCPException as ex:
        if debug:
            printer("Failed to transfer files to server , Exception".format(str(ex)),True)
    finally:
        if scp_client:
            scp_client.close()

def ssh_execute_command(command, ssh_client):
    debug = args.debug
    try:
        if args.debug:
            printer("Executing command {}".format(command))
        stdin,stdout,stderr=ssh_client.exec_command(command)
        stdout.channel.recv_exit_status()
        if debug:
            printer("Command executed successfully")
        
    except SSHException as ex:
        if debug:
            printer("Failed to execute command {} Exception {}".format(command,str(ex)),True)
        raise Forbidden("SSH exec command error ", str(ex))

def check_binary():
    debug = args.debug
    if os.name == "nt":
        binary_path = directory + os.sep + "secops_cli_windows-latest.exe"
        # check if binary exists 
        if not os.path.isfile(binary_path):
            return False
    else:
        dir_files = os.listdir(directory)
        if "secops_cli_ubuntu-20.04" in dir_files:
            binary_name = "secops_cli_ubuntu-20.04"
            if debug:
                printer("Binary name is {}".format(binary_name))
            
        elif "secops_cli_ubuntu-18.04" in dir_files:
            binary_name = "secops_cli_ubuntu-18.04"
            if debug:
                printer("Binary name is {}".format(binary_name))
            
        else:
            if debug:
                printer("No binary found in the directory",True)
            return False

        binary_path = os.path.join(directory, binary_name)

    return binary_path

def upload_results():
    try:
        #upload the results to the server
        verbose = args.verbose
        debug = args.debug
        if verbose:
            printer("Initiating upload of results")

        cli_command = {
            "operation":"upload",
            "acc_username":"girish@ascent-online.com",
            "acc_password":"X8JtBPn5wn#S7hnN",
            "acc_api_key":"fqKrNMmAEltia_59Sh_srhM1mqBqitBMVsAmosBfOo0",
            "additional_args":"-u"
        }

        command_url="https://{}:{}/run_task".format(JUMP_SERVER_IP,"5678")
        
        if debug:
            printer("Command url is {}".format(command_url))
            printer(("CLI Command is {}".format(cli_command)))
        try:
            response = requests.post(command_url, json=cli_command,verify=False)
        except Exception as e:
            if debug:
                printer("Error in uploading results {}".format(e),True)
            command_url="http://{}:{}/run_task".format(JUMP_SERVER_IP,"5678")
            if debug:
                printer("Command url is {}".format(command_url))
                printer(("CLI Command is {}".format(cli_command)))
            
            response = requests.post(command_url, json=cli_command)
            if response.status_code != 200:
                if debug:
                    printer("Failed to upload results , {}".format(response.text),True)
                return False

        if debug:
            printer("Response from server {}".format(response.text))
        
        # if response json has info check if info is a list if so then check if it has any elements if the stripped elements contains Upload successful
        if response.json().get("Info"):
            if isinstance(response.json().get("Info"), list):
                if any("Upload successful" in s.strip()  for s in response.json().get("Info")):
                    if verbose:
                        printer("Upload successful")
                        print("----------------------------------------")
                    return True
                else:
                    if verbose:
                        printer("Upload failed",True)
                    return False
            else:
                if "Upload successful" in response.json().get("Info").strip():
                    if verbose:
                        printer("Upload successful")
                        print("----------------------------------------")
                    return True
                else:
                    if verbose:
                        printer("Upload failed",True)
                    return False
        else:
            if verbose:
                printer("Upload failed,please try again in sometime.",True)
            return
    except Exception as e:
        if debug:
            printer("Exception occured during  upload {}".format(e),True)
        return False


if __name__ == "__main__":
    global JUMP_SERVER_IP
    global SSH_KEY_PATH
    global USERNAME
    global PASSWORD

    parser = argparse.ArgumentParser(description='Automation script for secops cli')
    parser.add_argument('-d','--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('-v', '--verbose', help='Verbose output', action='store_true',default=True)
    parser.add_argument('-jp', '--jump_server_ip', help='jump server ip', action='store')
    # ssh key path
    parser.add_argument('-k', '--ssh_key', help='ssh key path', action='store')
    # username
    parser.add_argument('-un', '--username', help='username', action='store')
    # password
    parser.add_argument('-p', '--password', help='password', action='store')
    # transfer mode
    parser.add_argument('-tm', '--transfer_mode', help='transfer mode', action='store')

    args = parser.parse_args()

    if not parser.parse_args().jump_server_ip:
        parser.error('jump server ip is required')
        exit(1)
    else:
        JUMP_SERVER_IP = str(parser.parse_args().jump_server_ip.strip())
        if args.debug:
            printer("Jump server ip is {}".format(JUMP_SERVER_IP))

    if not parser.parse_args().username:
        parser.error('username is required')
        exit(1)
    else:
        USERNAME = str(parser.parse_args().username.strip())
        if args.debug:
            printer("Username is    {}".format(USERNAME))


    if parser.parse_args().ssh_key:
        SSH_KEY_PATH = str(parser.parse_args().ssh_key.strip())
        if args.debug:
            printer("SSH key path is {}".format(SSH_KEY_PATH))
    else:
        SSH_KEY_PATH = None

    
    if  parser.parse_args().password:
        PASSWORD = str(parser.parse_args().password.strip())
        if args.debug:
            printer("Password is {}".format(PASSWORD))
    else:
        PASSWORD = None

    # check if ssh and password are not provided
    if not SSH_KEY_PATH and not PASSWORD:
        parser.error('Either ssh key or password is required')
        exit(1)
    
    sucess = False
    binary_path = check_binary()
    # if transfer mode is not provided then check if binary is present in the directory  and transfer it to the jump server
    if parser.parse_args().transfer_mode:
        transfer_status = transfer_reports()
        if transfer_status:
            upload_results()

    if binary_path:
        sucess = start_scan(binary_path)
    if sucess :
        upload_results()
    else:
        printer("Upload failed",True)
        
