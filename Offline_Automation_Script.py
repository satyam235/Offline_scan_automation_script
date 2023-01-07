import warnings
warnings.filterwarnings("ignore")

import requests
import tempfile
import os
import json
import subprocess
from pathlib import Path
import argparse
from rich.console import Console

CIDR_LIST = [
    {
        "cidr": "10.23.1.0/24", 
        "server_name": "lab Setup 1"
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
    try:
        verbose = args.verbose
        if args.debug:
            printer("Total CIDR's to scan {}".format(len(CIDR_LIST)))
        for cidr in CIDR_LIST:
            if verbose:
                printer("Performing Assesment on {}".format(cidr.get("cidr")))
            cli_command = {
                    "operation": "remote_scan",
                    "ip_address":cidr.get("cidr"),
                    "scan_type": "CIDR Scan",
                    "full_scan": "False",
                    "server_name":"Satyam",
                    "acc_username":"lol@lol.com",
                    "acc_password": "Test@1234",
                    "acc_api_key": "awD-t-MWxZmZGFjLpUmccnCbz6qScn51NI81TaIY5is",
                    "additional_args": ""
                    }
            if args.debug:
                printer("CLI command {}".format(cli_command))
            argument_dict = {}
            argument_dict[cli_command.get("operation")] = {}
            operation = cli_command.get("operation")
            additional_args = [cli_command.get("additional_args").strip()]
            acc_username = cli_command.get("acc_username")
            acc_password = cli_command.get("acc_password")
            jwt_token = cli_command.get("jwt_token")
            acc_api_key = cli_command.get("acc_api_key")

            request_keys = list(cli_command.keys())

            if "acc_username" in request_keys:
                request_keys.remove("acc_username")
            if "acc_password" in request_keys:
                request_keys.remove("acc_password")
            if "acc_api_key" in request_keys:
                request_keys.remove("acc_api_key")

            for key in request_keys:
                if key not in ["operation", "additional_args"]:
                    argument_dict[operation][key] = cli_command[key]
            
            credential_string = "{},{},{}".format(acc_username, acc_password, acc_api_key)
            argument_dict = json.dumps(argument_dict)
            if args.debug:
                printer(binary_path + " -cm " + argument_dict + " -c " + credential_string + " " + " ".join(additional_args))
            cli_process = subprocess.Popen([binary_path, "-cm", argument_dict, "-c", credential_string]+additional_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
        return True
    except Exception as e:
        printer("Exception occured, {}".format(e),True)
        return False


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



if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Automation script for secops cli')
    parser.add_argument('-d','--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('-v', '--verbose', help='Verbose output', action='store_true',default=True)

    args = parser.parse_args()
    binary_path = check_binary()
    if binary_path:
        sucess = start_scan(binary_path)
    if sucess :
        printer(msg="Task Completed",fail=False)
    else:
        printer("Task failed",True)
        
