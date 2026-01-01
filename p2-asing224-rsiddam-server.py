import socket
import threading
import sys
import select
import argparse
import os


def build_message(method, headers, body=""):
    """
    Message format as per the message types
    Request Type: REGISTER
    header lines : clientID:  name
                   IP: ipaddress
                   Port: port number
    
    Request Type: BRIDGE
    header lines : clientID: name
                   
    Request Type: QUIT
    header lines: No headers needed
               
    """
    # method : REGISTER or BRIDGE
    lines = [method]
    for k, v in headers.items(): # headers (key-value pairs), may be more than one
        lines.append(f"{k}: {v}") # append headers (key-value pairs) into single line
    lines.append("") # add a blank separator line
    if body: # if any optional message is present
        lines.append(body)  # if so, append it  to same line
    return "\r\n".join(lines) + "\r\n"  # all messages into a single line



# Configuration
HOST = '127.0.0.1'
PORT = 7001
CLIENT_FILE = 'clients.txt'
CLIENT_DATA_SIZE = 2048

ERROR = "Un expected message\n"
# Store client contact info
clients = {}

def save_clients():
    with open(CLIENT_FILE, 'w') as f:
        for clientID, name in clients.items():
            f.write(f"{clientID}:{name}\n")

def load_clients():
    try:
        with open(CLIENT_FILE, 'r') as f:
            for line in f:
                clientID, name = line.strip().split(':', 1)
                clients[clientID] = name
    except FileNotFoundError:
        pass

def print_clients():
    clients = {}
    try:
        with open(CLIENT_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Spliting the line at the first colon to get clientID and the rest of the data
                clientID, data = line.split(':', 1)
                # Using eval to parse the dictionary string
                info = eval(data)
                clients[clientID] = info
        # Now, priting the client information
        for clientID, info in clients.items():
            print(f"{info['name']} {info['ip']}:{info['port']}")

    except FileNotFoundError:
        print(f"File {CLIENT_FILE} not found.")
    return clients


def handle_client(conn, data):
    try:
        lines = data.split('\n')
        if not lines:
            return
        #print(f"Lines {len(lines)}")
        #print(data)
        cmd = lines[0].strip()
        # print(cmd)
        if cmd == "REGISTER":
            if len(lines) >= 4:
                line2 = lines[1].split(":", 1)
                if len(line2) == 2:
                    clientID, name = line2[0].strip(), line2[1].strip()
                    # print(clientID, name)
                else:
                    conn.sendall(ERROR.encode('utf-8'))
                    return
                line3 = lines[2].split(":", 1)
                if len(line3) == 2:
                    client_ip, ip = line3[0].strip(), line3[1].strip()
                    # print(client_ip, ip)
                else:
                    conn.sendall(ERROR.encode('utf-8'))
                    return
                line4 = lines[3].split(":", 1)
                if len(line4) == 2:
                    client_port, port = line4[0].strip(), line4[1].strip()
                    # print(client_port, port)
                else:
                    conn.sendall(ERROR.encode('utf-8'))
                    return
                # Initialize and store client info
                clients[name] = {
                    'name': name,
                    'ip': ip,
                    'port': port
                }                    
                #print(clients)
                save_clients()
                print(f"REGISTER: {name} from {ip}:{port} received")
                #REGISTER: student1 from 127.0.0.1:2000 received
                #print_clients()

                # preparing respone to client for REGACK
                headers = {
                    "clientID": name,
                    "IP": ip,
                    "Port": int(port),
                    "Status":"registered"
                }
                response = build_message("REGACK", headers) 
                #print(response)               
                conn.sendall(response.encode('utf-8'))                
            else:
                conn.sendall(ERROR.encode('utf-8'))
        elif cmd == 'BRIDGE':
            if len(lines) >= 2:
                
                # print(f"Flow Check 1")
                if len(clients) < 2 :  
                    headers = {
                        "clientID": " ",
                        "IP": " ",
                        "Port": " ",
                        "Status":"registered"
                    }
                    response = build_message("BRIDGEACK", headers) 
                    conn.sendall(response.encode('utf-8'))
                    return               

                # Look up both clients by name
                client_info = list(clients.values())
                info1  = client_info[0]
                info2  = client_info[1]


                #print(f"BRIDGE: {name1} {name2}")
                headers = {
                    "clientID": info1['name'],
                    "IP": info1['ip'],
                    "Port": info1['port'],
                    "Status":"registered"
                }
                response = build_message("BRIDGEACK", headers) 
                #response = f"BRIDGEACK {info1['name']} {info1['ip']}:{info1['port']}\n"
                print(f"BRIDGE: {info2['name']} {info2['ip']}:{info2['port']} {info1['name']} {info1['ip']}:{info1['port']}")
                #print(response)
                conn.sendall(response.encode('utf-8'))
              
            else:
                print(f"Malformed incoming message")
                # closing socket
                conn.close()
                # delete the client information file
                if os.path.exists(CLIENT_FILE):
                    os.remove(CLIENT_FILE)              

                print("\nExiting the program")
                sys.exit(0)  
        else:
            #print(f"Malformed incoming message")
            print("Malformed incoming message", file=sys.stderr)
            # closing socket
            conn.close()
            # delete the client information file
            if os.path.exists(CLIENT_FILE):
                os.remove(CLIENT_FILE)              
            #print("\nExiting the program")
            sys.exit(0)            

    except KeyboardInterrupt:
        print("\nshutting down...")
        # delete the client information file
        if os.path.exists(CLIENT_FILE):
            os.remove(CLIENT_FILE)   
        sys.exit(0)        

def server_code():
    #load_clients()
    # create server
    parser = argparse.ArgumentParser(description="Chat Server")
    parser.add_argument('--port', required=True, help="Server PORT")
    args = parser.parse_args()
    server_port = int(args.port)
    try:
        # creating TCP socket for the server using socket
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # seting SO_REUSEADDR so that same server can be re-used, had to change server port while testing
        # so, using this option
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # We need to bind the IP address and the port number to the socket
        server.bind((HOST, server_port))
        # After bind starting socket to listen for any client requests
        # In listen we need to specify the max number of queued connection requests 
        # that the server will hold before refusing new ones - making this as 5
        server.listen(5)
        print(f"Server listening on {HOST}:{server_port}")
    except OSError as e:
        print(f"Socket error: {e}")
        sys.exit(0)

    # adding List of sockets for select - server and sys.stdin
    inputs = [server, sys.stdin]
    try:
        while True:

            #print("> ", end="", flush=True) # Display the prompt > in the terminal, signaling the user to type something.

            # Wait for message on any of the sockets
            readable, _, _ = select.select(inputs, [], [])

            # in a loop, checking any of the sokcets has message
            for sock in readable:
                if sock is server:
                    # New client connection, accept the connection
                    conn, addr = server.accept()
                    # if no message not blocking it
                    conn.setblocking(False)
                    # adds the newly accepted client socket connection to the inputs list
                    # So, select will have additional client socket to check for message
                    inputs.append(conn)
                    #print(f"Client connected: {addr}")
                elif sock is sys.stdin:
                    # Terminal input
                    line = sys.stdin.readline()
                    if line.strip().lower() == '/quit':
                        raise KeyboardInterrupt
                        break
                    if line.strip().lower() == '/info':
                        print_clients()
                        continue
                else:
                    # Client message
                    try:
                        # receives data from the client socket upto CLIENT_DATA_SIZE bytes. Assuming this will be
                        # max message size
                        data = sock.recv(CLIENT_DATA_SIZE).decode('utf-8').strip()
                        # print(data)
                        if len(data) > 0:
                            # print("CLient Msg")
                            handle_client(sock, data)
                            inputs.remove(sock)
                            #print("Peer closed the socket .. closing my sokcet")
                            sock.close() # closing socket with the client
                        else:
                            # Client disconnected, remove from the input list
                            inputs.remove(sock)
                            # close the socket
                            #print("Peer closed the socket .. closing my sokcet")
                            sock.close()
                    except ConnectionResetError:
                        # connection was reset, remove from the input list
                        inputs.remove(sock)
                        # close the socket
                        sock.close()
    except KeyboardInterrupt:
        print("\nServer shutting down...")      

        for sockets in inputs:
            if sockets:
                if sockets != server and sockets !=sys.stdin:
                    # graceful shutdown first for client's socket only
                    sockets.shutdown(socket.SHUT_RDWR)
                # close all of the sockets
                sockets.close()
        sys.exit(0)          
if __name__ == "__main__":
    server_code()
