#!/usr/bin/env python3

#external sources:
    #https://www.youtube.com/watch?v=bwTAVGg_kVs
    #https://docs.python.org/3/library/socket.html

import sys
import socket
import argparse
import select

client_ip = "127.0.0.1"
def error(msg):
    print(msg)
    sys.exit(1)

# Expected:
#   --id <ClientID>
#   --port <ClientPort>
#   --server <IP:Port>
def parse_args():
    parser = argparse.ArgumentParser(add_help=False) #no -h flag so there isn't extra output
    parser.add_argument("--id")
    parser.add_argument("--port", type=int)
    parser.add_argument("--server")

    args, unknown = parser.parse_known_args()

    if args.id is None or args.port is None or args.server is None:
        error("Usage: --id <ID> --port <Port> --server <IP:Port>")

    try:
        server_ip, server_port = args.server.split(":")
        server_port = int(server_port)
    except:
        error("Server must be formatted as IP:Port")

    return args.id, args.port, server_ip, server_port

def register(client_id, client_ip, client_port):
    return (
        "REGISTER\r\n"
        f"clientID: {client_id}\r\n"
        f"IP: {client_ip}\r\n"
        f"Port: {client_port}\r\n"
        "\r\n" # Since it needs 2 enters to identify end
    )

def bridge(client_id):
    return (
        "BRIDGE\r\n"
        f"clientID: {client_id}\r\n"
        "\r\n" # Since it needs 2 enters to identify end
    )

def chat(msg, id, ip, port):
    return (
        "CHAT\r\n"
        f"message: {msg}\r\n"
        f"id: {id}\r\n"
        f"ip: {ip}\r\n"
        f"port: {port}\r\n"
        "\r\n"
    )

def send_and_recv(sock, msg):
    #print(f"Sending {msg} to {sock}")
    try:
        sock.sendall(msg.encode())
    except socket.error as e:
        print(f"Socket error when sending: {e}")
    
    try:
        data = sock.recv(1024) # 1kb; doubtful message will go over this much
    except socket.error as e:
        print(f"Socket error when receiving: {e}")
    #print(f"Received {data.decode()}")
    return data.decode()

def send_to_peer(peer_sock, msg):
    #print("Sending to peer")
    try:
        peer_sock.sendall(msg.encode())
    except socket.error as e:
        print(f"Socket error when sending to peer: {e}")
    return

def main():
    client_id, client_port, server_ip, server_port = parse_args()
    
    #try:
        #prep_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
        #prep_sock.connect((server_ip, server_port))
    #print(f"{client_id} running on {server_ip}:{client_port}")
        # Outgoing IP
        #client_ip = prep_sock.getsockname()[0]
    #except socket.error as e:
        #error(f"Failed to connect to server: {e}")
    #finally:
        #prep_sock.close()

    try:
        input_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        input_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        input_sock.bind((client_ip, client_port))
        print(f"{client_id} running on {server_ip}:{client_port}")
        input_sock.listen(1)
    except socket.error as e:
        error(f"Input socket setup failed: {e}") #quits program instead of just a print
    
    sockets = [sys.stdin, input_sock]

    peer_sock = None
    peer_id = ""
    peer_ip = ""
    peer_port = None

    first_pass = False

    mode = "NORMAL" #Modes: NORMAL, WAIT, CHAT(READ, WRITE)

    def parse_response(response):
        id = None
        ip = None
        port = None
        lines = [i.strip() for i in response.splitlines()]
        for i in lines:
            if i.startswith("clientID:"):
                id = i.split(":", 1)[1].strip()
            elif i.startswith("IP:"):
                ip = i.split(":", 1)[1].strip()
            elif i.startswith("Port:"):
                check_port = i.split(":", 1)[1].strip()
                if check_port.isdigit():
                    port = int(check_port)
                else:
                    port = None
        return id, ip, port
    
    while True:
        try:
            read, write, exception = select.select(sockets, [], [])

            for i in read:

                if i is sys.stdin:
                    if mode=="NORMAL":
                        user_input = sys.stdin.readline().strip()
                        if user_input == "/id":
                            print(client_id)

                        elif user_input == "/register":
                            try:
                                server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                server_sock.connect((server_ip, server_port))
                                msg = register(client_id, client_ip, client_port)
                                response = send_and_recv(server_sock, msg)
                            except socket.error as e:
                                print(f"Register failed: {e}")
                            finally:
                                server_sock.close()

                        elif user_input == "/bridge":
                            try:
                                server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                server_sock.connect((server_ip, server_port))
                                msg = bridge(client_id)
                                response = send_and_recv(server_sock, msg)
                                # Output <client_id> IN WAIT MODE if the bridge ack returns blank values
                                lines = [i.strip() for i in response.splitlines()]
                                #print(lines)
                                peer_id = ""
                                peer_ip = ""
                                peer_port = None

                                for i in lines:
                                    if i.startswith("clientID:"):
                                        peer_id = i.split(":", 1)[1].strip()
                                    elif i.startswith("IP:"):
                                        peer_ip = i.split(":", 1)[1].strip()
                                    elif i.startswith("Port:"):
                                        peer_port_test = i.split(":", 1)[1].strip()
                                        if peer_port_test.isdigit():
                                            peer_port = int(peer_port_test)
                                        else:
                                            peer_port = None
                                
                                if peer_id == "" or peer_ip == "" or peer_port == None or peer_port == "":
                                    mode = "WAIT"
                                    first_pass = True
                                    print(f"{client_id} IN WAIT MODE")
                                else:
                                    #print(f"peer_sock {peer_sock}")
                                    try:
                                        peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                        peer_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                        peer_sock.connect((peer_ip, peer_port))
                                        sockets.append(peer_sock)
                                    except socket.error as e:
                                        print(f"Peer socket setup failed: {e}")
                                    #peer_sock.listen(1)
                                    #print(f"peer_sock {peer_sock}")
                                    #print("IN WRITE MODE")
                                    #mode = "WRITE"
                            except socket.error as e:
                                print(f"Bridge request failed: {e}")
                            finally:
                                server_sock.close()

                            
                        elif user_input == "/chat":
                            if peer_sock is None:
                                continue
                            #print(f"Peer: {peer_id} {peer_ip}:{peer_port}")
                            try:
                                #server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                #server_sock.connect((server_ip, server_port))
                                #server_msg = ("CHAT\r\n"
                                #    "\r\n"
                                #    )
                                #response = send_and_recv(server_sock, server_msg)
                                print("IN CHAT MODE") #need to send "CHAT" to server as well
                                print("IN WRITE MODE")
                                mode = "WRITE"
                                hello = sys.stdin.readline().strip() #first message
                                msg = chat(hello, client_id, client_ip, client_port)
                                send_to_peer(peer_sock, msg) #Chat is peer to peer, no server needed
                                print("IN READ MODE")
                                mode = "READ"
                            except socket.error as e:
                                print(f"Chat failed to establish with server: {e}")
                            finally:
                                server_sock.close()
                            break

                        elif user_input == "":
                            continue
                        
                        elif user_input == "/quit":
                            raise KeyboardInterrupt

                        else:
                            print("Invalid command. Use /id, /register, /bridge, /chat, or /quit.")
                    
                    elif mode=="READ":
                        # goes into elif per_sock is not None
                        #print("Entered the read 'branch' successfully")
                        continue

                    elif mode=="WRITE":
                        #print("properly entered write mode")
                        hello = sys.stdin.readline().strip() #first message
                        msg = chat(hello, client_id, client_ip, client_port)
                        #print(f"Sending to {peer_id}, {peer_ip}:{peer_port}, at {peer_sock}")
                        #print(msg)
                        send_to_peer(peer_sock, msg) #Server doesn't send anything.... does it?
                        if hello=="/quit":
                            print("Chat session has ended")
                            raise KeyboardInterrupt
                        print("IN READ MODE")
                        mode = "READ"
                        break

                elif i is input_sock:
                    #print(mode)
                    try:
                        conn, addr = input_sock.accept()
                    except socket.error as e:
                        print(f"Error accepting input data: {e}")
                    #print(f"peer_sock (or conn) = {conn}")
                    #print(f"addr = {addr}")
                    peer_sock = conn
                    if peer_sock not in sockets:
                        sockets.append(peer_sock)
                    #print(sockets)
                    #print("IN WRITE MODE 2")
                    #mode = "WRITE"
                 
                elif peer_sock is not None and i is peer_sock: #READ
                    try:
                        data = peer_sock.recv(1024)
                    except socket.error as e:
                        print(f"Error receiving peer data: {e}")
                        sockets.remove(peer_sock)
                        peer_sock.close()
                        peer_sock = None
                        continue
                    #print(f"i is peer sock: {data}")
                    if not data:
                        #print("Peer disconnected")
                        sockets.remove(peer_sock)
                        peer_sock.close()
                        peer_sock = None
                    else:
                        decoded = data.decode().rstrip()
                        lines = [i.strip() for i in decoded.splitlines()]
                        #print(f"lines = {lines}")
                        mess = ""
                        for i in lines:
                            #print(f"i in lines = {i}")
                            if i.startswith("message:"):
                                mess = i.split(":", 1)[1].strip()
                            elif i.startswith("id:"):
                                peer_id = i.split(":", 1)[1].strip()
                            elif i.startswith("ip:"):
                                peer_ip = i.split(":", 1)[1].strip()
                            elif i.startswith("port:"):
                                peer_port = i.split(":", 1)[1].strip()
                        #print(f"peer from {peer_ip}:{peer_port}")
                        if first_pass:
                            print(f"Incoming chat request from {peer_id} {peer_ip}:{peer_port}")
                            first_pass = False
                        if mess=="/quit":
                            print(f"{peer_id} has ended the chat session.")
                            raise KeyboardInterrupt
                        print(f"{peer_id}> {mess}")
                        print("IN WRITE MODE")
                        mode = "WRITE"
                        break
                #print("Passing a 'for i in read' loop")
        except KeyboardInterrupt:
            # Tell other user we are exiting
            #need to send "QUIT\r\n\r\n to server"
            print("Exiting program")
            if peer_sock is not None:
                quit_msg = chat("/quit", client_id, client_ip, client_port)
                peer_sock.sendall(quit_msg.encode())
                
            break

    try:
        if peer_sock:
            peer_sock.close()
        input_sock.close()
    except socket.error as e:
        print("Error closing sockets: {e}")

if __name__ == "__main__":
    main()