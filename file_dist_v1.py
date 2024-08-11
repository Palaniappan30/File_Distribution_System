import argparse
import os
import socket
import json
import hashlib
from cryptography.fernet import Fernet
from threading import Thread
import base64
import logging

CHUNK_SIZE = 8192

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class FileDistributionServer:
    def _init_(self, port):
        self.port = port
        self.groups = {}
        self.admins = set()
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', self.port))
            s.listen()
            logging.info(f"Server started on port {self.port}")
            while True:
                conn, addr = s.accept()
                Thread(target=self.handle_client, args=(conn, addr)).start()

    def handle_client(self, conn, addr):
        try:
            logging.info(f"New connection from {addr}")
            while True:
                data = conn.recv(1024).decode()
                if not data:
                    break
                command = json.loads(data)
                logging.debug(f"Received command: {command}")
                if command['action'] == 'retrieve_file':
                    response = self.retrieve_file(command['group_name'], command['file_name'], command['user'])
                    conn.send(response.encode())
                    file_info = json.loads(response)
                    if file_info['status'] == 'success':
                        chunk_number = 0
                        total_sent = 0
                        while True:
                            chunk = self.get_file_chunk(command['group_name'], command['file_name'], chunk_number)
                            if not chunk:
                                break
                            try:
                                encoded_chunk = chunk.encode()
                                conn.send(encoded_chunk)
                                total_sent += len(encoded_chunk)
                                logging.debug(f"Sent chunk {chunk_number}, size: {len(encoded_chunk)}, total sent: {total_sent}")
                                ack = conn.recv(1024).decode()
                                if ack != 'ACK':
                                    logging.warning(f"Unexpected ACK: {ack}")
                                    break
                            except Exception as e:
                                logging.error(f"Error while sending chunk: {str(e)}")
                                break
                            chunk_number += 1
                        conn.send('EOF'.encode())
                        logging.info(f"File transfer completed. Total sent: {total_sent}")
                else:
                    response = self.process_command(command, addr)
                    conn.send(json.dumps(response).encode())
        except Exception as e:
            logging.error(f"Client handling error: {str(e)}")
        finally:
            conn.close()
            logging.info(f"Connection closed for {addr}")

    def process_command(self, command, addr):
        action = command['action']
        if action == 'create_group':
            return self.create_group(command['group_name'], command['admin'])
        elif action == 'join_group':
            return self.join_group(command['group_name'], command['user'])
        elif action == 'distribute_file':
            return self.distribute_file(command['group_name'], command['file_path'], command['admin'])
        elif action == 'list_groups':
            return self.list_groups()
        elif action == 'add_admin':
            return self.add_admin(command['admin'])
        elif action == 'list_files':
            return self.list_files(command['group_name'], command['user'])
        elif action == 'retrieve_file':
            return self.retrieve_file(command['group_name'], command['file_name'], command['user'])
        else:
            return {'status': 'error', 'message': 'Invalid command'}

    def create_group(self, group_name, admin):
        if admin not in self.admins:
            return {'status': 'error', 'message': 'Only admins can create groups'}
        if group_name in self.groups:
            return {'status': 'error', 'message': 'Group already exists'}
        self.groups[group_name] = {'admin': admin, 'members': set(), 'files': []}
        return {'status': 'success', 'message': f'Group {group_name} created'}

    def join_group(self, group_name, user):
        if group_name not in self.groups:
            return {'status': 'error', 'message': 'Group does not exist'}
        self.groups[group_name]['members'].add(user)
        return {'status': 'success', 'message': f'Joined group {group_name}'}

    def list_files(self, group_name, user):
        if group_name not in self.groups:
            return {'status': 'error', 'message': 'Group does not exist'}
        if user not in self.groups[group_name]['members'] and user != self.groups[group_name]['admin']:
            return {'status': 'error', 'message': 'User is not a member of this group'}
        files = [file['name'] for file in self.groups[group_name]['files']]
        return {'status': 'success', 'files': files}
    
    def retrieve_file(self, group_name, file_name, user):
        try:
            if group_name not in self.groups:
                return json.dumps({'status': 'error', 'message': 'Group does not exist'})
            if user not in self.groups[group_name]['members'] and user != self.groups[group_name]['admin']:
                return json.dumps({'status': 'error', 'message': 'User is not a member of this group'})
            
            for file in self.groups[group_name]['files']:
                if file['name'] == file_name:
                    decrypted_content = self.fernet.decrypt(file['content'])
                    return json.dumps({
                        'status': 'success',
                        'file_name': file_name,
                        'file_size': len(decrypted_content),
                        'hash': file['hash']
                    })
            
            return json.dumps({'status': 'error', 'message': 'File not found in the group'})
        except Exception as e:
            return json.dumps({'status': 'error', 'message': f'Server error: {str(e)}'})

    CHUNK_SIZE = 8192

    def get_file_chunk(self, group_name, file_name, chunk_number):
        for file in self.groups[group_name]['files']:
            if file['name'] == file_name:
                decrypted_content = self.fernet.decrypt(file['content'])
                start = chunk_number * CHUNK_SIZE
                end = start + CHUNK_SIZE
                chunk = decrypted_content[start:end]
                chunk_hash = hashlib.sha256(chunk).hexdigest()
                encoded_chunk = base64.b64encode(chunk).decode('utf-8')
                return f"{len(encoded_chunk)}|{encoded_chunk}|{chunk_hash}"
        return None
    
    def distribute_file(self, group_name, file_path, admin):
        if admin not in self.admins:
            return {'status': 'error', 'message': 'Only admins can distribute files'}
        if group_name not in self.groups:
            return {'status': 'error', 'message': 'Group does not exist'}
        if not os.path.exists(file_path):
            return {'status': 'error', 'message': 'File does not exist'}
        
        with open(file_path, 'rb') as file:
            file_content = file.read()
        encrypted_content = self.fernet.encrypt(file_content)
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        self.groups[group_name]['files'].append({
            'name': os.path.basename(file_path),
            'content': encrypted_content,
            'hash': file_hash
        })
        return {'status': 'success', 'message': f'File distributed to group {group_name}'}

    def list_groups(self):
        return {'status': 'success', 'groups': list(self.groups.keys())}

    def add_admin(self, admin):
        self.admins.add(admin)
        return {'status': 'success', 'message': f'{admin} added as admin'}

class FileDistributionClient:
    def _init_(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port

    def send_command(self, command):
        with socket.create_connection((self.server_host, self.server_port)) as sock:
            sock.send(json.dumps(command).encode('utf-8'))
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            try:
                return json.loads(response)
            except json.JSONDecodeError:
                logging.error(f"Received invalid JSON: {response}")
                return {'status': 'error', 'message': 'Received invalid JSON from server'}

    def create_group(self, group_name, admin):
        command = {
            'action': 'create_group',
            'group_name': group_name,
            'admin': admin
        }
        return self.send_command(command)

    def join_group(self, group_name, user):
        command = {
            'action': 'join_group',
            'group_name': group_name,
            'user': user
        }
        return self.send_command(command)

    def list_files(self, group_name, user):
        command = {
            'action': 'list_files',
            'group_name': group_name,
            'user': user
        }
        return self.send_command(command)
    
    def retrieve_file(self, group_name, file_name, user):
        try:
            with socket.create_connection((self.server_host, self.server_port), timeout=15) as sock:
                command = {
                    'action': 'retrieve_file',
                    'group_name': group_name,
                    'file_name': file_name,
                    'user': user
                }
                sock.send(json.dumps(command).encode('utf-8'))
                
                response = sock.recv(1024).decode('utf-8')
                file_info = json.loads(response)
                if file_info['status'] == 'success':
                    save_path = input("Enter path to save the file: ")
                    save_path = os.path.join(save_path, file_name)
                    os.makedirs(os.path.dirname(save_path), exist_ok=True)
                    file_size = 0
                    chunk_number = 0
                    with open(save_path, 'wb') as f:
                        while True:
                            try:
                                # Read the size of the incoming chunk
                                size_data = sock.recv(20).decode('utf-8').strip()
                                if not size_data or size_data == 'EOF':
                                    break
                                chunk_size = int(size_data.split('|')[0])
                                
                                # Read the chunk and hash
                                chunk_data = b''
                                while len(chunk_data) < chunk_size + 64:  # 64 for the hash
                                    chunk_data += sock.recv(chunk_size + 64 - len(chunk_data))
                                
                                # Split the data into chunk and hash
                                encoded_chunk = chunk_data[:chunk_size].decode('utf-8')
                                chunk_hash = chunk_data[chunk_size:].decode('utf-8')
                                
                                decoded_chunk = base64.b64decode(encoded_chunk)
                                if hashlib.sha256(decoded_chunk).hexdigest() != chunk_hash:
                                    raise ValueError("Chunk integrity check failed")
                                f.write(decoded_chunk)
                                file_size += len(decoded_chunk)
                                sock.send('ACK'.encode('utf-8'))
                            except (socket.timeout, ConnectionAbortedError, ConnectionResetError) as e:
                                logging.error(f"Error receiving chunk: {str(e)}")
                                break
                    logging.info(f"File download completed. Total size: {file_size}")
                    if verify_file_integrity(save_path, file_info['hash']):
                        print(f"File {file_name} successfully downloaded and verified!")
                    else:
                        print(f"File {file_name} was downloaded but failed integrity check!")
                else:
                    print(f"Failed to retrieve file: {file_info['message']}")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {str(e)}")

    def distribute_file(self, group_name, file_path, admin):
        command = {
            'action': 'distribute_file',
            'group_name': group_name,
            'file_path': file_path,
            'admin': admin
        }
        return self.send_command(command)

    def list_groups(self):
        command = {
            'action': 'list_groups'
        }
        return self.send_command(command)

    def add_admin(self, admin):
        command = {
            'action': 'add_admin',
            'admin': admin
        }
        return self.send_command(command)

def verify_file_integrity(file_path, expected_hash):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(CHUNK_SIZE), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest() == expected_hash
    except Exception as e:
        logging.error(f"Failed to verify file integrity: {str(e)}")
        return False

if _name_ == '_main_':
    parser = argparse.ArgumentParser(description="File Distribution CLI")
    parser.add_argument('role', choices=['server', 'client'], help="Run as either server or client")
    parser.add_argument('--port', type=int, default=8080, help="Port number for the server")
    parser.add_argument('--server-host', type=str, help="Server host address for the client")
    parser.add_argument('--server-port', type=int, help="Server port for the client")
    args = parser.parse_args()

    if args.role == 'server':
        server = FileDistributionServer(args.port)
        server.start()
    elif args.role == 'client':
        client = FileDistributionClient(args.server_host, args.server_port)
        while True:
            print("\nOptions:")
            print("1. Create Group")
            print("2. Join Group")
            print("3. List Files")
            print("4. Retrieve File")
            print("5. Distribute File")
            print("6. List Groups")
            print("7. Add Admin")
            choice = input("Select an option (q to quit): ").strip()
            if choice == '1':
                group_name = input("Enter group name: ")
                admin = input("Enter admin name: ")
                print(client.create_group(group_name, admin))
            elif choice == '2':
                group_name = input("Enter group name: ")
                user = input("Enter your name: ")
                print(client.join_group(group_name, user))
            elif choice == '3':
                group_name = input("Enter group name: ")
                user = input("Enter your name: ")
                print(client.list_files(group_name, user))
            elif choice == '4':
                group_name = input("Enter group name: ")
                file_name = input("Enter file name: ")
                user = input("Enter your name: ")
                client.retrieve_file(group_name, file_name, user)
            elif choice == '5':
                group_name = input("Enter group name: ")
                file_path = input("Enter file path: ")
                admin = input("Enter admin name: ")
                print(client.distribute_file(group_name, file_path, admin))
            elif choice == '6':
                print(client.list_groups())
            elif choice == '7':
                admin = input("Enter admin name to add: ")
                print(client.add_admin(admin))
            elif choice.lower() == 'q':
                break
            else:
                print("Invalid option. Please try again.")