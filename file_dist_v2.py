import argparse
import os
import socket
import json
import hashlib
from cryptography.fernet import Fernet
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
import base64

CHUNK_SIZE = 8192 

class FileDistributionServer:
    def __init__(self, port):
        self.port = port
        self.groups = {}
        self.admins = set()
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', self.port))
            s.listen()
            print(f"Server started on port {self.port}")
            while True:
                conn, addr = s.accept()
                Thread(target=self.handle_client, args=(conn, addr)).start()

    def handle_client(self, conn, addr):
        try:
            with ThreadPoolExecutor() as executor:
                while True:
                    data = conn.recv(1024).decode()
                    if not data:
                        break
                    command = json.loads(data)
                    if command['action'] == 'retrieve_file':
                        response = self.retrieve_file(command['group_name'], command['file_name'], command['user'])
                        conn.send(response.encode())
                        file_info = json.loads(response)
                        if file_info['status'] == 'success':
                            chunk_number = 0
                            while True:
                                chunk = self.get_file_chunk(command['group_name'], command['file_name'], chunk_number)
                                if not chunk:
                                    break
                                try:
                                    conn.send(chunk.encode())
                                    ack = conn.recv(1024).decode()
                                    if ack != 'ACK':
                                        break
                                except (socket.timeout, ConnectionAbortedError, ConnectionResetError) as e:
                                    print(f"Error while sending chunk: {str(e)}")
                                    break
                                chunk_number += 1
                            conn.send('EOF'.encode())
                    else:
                        response = self.process_command(command, addr)
                        conn.send(json.dumps(response).encode())
        except Exception as e:
            print(f"Client handling error: {str(e)}")
        finally:
            conn.close()

    def process_command(self, command, addr):
        action = command['action']
        if action == 'create_group':
            return self.create_group(command['group_name'], command['admin'])
        elif action == 'join_group':
            return self.join_group(command['group_name'], command['user'])
        elif action == 'distribute_files':
            return self.distribute_files(command['group_name'], command['file_paths'], command['admin'])
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
            print(f"Retrieving file: group={group_name}, file={file_name}, user={user}")
            if group_name not in self.groups:
                print(f"Group '{group_name}' does not exist")
                return json.dumps({'status': 'error', 'message': 'Group does not exist'})
            if user not in self.groups[group_name]['members'] and user != self.groups[group_name]['admin']:
                print(f"User '{user}' is not a member of the group '{group_name}'")
                return json.dumps({'status': 'error', 'message': 'User is not a member of this group'})

            for file in self.groups[group_name]['files']:
                if file['name'] == file_name:
                    print(f"File '{file_name}' found, preparing to send")
                    decrypted_content = self.fernet.decrypt(file['content'])
                    return json.dumps({
                        'status': 'success',
                        'file_name': file_name,
                        'file_size': len(decrypted_content),
                        'hash': file['hash']
                    })

            print(f"File '{file_name}' not found in the group '{group_name}'")
            return json.dumps({'status': 'error', 'message': 'File not found in the group'})
        except Exception as e:
            print(f"Error in retrieve_file: {str(e)}")
            return json.dumps({'status': 'error', 'message': f'Server error: {str(e)}'})


    def get_file_chunk(self, group_name, file_name, chunk_number):
        for file in self.groups[group_name]['files']:
            if file['name'] == file_name:
                decrypted_content = self.fernet.decrypt(file['content'])
                start = chunk_number * CHUNK_SIZE
                end = start + CHUNK_SIZE
                chunk = decrypted_content[start:end]
                return base64.b64encode(chunk).decode('utf-8')
        return None
    
    def distribute_files(self, group_name, file_paths, admin):
        if admin not in self.admins:
            return {'status': 'error', 'message': 'Only admins can distribute files'}
        if group_name not in self.groups:
            return {'status': 'error', 'message': 'Group does not exist'}

        file_info_list = []
        for file_path in file_paths:
            if not os.path.exists(file_path):
                continue
            
            with open(file_path, 'rb') as file:
                file_content = file.read()
            encrypted_content = self.fernet.encrypt(file_content)
            file_hash = hashlib.sha256(file_content).hexdigest()
            
            file_info_list.append({
                'name': os.path.basename(file_path),
                'content': encrypted_content,
                'hash': file_hash
            })
        
        self.groups[group_name]['files'].extend(file_info_list)
        return {'status': 'success', 'message': f'Files distributed to group {group_name}'}

    def list_groups(self):
        return {'status': 'success', 'groups': list(self.groups.keys())}

    def add_admin(self, admin):
        self.admins.add(admin)
        return {'status': 'success', 'message': f'{admin} added as admin'}

class FileDistributionClient:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port

    def send_command(self, command):
        with socket.create_connection((self.server_host, self.server_port)) as sock:
            sock.send(json.dumps(command).encode('utf-8'))
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            try:
                return json.loads(response)
            except json.JSONDecodeError:
                print(f"Received invalid JSON: {response}")
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
                    with open(save_path, 'wb') as f:
                        while True:
                            try:
                                chunk = sock.recv(CHUNK_SIZE)
                                if not chunk or chunk.decode('utf-8', errors='ignore') == 'EOF':
                                    break
                                decoded_chunk = base64.b64decode(chunk)
                                f.write(decoded_chunk)
                                file_size += len(decoded_chunk)
                                sock.send('ACK'.encode('utf-8'))
                            except (socket.timeout, ConnectionAbortedError, ConnectionResetError) as e:
                                print(f"Error receiving chunk: {str(e)}")
                                break
                    print(f"File download completed. Total size: {file_size}")
                    if verify_file_integrity(save_path, file_info['hash']):
                        print(f"File {file_name} successfully downloaded and verified!")
                    else:
                        print(f"File {file_name} was downloaded but failed integrity check!")
                else:
                    print(f"Failed to retrieve file: {file_info['message']}")
        except Exception as e:
            print(f"An unexpected error occurred: {str(e)}")

    def distribute_files(self, group_name, file_paths, admin):
        command = {
            'action': 'distribute_files',
            'group_name': group_name,
            'file_paths': file_paths,
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
        print(f"Failed to verify file integrity: {str(e)}")
        return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="File Distribution CLI")
    parser.add_argument('role', choices=['server', 'client'], help="Run as either server or client")
    parser.add_argument('--port', type=int, default=8080, help="Port number for the server")
    parser.add_argument('--server-host', type=str, default='localhost', help="Server host address for the client")
    parser.add_argument('--server-port', type=int, help="Server port for the client")
    args = parser.parse_args()

    if args.role == 'server':
        server = FileDistributionServer(args.port)
        server.start()
    elif args.role == 'client':
        client = FileDistributionClient(args.server_host, args.server_port or args.port)
        
        while True:
            user_type = input("Are you an Admin or User? (admin/user/q to quit): ").lower().strip()
            
            if user_type == 'q':
                break
            elif user_type not in ['admin', 'user']:
                print("Invalid choice. Please enter 'admin' or 'user'.")
                continue

            if user_type == 'admin':
                while True:
                    print("\nAdmin Options:")
                    print("1. Create Group")
                    print("2. Distribute Files")
                    print("3. List Groups")
                    print("4. Add Admin")
                    print("5. Back to main menu")
                    choice = input("Select an option: ").strip()

                    if choice == '1':
                        group_name = input("Enter group name: ")
                        admin = input("Enter your admin name: ")
                        print(client.create_group(group_name, admin))
                    elif choice == '2':
                        group_name = input("Enter group name: ")
                        file_paths = input("Enter file paths (comma-separated): ").split(',')
                        admin = input("Enter your admin name: ")
                        print(client.distribute_files(group_name, file_paths, admin))
                    elif choice == '3':
                        print(client.list_groups())
                    elif choice == '4':
                        admin = input("Enter new admin name to add: ")
                        print(client.add_admin(admin))
                    elif choice == '5':
                        break
                    else:
                        print("Invalid option. Please try again.")

            elif user_type == 'user':
                while True:
                    print("\nUser Options:")
                    print("1. Join Group")
                    print("2. List Files")
                    print("3. Retrieve File")
                    print("4. Back to main menu")
                    choice = input("Select an option: ").strip()

                    if choice == '1':
                        group_name = input("Enter group name to join: ")
                        user = input("Enter your username: ")
                        print(client.join_group(group_name, user))
                    elif choice == '2':
                        group_name = input("Enter group name: ")
                        user = input("Enter your username: ")
                        print(client.list_files(group_name, user))
                    elif choice == '3':
                        group_name = input("Enter group name: ")
                        file_name = input("Enter file name to retrieve: ")
                        user = input("Enter your username: ")