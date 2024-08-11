import argparse
import os
import socket
import json
import hashlib
from cryptography.fernet import Fernet
from threading import Thread, Lock
import base64
import logging
from concurrent.futures import ThreadPoolExecutor
import zlib
import time
import schedule
import psutil

CHUNK_SIZE = 8192

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class FileDistributionServer:
    def _init_(self, port):
        self.port = port
        self.groups = {}
        self.admins = set()
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
        self.lock = Lock()
        self.transfers = {}
        self.offline_clients = {}

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', self.port))
            s.listen()
            logging.info(f"Server started on port {self.port}")
            with ThreadPoolExecutor(max_workers=psutil.cpu_count(logical=False) * 2) as executor:
                while True:
                    conn, addr = s.accept()
                    executor.submit(self.handle_client, conn, addr)

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
                        self.send_file(conn, command['group_name'], command['file_name'])
                elif command['action'] == 'check_offline_transfers':
                    self.check_offline_transfers(conn, command['user'])
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
        elif action == 'distribute_files':
            return self.distribute_files(command['group_name'], command['file_paths'], command['admin'], command.get('silent', False), command.get('schedule_time'))
        elif action == 'list_groups':
            return self.list_groups()
        elif action == 'add_admin':
            return self.add_admin(command['admin'])
        elif action == 'list_files':
            return self.list_files(command['group_name'], command['user'])
        elif action == 'remove_user':
            return self.remove_user(command['group_name'], command['user'], command['admin'])
        elif action == 'pause_transfer':
            return self.pause_transfer(command['transfer_id'], command['admin'])
        elif action == 'resume_transfer':
            return self.resume_transfer(command['transfer_id'], command['admin'])
        elif action == 'abort_transfer':
            return self.abort_transfer(command['transfer_id'], command['admin'])
        elif action == 'transfer_progress':
            return self.transfer_progress(command['transfer_id'])
        elif action == 'execute_post_transfer':
            return self.execute_post_transfer(command['group_name'], command['file_name'], command['script'])
        else:
            return {'status': 'error', 'message': 'Invalid command'}

    def create_group(self, group_name, admin):
        if admin not in self.admins:
            return {'status': 'error', 'message': 'Only admins can create groups'}
        with self.lock:
            if group_name in self.groups:
                return {'status': 'error', 'message': 'Group already exists'}
            self.groups[group_name] = {'admin': admin, 'members': set(), 'files': []}
        return {'status': 'success', 'message': f'Group {group_name} created'}

    def join_group(self, group_name, user):
        with self.lock:
            if group_name not in self.groups:
                return {'status': 'error', 'message': 'Group does not exist'}
            self.groups[group_name]['members'].add(user)
        return {'status': 'success', 'message': f'Joined group {group_name}'}

    def remove_user(self, group_name, user, admin):
        if admin not in self.admins:
            return {'status': 'error', 'message': 'Only admins can remove users'}
        with self.lock:
            if group_name not in self.groups:
                return {'status': 'error', 'message': 'Group does not exist'}
            if user not in self.groups[group_name]['members']:
                return {'status': 'error', 'message': 'User not in group'}
            self.groups[group_name]['members'].remove(user)
        return {'status': 'success', 'message': f'Removed user {user} from group {group_name}'}

    def list_files(self, group_name, user):
        with self.lock:
            if group_name not in self.groups:
                return {'status': 'error', 'message': 'Group does not exist'}
            if user not in self.groups[group_name]['members'] and user != self.groups[group_name]['admin']:
                return {'status': 'error', 'message': 'User is not a member of this group'}
            files = [file['name'] for file in self.groups[group_name]['files']]
        return {'status': 'success', 'files': files}
    
    def retrieve_file(self, group_name, file_name, user):
        try:
            with self.lock:
                if group_name not in self.groups:
                    return json.dumps({'status': 'error', 'message': 'Group does not exist'})
                if user not in self.groups[group_name]['members'] and user != self.groups[group_name]['admin']:
                    return json.dumps({'status': 'error', 'message': 'User is not a member of this group'})
                
                for file in self.groups[group_name]['files']:
                    if file['name'] == file_name:
                        return json.dumps({
                            'status': 'success',
                            'file_name': file_name,
                            'file_size': len(file['content']),
                            'hash': file['hash']
                        })
            
            return json.dumps({'status': 'error', 'message': 'File not found in the group'})
        except Exception as e:
            return json.dumps({'status': 'error', 'message': f'Server error: {str(e)}'})

    def send_file(self, conn, group_name, file_name):
        for file in self.groups[group_name]['files']:
            if file['name'] == file_name:
                decrypted_content = self.fernet.decrypt(file['content'])
                compressed_content = zlib.compress(decrypted_content)
                total_sent = 0
                for i in range(0, len(compressed_content), CHUNK_SIZE):
                    chunk = compressed_content[i:i+CHUNK_SIZE]
                    chunk_hash = hashlib.sha256(chunk).hexdigest()
                    encoded_chunk = base64.b64encode(chunk).decode('utf-8')
                    message = f"{len(encoded_chunk)}|{encoded_chunk}|{chunk_hash}"
                    conn.send(message.encode())
                    total_sent += len(chunk)
                    ack = conn.recv(1024).decode()
                    if ack != 'ACK':
                        logging.warning(f"Unexpected ACK: {ack}")
                        break
                conn.send('EOF'.encode())
                logging.info(f"File transfer completed. Total sent: {total_sent}")
                return
        logging.error(f"File {file_name} not found in group {group_name}")
    
    def distribute_files(self, group_name, file_paths, admin, silent=False, schedule_time=None):
        if admin not in self.admins:
            return {'status': 'error', 'message': 'Only admins can distribute files'}
        with self.lock:
            if group_name not in self.groups:
                return {'status': 'error', 'message': 'Group does not exist'}
        
        transfer_id = hashlib.md5(f"{group_name}{file_paths}{time.time()}".encode()).hexdigest()
        self.transfers[transfer_id] = {'status': 'pending', 'progress': 0}

        if schedule_time:
            schedule.every().day.at(schedule_time).do(self._distribute_files, group_name, file_paths, admin, silent, transfer_id)
            return {'status': 'success', 'message': f'File distribution scheduled for {schedule_time}', 'transfer_id': transfer_id}
        else:
            Thread(target=self._distribute_files, args=(group_name, file_paths, admin, silent, transfer_id)).start()
            return {'status': 'success', 'message': 'File distribution started', 'transfer_id': transfer_id}

    def _distribute_files(self, group_name, file_paths, admin, silent, transfer_id):
        successful_files = []
        failed_files = []
        
        for file_path in file_paths:
            if not os.path.exists(file_path):
                failed_files.append(file_path)
                continue
            try:
                with open(file_path, 'rb') as file:
                    file_content = file.read()
                compressed_content = zlib.compress(file_content)
                encrypted_content = self.fernet.encrypt(compressed_content)
                file_hash = hashlib.sha256(file_content).hexdigest()
                
                with self.lock:
                    self.groups[group_name]['files'].append({
                        'name': os.path.basename(file_path),
                        'content': encrypted_content,
                        'hash': file_hash
                    })
                successful_files.append(file_path)
                self.transfers[transfer_id]['progress'] += 1
            except Exception as e:
                logging.error(f"Error distributing file {file_path}: {str(e)}")
                failed_files.append(file_path)

        self.transfers[transfer_id]['status'] = 'completed'
        self.transfers[transfer_id]['progress'] = 100

        if not silent:
            for user in self.groups[group_name]['members']:
                if user in self.offline_clients:
                    self.offline_clients[user].append({
                        'group_name': group_name,
                        'files': successful_files
                    })

    def list_groups(self):
        with self.lock:
            return {'status': 'success', 'groups': list(self.groups.keys())}

    def add_admin(self, admin):
        with self.lock:
            self.admins.add(admin)
        return {'status': 'success', 'message': f'{admin} added as admin'}

    def pause_transfer(self, transfer_id, admin):
        if admin not in self.admins:
            return {'status': 'error', 'message': 'Only admins can pause transfers'}
        if transfer_id in self.transfers:
            self.transfers[transfer_id]['status'] = 'paused'
            return {'status': 'success', 'message': f'Transfer {transfer_id} paused'}
        return {'status': 'error', 'message': 'Transfer not found'}

    def resume_transfer(self, transfer_id, admin):
        if admin not in self.admins:
            return {'status': 'error', 'message': 'Only admins can resume transfers'}
        if transfer_id in self.transfers:
            self.transfers[transfer_id]['status'] = 'in_progress'
            return {'status': 'success', 'message': f'Transfer {transfer_id} resumed'}
        return {'status': 'error', 'message': 'Transfer not found'}

    def abort_transfer(self, transfer_id, admin):
        if admin not in self.admins:
            return {'status': 'error', 'message': 'Only admins can abort transfers'}
        if transfer_id in self.transfers:
            self.transfers[transfer_id]['status'] = 'aborted'
            return {'status': 'success', 'message': f'Transfer {transfer_id} aborted'}
        return {'status': 'error', 'message': 'Transfer not found'}

    def transfer_progress(self, transfer_id):
        if transfer_id in self.transfers:
            return {'status': 'success', 'progress': self.transfers[transfer_id]['progress']}
        return {'status': 'error', 'message': 'Transfer not found'}

    def execute_post_transfer(self, group_name, file_name, script):
        # This method would be implemented on the client side
        pass

    def check_offline_transfers(self, conn, user):
        if user in self.offline_clients:
            transfers = self.offline_clients[user]
            conn.send(json.dumps(transfers).encode())
            del self.offline_clients[user]
        else:
            conn.send(json.dumps([]).encode())

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
                    with open(save_path, 'wb') as f:
                        while True:
                            try:
                                data = sock.recv(1024).decode('utf-8')
                                if data == 'EOF':
                                    break
                                size, encoded_chunk, chunk_hash = data.split('|')
                                chunk = base64.b64decode(encoded_chunk)
                                decompressed_chunk = zlib.decompress(chunk)
                                if hashlib.sha256(chunk).hexdigest() != chunk_hash:
                                    raise ValueError("Chunk integrity check failed")
                                f.write(decompressed_chunk)
                                file_size += len(decompressed_chunk)
                                sock.send('ACK'.encode('utf-8'))
                            except Exception as e:
                                logging.error(f"Error receiving chunk: {str(e)}")
                                break
                    logging.info(f"File download completed. Total size: {file_size}")
                    if self.verify_file_integrity(save_path, file_info['hash']):
                        print(f"File {file_name} successfully downloaded and verified!")
                        self.execute_post_transfer(group_name, file_name, save_path)
                    else:
                        print(f"File {file_name} was downloaded but failed integrity check!")
                else:
                    print(f"Failed to retrieve file: {file_info['message']}")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {str(e)}")

    def distribute_files(self, group_name, file_paths, admin, silent=False, schedule_time=None):
        command = {
            'action': 'distribute_files',
            'group_name': group_name,
            'file_paths': file_paths,
            'admin': admin,
            'silent': silent,
            'schedule_time': schedule_time
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

    def remove_user(self, group_name, user, admin):
        command = {
            'action': 'remove_user',
            'group_name': group_name,
            'user': user,
            'admin': admin
        }
        return self.send_command(command)

    def pause_transfer(self, transfer_id, admin):
        command = {
            'action': 'pause_transfer',
            'transfer_id': transfer_id,
            'admin': admin
        }
        return self.send_command(command)

    def resume_transfer(self, transfer_id, admin):
        command = {
            'action': 'resume_transfer',
            'transfer_id': transfer_id,
            'admin': admin
        }
        return self.send_command(command)

    def abort_transfer(self, transfer_id, admin):
        command = {
            'action': 'abort_transfer',
            'transfer_id': transfer_id,
            'admin': admin
        }
        return self.send_command(command)

    def transfer_progress(self, transfer_id):
        command = {
            'action': 'transfer_progress',
            'transfer_id': transfer_id
        }
        return self.send_command(command)

    def check_offline_transfers(self, user):
        command = {
            'action': 'check_offline_transfers',
            'user': user
        }
        return self.send_command(command)

    def verify_file_integrity(self, file_path, expected_hash):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest() == expected_hash
        except Exception as e:
            logging.error(f"Failed to verify file integrity: {str(e)}")
            return False

    def execute_post_transfer(self, group_name, file_name, file_path):
        print(f"Executing post-transfer actions for {file_name} in group {group_name}")
        # Add your post-transfer logic here
        # For example:
        # if file_name.endswith('.mp3'):
        #     os.system(f"play {file_path}")  # This would play the audio file on Unix-like systems
        # elif file_name.endswith('.py'):
        #     os.system(f"python {file_path}")  # This would execute the Python script

if _name_ == '_main_':
    parser = argparse.ArgumentParser(description="File Distribution CLI")
    parser.add_argument('role', choices=['server', 'client'], help="Run as either server or client")
    parser.add_argument('--port', type=int, default=8080, help="Port number for the server")
    parser.add_argument('--server-host', type=str, default='localhost', help="Server host address for the client")
    parser.add_argument('--server-port', type=int, default=8080, help="Server port for the client")
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
            print("5. Distribute Files")
            print("6. List Groups")
            print("7. Add Admin")
            print("8. Remove User from Group")
            print("9. Pause Transfer")
            print("10. Resume Transfer")
            print("11. Abort Transfer")
            print("12. Check Transfer Progress")
            print("13. Check Offline Transfers")
            print("14. Quit")
            choice = input("Select an option: ").strip()
            
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
                file_paths = input("Enter file paths (comma-separated): ").split(',')
                admin = input("Enter admin name: ")
                silent = input("Silent transfer? (y/n): ").lower() == 'y'
                schedule_time = input("Enter schedule time (HH:MM) or leave blank for immediate: ")
                if not schedule_time:
                    schedule_time = None
                print(client.distribute_files(group_name, file_paths, admin, silent, schedule_time))
            elif choice == '6':
                print(client.list_groups())
            elif choice == '7':
                admin = input("Enter admin name to add: ")
                print(client.add_admin(admin))
            elif choice == '8':
                group_name = input("Enter group name: ")
                user = input("Enter user to remove: ")
                admin = input("Enter admin name: ")
                print(client.remove_user(group_name, user, admin))
            elif choice == '9':
                transfer_id = input("Enter transfer ID: ")
                admin = input("Enter admin name: ")
                print(client.pause_transfer(transfer_id, admin))
            elif choice == '10':
                transfer_id = input("Enter transfer ID: ")
                admin = input("Enter admin name: ")
                print(client.resume_transfer(transfer_id, admin))
            elif choice == '11':
                transfer_id = input("Enter transfer ID: ")
                admin = input("Enter admin name: ")
                print(client.abort_transfer(transfer_id, admin))
            elif choice == '12':
                transfer_id = input("Enter transfer ID: ")
                print(client.transfer_progress(transfer_id))
            elif choice == '13':
                user = input("Enter your name: ")
                print(client.check_offline_transfers(user))
            elif choice == '14':
                print("Exiting...")
                break
            else:
                print("Invalid option. Please try again.")