# File_Distribution_System

A robust and secure file distribution system built with Python, enabling efficient file sharing among groups. This tool supports group creation, file distribution, retrieval, and integrity verification using encryption and hash-based verification.
There are 2 classes implemented- one for server side and another for client.

There are 3 versions included:
version1-
version2- 
version3-
To run the server
Execute the command-  python file_dist.py server --port 5000

To run the client-
python file_dist.py client --server-host localhost --server-port 5000

Extra Feautres:
1. Remove user from group access given to admin 
2. Silent transfer whether the user should be notified or not of the file sent
3. Transfer progress for large file transfer
4. Offline transfers for user to check whether any notification came when they were offline
5. Scheduled time for transfer
