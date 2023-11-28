#!/bin/python3

import csv              # Import csv file
import telnetlib        # Telnet to devices
import re               # Regex for search remote hostname
import threading        # Multithread process
import getpass          # Prompt for username, password & enable 
import sys              # Get arguments 

def telnet_cisco_device(ip_addr, username, password, enable_password, cmd_file):
    try:
        # Connect to the device
        tn = telnetlib.Telnet(ip_addr)
        
        # Enter username
        tn.read_until(b"Username: ")
        tn.write(username.encode('ascii') + b"\n")
        
        # Enter password
        tn.read_until(b"Password: ")
        tn.write(password.encode('ascii') + b"\n")
        
        
        # Enter enable mode
        tn.read_until(b">")
        tn.write(b"enable\n")
        tn.read_until(b"Password: ")
        tn.write(enable_password.encode('ascii') + b"\n")
        tn.read_until(b"#", timeout=5)
        
        # cmds = [ 
        #     'conf t',
        #     'ip access-list resequence POS-IN 10 10',
        #     'ip access-list resequence POS-OUT 10 10',
        #     'ip access-list extended POS-IN',
        #     '5 permit tcp any range 5900 5901 any',
        #     'ip access-list extended POS-OUT',
        #     '5 permit tcp any any range 5900 5901',
        #     'ip access-list resequence POS-IN 10 10',
        #     'ip access-list resequence POS-OUT 10 10',
        #     'end',
        #     'wr'
        # ]

        try:
            with open(cmd_file,'r') as cmds:

                for cmd in cmds:
                    c = cmd.strip()
                    tn.write(c.encode('ascii') + b"\n")
                    tn.read_until(b"#", timeout=5).decode('ascii')

        except Exception as e:
            print(f"Error: {e}")
            

        ########## GET HOSTNAME ##########

        # Send the command to get the hostname
        tn.write("show running-config | include hostname".encode('ascii') + b"\n")

        # Wait for the command to execute and capture the output
        output = tn.read_until(b"#",timeout=5).decode('ascii')

        # print(f"Output: {output}")

       # Extract the hostname from the output
        match = re.search(r"hostname ([\w.#-]+)", output)
        if match:
            hostname = match.group(1)
            print(f"ACL for {hostname} with IP {ip_addr} has been configured successfully!")
        else:
            print(f"Hostname not found for {ip_addr}.")


        tn.write(b"q\n")
        # Close the connection
        tn.close()
        
        
    
    except Exception as e:
        print(f"Error: {e}")

def read_csv_file(file_path,username,password,enable_password,cmd_file):
    try:
        with open(file_path, 'r') as csv_file:
            csv_reader = csv.reader(csv_file)
            
            # Assuming the first row of the CSV file contains headers
            headers = next(csv_reader)
            
            # Loop through each row in the CSV file
            for row in csv_reader:

                # Replace with your username, password and enable_password 
                # username = "your_username"
                # password = "your_password"
                # enable_password = "your_enable_password"

                # Create threads for each Telnet connection

                threads = []
                for host in row:
                    thread = threading.Thread(target=telnet_cisco_device, args=(host, username,password,enable_password,cmd_file))
                    threads.append(thread)

                # Start all threads
                for thread in threads:
                    thread.start()

                # Wait for all threads to finish
                for thread in threads:
                    thread.join()

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":

    device_file_list = sys.argv[1]
    cmd_file = sys.argv[2]

    username = input("Username: ")
    password = getpass.getpass("Password: ")
    enable_password = getpass.getpass("Enable password: ")

    # Replace 'your_file.csv' with the actual path to your CSV file
    # csv_file_path = 'iplist_example.csv'
    # cmd_file = 'cisco_cmd.txt'
    read_csv_file(device_file_list,username,password,enable_password,cmd_file)
