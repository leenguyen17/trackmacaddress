import paramiko
import re
import tkinter as tk
from tkinter import filedialog
from prettytable import PrettyTable
import getpass

def get_vlan_and_ports_for_mac(switch_ip, username, password, mac_address):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(switch_ip, username=username, password=password, look_for_keys=False)

        # Use "show ethernet-switching table" command to get VLANs and ports for the MAC address
        mac_command = f"show ethernet-switching table | match {mac_address}"
        stdin, stdout, stderr = ssh.exec_command(mac_command)
        mac_output = stdout.read().decode()

        # Use regular expressions to find all VLANs and ports for the MAC address
        vlan_pattern = re.compile(r"(\S+)\s+{0}".format(mac_address))
        port_pattern = re.compile(r"(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+")

        vlans = [match.group(1) for match in vlan_pattern.finditer(mac_output)]
        ports = [match.group(2) for match in port_pattern.finditer(mac_output)]

        if vlans and ports:
            result_table = PrettyTable()
            result_table.field_names = ["VLAN", "Switch IP", "Port", "MAC Address"]

            for vlan, port in zip(vlans, ports):
                result_table.add_row([vlan, switch_ip, port, mac_address])

            return result_table.get_string()
        else:
            return f"The MAC address {mac_address} was not found in the MAC address table on {switch_ip}."

    except Exception as e:
        return f"Error: {e}"

    finally:
        ssh.close()
# Read switch IPs from a text file
def read_switch_ips():
    root = tk.Tk()
    root.withdraw()  # Hide the main window

    file_path = filedialog.askopenfilename(
        title="Select File Containing Switch IPs",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )

    return file_path

# Example usage:
file_path = read_switch_ips()
def is_valid_mac_address(mac_address):
    # Regular expression for MAC address format (e.g., "00:1A:2B:3C:4D:5E")
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(mac_pattern.match(mac_address))

# Example usage:
if file_path:
    switch_ips = []  # Placeholder for now, modify accordingly
    username = input("Enter your SSH username: ")
    password = getpass.getpass("Enter your SSH password: ")

    while True:
        mac_address = input("Enter MAC address (or type 'exit' to quit): ")

        if mac_address.lower() == 'exit':
            break

        if not is_valid_mac_address(mac_address):
            print("Invalid MAC address format. Please enter a valid MAC address.")
            continue

        with open(file_path, "r") as file:
            switch_ips = [line.strip() for line in file]

        for switch_ip in switch_ips:
            result = get_vlan_and_ports_for_mac(switch_ip, username, password, mac_address)
            print(result)