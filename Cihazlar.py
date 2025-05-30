import socket
import urllib.request
import tkinter as tk
from tkinter import ttk
from scapy.all import ARP, Ether, srp
import datetime
import json

# Cihazları saklamak için bir dosya oluştu<r
def load_devices(filename="devices.json"):
    try:
        with open(filename, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return []

def save_devices(devices, filename="devices.json"):
    with open(filename, "w") as file:
        json.dump(devices, file, indent=4)

def get_mac_vendor(mac):
    try:
        url = f'https://api.macvendors.com/{mac}'
        response = urllib.request.urlopen(url)
        vendor = response.read().decode()
        return vendor
    except:
        return "N/A"

def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    
    devices = load_devices()
    device_dict = {dev['mac']: dev for dev in devices}
    
    for sent, received in result:
        vendor = get_mac_vendor(received.hwsrc)
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            hostname = "N/A"
        
        if received.hwsrc in device_dict:
            device = device_dict[received.hwsrc]
            device['last_detected'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            device['detection_count'] += 1
            device['active'] = 'Yes'
        else:
            devices.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'vendor': vendor,
                'hostname': hostname,
                'first_detected': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'last_detected': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'detection_count': 1,
                'active': 'Yes'
            })
    
    # Güncellenmiş cihazları dosyaya kaydet
    save_devices(devices)
    return devices

def show_devices(devices):
    root = tk.Tk()
    root.title("Ağdaki Cihazlar")

    columns = ('IP Address', 'Device Name', 'MAC Address', 'Network Adapter Company', 'Device Information',
               'User Text', 'IPv6 Address', 'Link Local IPv6 Address', 'First Detected On', 'Last Detected On',
               'Detection Count', 'Active')
    
    tree = ttk.Treeview(root, columns=columns, show='headings')
    
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, anchor=tk.W, width=150)

    for device in devices:
        tree.insert('', tk.END, values=(
            device['ip'], 
            device['hostname'], 
            device['mac'], 
            device['vendor'],
            'N/A',  # Device Information
            'N/A',  # User Text
            'N/A',  # IPv6 Address
            'N/A',  # Link Local IPv6 Address
            device['first_detected'], 
            device['last_detected'], 
            device['detection_count'], 
            device['active']
        ))

    tree.pack(expand=True, fill='both')
    root.mainloop()

# Ağı taramak için IP aralığını belirtin
ip_range = "192.168.1.1/24"
devices = scan_network(ip_range)
show_devices(devices)
