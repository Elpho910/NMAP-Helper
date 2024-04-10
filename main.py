import nmap
import pandas as pd
import netifaces
from tkinter import *
from tkinter import messagebox

window = Tk()
window.title("Network Enumerator")
window.config(padx=20, pady=20)

def scan_network(subnet, scan_type):
    
    if scan_type == "Full":
        scan_args = "-sV"
    else:
        scan_args = "-sS -F"
    
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments=scan_args)
    
    columns = ['Host', 'Hostname', 'State', 'Protocol', 'Port', 'Service']
    scan_results_df = pd.DataFrame(columns=columns)
    
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            open_ports = nm[host][proto].keys()
            for port in open_ports:
                row = {
                    'Host': host,
                    'Hostname': nm[host].hostname(),
                    'State': nm[host].state(),
                    'Protocol': proto,
                    'Port': port,
                    'Service': nm[host][proto][port]['name']
                }
                
                scan_results_df = scan_results_df._append(row, ignore_index=True)
    
    return scan_results_df


def get_current_subnet():
    gws = netifaces.gateways()
    default_gateway = gws['default'][netifaces.AF_INET][0]
    interface = gws['default'][netifaces.AF_INET][1]
    
    addrs = netifaces.ifaddresses(interface)
    ip_info = addrs[netifaces.AF_INET][0]
    ip_address = ip_info['addr']
    netmask = ip_info['netmask']
    
    ip_parts = ip_address.split('.')
    mask_parts = netmask.split('.')
    subnet_parts = [str(int(ip_parts[i]) & int(mask_parts[i])) for i in range(4)]
    subnet = '.'.join(subnet_parts) + '/' + str(sum(bin(int(x)).count('1') for x in mask_parts ))
    
    return subnet

def main():
    scanned_subnet = get_current_subnet()
    subnet_label = Label(text=scanned_subnet)
    subnet_label.grid(column=1, row=0, padx=10, pady=10)
    print(f"Detected subnet: {scanned_subnet}")
    scan_type = input("Scan Type, Enter: Quick or Full ")
    print("Scanning... Please Wait...")
    scan_results_df = scan_network(scanned_subnet, scan_type)
    print(scan_results_df)
    
    excel_file_name = 'nmap_scan_results.xlsx'
    
    scan_results_df.to_excel(excel_file_name, index=False)
    
    print(f"Scan complete.  Results saved to {excel_file_name}")




if __name__ == "__main__":
    main()
    
window.mainloop()