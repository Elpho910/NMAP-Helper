import nmap
import pandas as pd
import netifaces


def scan_network(subnet):
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-sV')
    
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
    subnet = get_current_subnet()
    print(f"Detected subnet: {subnet}")
    network = input("Enter IP/Subnet to scan: ")
    print("Scanning... Please Wait...")
    scan_results_df = scan_network(network)
    
    excel_file_name = 'nmap_scan_results.xlsx'
    
    scan_results_df.to_excel(excel_file_name, index=False)
    
    print(f"Scan complete.  Results saved to {excel_file_name}")


if __name__ == "__main__":
    main()