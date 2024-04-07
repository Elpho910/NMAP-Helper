import nmap
import pandas as pd


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
    
def main():
    network = input("Enter IP/Subnet to scan: ")
    print("Scanning... Please Wait...")
    scan_results_df = scan_network(network)
    
    excel_file_name = 'nmap_scan_results.xlsx'
    
    scan_results_df.to_excel(excel_file_name, index=False)
    
    print(f"Scan complete.  Results saved to {excel_file_name}")


if __name__ == "__main__":
    main()