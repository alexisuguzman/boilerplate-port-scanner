import socket
import common_ports
import re

def get_open_ports(target, port_range, verbose = False):
    print(f"Scanning port range: {port_range} on target: {target}")
    open_ports = []

    url = None
    ip_address = None

    # Regex pattern for validating IPv4 addresses
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if pattern.match(target):
        print("matched ip")
        is_ip = True
    else: 
        is_ip = False
    
    # Try to process as ip      
    if is_ip == True:
        ip_address = target
        try:
            url = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            url = ""
        except socket.error:
            return "Error: Invalid IP address"
    else:
        # If not an IP, try resolving it as a hostname
        try:
            url = target
            ip_address = socket.gethostbyname(url)
        except socket.error:
            return "Error: Invalid hostname"

    for port in range(port_range[0], port_range[1] + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        print(f"scanning port: {port}")
        if s.connect_ex((target, port)):
            s.close()
            continue
        else:
            open_ports.append(port)
            s.close()

    services = common_ports.ports_and_services

    if verbose == True:
        if url == "": 
            url_and_ip = f"{ip_address}"
        else:
            url_and_ip = f"{url} ({ip_address})"

        verbose_output = f"Open ports for {url_and_ip}\n" + "PORT     SERVICE"
        for port in open_ports:
            service = services.get(port, "unknown")
            verbose_output += f'\n{port:<9}' + f"{service}" 

        return(verbose_output)
        


    return(open_ports)
