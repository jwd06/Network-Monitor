import psutil, socket, time, datetime, json
from collections import defaultdict

#given a connection tell me what protocol type they are using i.e TCP/UDP
def protocol_name(conn):
    if conn.type == socket.SOCK_STREAM:
        return "TCP"
    if conn.type == socket.SOCK_DGRAM:
        return "UDP"
    else:
        return "Other"

#given a proccess ID, tell me the name
def proccess_name(pid):
    try:
        return psutil.Process(pid).name() #creates a proccess object for the running pid
    except psutil.AccessDenied:
        return "Unknown" #Exist gracefully when root privilages are denied
    except psutil.NoSuchProcess:
        return "Unknow" 

def local_address_IPv4(ip):
    return ip in ("127.0.0.1", "::1")

def local_address_IPv6(ip):
    return isinstance(ip, str) and ip.lower().startswith("fe80")

def should_skip_remote_ip(ip, hide_local_IPv4=True, hide_local_IPv6=True):
    if local_address_IPv4(ip) and hide_local_IPv4:
        return True
    elif local_address_IPv6(ip) and hide_local_IPv6:
        return True 
    else:
        return False
    
def snapshot():
    #Creates a deafult dictionary with a default value of 0
    process_counts = defaultdict(int)
    ip_counts = defaultdict(int)
    r_port_counts = defaultdict(int)
    
    #Return system-wide socket connections as a list of named tuple
    conns = psutil.net_connections(kind="inet")
    
    for connections in conns:
        if not connections.raddr: #Ignore connections which does not have a remote addr
            continue

        r_addr, r_port = connections.raddr
        
        if should_skip_remote_ip(r_addr):
            continue
        
        process_counts[proccess_name(connections.pid) if connections.pid else "Unknown"] += 1 #Which app is opening the most connections
        ip_counts[r_addr] += 1 #which server are we talking to the most
        r_port_counts[r_port] += 1 #Analyze any unsual ports
    return process_counts, ip_counts, r_port_counts #just returns the dictionary

def top_n(counts, n=7): #show only the top n netwroks details 
    return (sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n])


def logging_snapshot(process_counts, ip_counts, port_counts):
    #Using dict object to convert from special dict obj defaultdict
    #JSON can only be converted using few python obj
    log_data = {
        "Timestamp" : datetime.datetime.now().isoformat(),
        "Top apps" : top_n(process_counts),
        "Top IPs" : top_n(ip_counts),
        "Top ports" : top_n(port_counts)
        }
    with open("log_data_entry.jsonl", "a") as log_data_file:
        log_data_file.write(json.dumps(log_data) + "\n")

#Simple spike detection based on 3 rules, if current >= min spike allowed to avoid false alarm
#if the prvious == 0  and current >= min
#Or current * multiplier > previous

def spike_detection(current, previous, min_abs=10, multiplier=3):
    spike = []
    for k, curr_count in current.items():
        prev = previous.get(k, 0)
        
        if curr_count >= min_abs and ((prev == 0 and curr_count >= min_abs) or (prev > 0 and curr_count > multiplier * prev)):
            spike.append((k, curr_count, prev))
    return (sorted(spike, key=lambda s: (s[1]/(s[2] + 1e-9), s[1]), reverse=True))

def printer(counts, title, key_width=20, value_width=6):
    print(title)
    print("-" * (key_width * value_width + 5))
    
    for k, v in counts:
        print(f"{str(k):{key_width}} {v:{value_width}}")

def spike_printer(title, items, n=5):
    print(f"SPIKE DETECTED In {title}")
    for k, curr, prev in items: 
        k = str(k)
        multiplier = "new" if prev == 0 else f"x{curr/prev:.1f}"
        print(f"{k:8} {prev:8} {curr:8} multiplier = {multiplier}")
    

def main():
    print("Activate network connections\n")
    
    #Return system-wide socket connections as a list of named tuple
    conns = psutil.net_connections(kind="inet") #TCP/UDP, IPv4, IPv6
    rows = []
    
    #first loop to collect data
    for c in conns:
        if not c.raddr:
            continue # ignore connections which does not have a remote address
        
        #get the proccess name with the given pid
        #not every netwrook connection have a PID
        name_proccess = proccess_name(c.pid) if c.pid else "Unknown"
        name_proto = protocol_name(c)
        
        local_ip, local_port = c.laddr
        remote_ip, remote_port = c.raddr
        
        rows.append((name_proccess, c.pid, name_proto, f"{local_ip} : {local_port}", f"{remote_ip} : {remote_port}", c.status ))
        
        #sort by process name then PID
        #If you have same process name, then sort by PID
        rows.sort(key=lambda x: (x[0], str(x[1])))
        
    #Show only the first 50 rows of the list
    for process, pid, proto, local_ep, remote_ep, status in rows[:50]:
        #Number padding {value:WIDTH}
        print(f"{process:20} pid={str(pid):6} {proto:3} {status:12} {local_ep:22} -> {remote_ep}")
    #summary of total connections shown
    print(f"\nTotal shown: {min(len(rows), 50)}")
    
    prev_proc = {}
    prev_ip = {}
    prev_ports = {}
        
    while True:
        try:
            process_counts, ip_counts, port_counts = snapshot()
        
            logging_snapshot(process_counts, ip_counts, port_counts)
        
            # proc_sorted = sorted(process_counts.items(), key=lambda x: x[1])
            # ip_sorted = sorted(ip_counts.items(), key=lambda x: x[1])
            # port_sorted = sorted(port_counts.items(), key=lambda x: x[1])
            
            printer(top_n(process_counts), "TOP APPS")
            printer(top_n(ip_counts), "TOP IPs")
            printer(top_n(port_counts), "TOP PORTS")
            
            # print("Top Apps\n")
            # for process, counts in proc_sorted:
            #     print(f"{process:15}->{counts}")
            # print("Top IPs\n")
            # for ip, counts in ip_sorted:
            #     print(f"{ip:15}->{counts}")
            # print("Top ports")
            # for ports, counts in port_counts:
            #     print(f"{ports}->{counts}")
        
            # print("-"*50)
            
            spike_proc = spike_detection(process_counts, prev_proc)
            spike_ip = spike_detection(ip_counts, prev_ip)
            spike_ports = spike_detection(port_counts, prev_ports)
            
            if spike_proc or spike_ip or spike_ports:
                
                spike_printer("APPS", spike_proc)
                spike_printer("IPs", spike_ip)
                spike_printer("PORTS", spike_ports)
                # print("Spike Detected!!!")
                
                # for k, curr, prev in spike_proc[:5]:
                #     print(f"[APP] {k:20} Current:{curr:4} Previous:{prev:4}")
                # for k, curr, prev in spike_ip[:5]:
                #     print(f"[IP] {k:20} Current:{curr:4} Previous:{prev:4}")
                # for k, curr, prev in spike_ports[:5]:
                #     print(f"[PORTS] {k:20} Current:{curr:4} Previous:{prev:4}")
            
            #Update previous
            prev_proc = dict(process_counts)
            prev_ip = dict(ip_counts)
            prev_ports = dict(port_counts)
        
            time.sleep(5)
        
        except KeyboardInterrupt:
            print("Program has ended")
            break
         
if __name__ == "__main__":
    main()
        

