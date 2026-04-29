import json
from collections import defaultdict

log_path = "log_data_entry.jsonl"

def read(path):
    entries = [] #jsonl file inside the list
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
    return entries

def aggregate_counts(entries, file_name):
    total = defaultdict(int)
    
    for e in entries: #jsonl file in the list
        d = e.get(file_name, None)
        if d is None :
            continue

        #older logs which are in dict formate
        if isinstance(d, dict): 
            for k, v in d.items():
                total[str(k)] += int(v)

        #newer logs which are in list format
        elif isinstance(d, list):
            for item in d:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    k, v = item
                    total[str(k)] += int(v)

    return dict(total)

def top_n(data, n=5):
    if isinstance(data, dict):
        items = list(data.items())
    elif isinstance(data, list):
        items = [(k, v) for k, v in data]
    
    items.sort(key=lambda kv: kv[1], reverse=True)
    return items[:n]

def print_top(title, items, n=5, key_width=22):
    print(title)
    print("-" * (key_width + 12))

    for k, v in items[:n]:
        print(f"{str(k):{key_width}} {int(v):>6}")

    print()

def main():
    entries = read(log_path)
    if not entries:
        print("No data")
        return
    
    apps_total = aggregate_counts(entries, "Top apps")
    ips_total = aggregate_counts(entries, "Top IPs")
    ports_total = aggregate_counts(entries, "Top ports")
    
    print("Time range:", entries[0].get("Timestamp"), "-", entries[-1].get("Timestamp"),"\n")

    print_top("Top apps", top_n(apps_total, 10))
    print_top("Top IPs", top_n(ips_total, 10))
    print_top("Top Ports", top_n(ports_total, 10))
    
    #print(f"Entries read: {len(entries)} \n")
    #print("Top apps overall:", top_n(apps_total, 8), "\n")
    #print("Top IPs overall :", top_n(ips_total, 8), "\n")
    #print("Top ports overall:", top_n(ports_total, 8), "\n")

    

if __name__ == "__main__":
    main()    
