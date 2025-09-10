from collections import defaultdict
import json

with open("dns_log.json") as f:
    packets = json.load(f)

traffic_per_ip = defaultdict(int)
for p in packets:
    traffic_per_ip[p["src"]] += p["size"]
    traffic_per_ip[p["dst"]] += p["size"]

print(traffic_per_ip)

traffic_proto = defaultdict(lambda: defaultdict(int))

for p in packets:
    proto = p.get("proto_name", "UNKNOWN")
    src = p["src"]
    traffic_proto[src][proto] += p["size"]

print(traffic_proto)

from collections import Counter

sport_counter = Counter()
dport_counter = Counter()

for p in packets:
    if "sport" in p: sport_counter[p["sport"]] += 1
    if "dport" in p: dport_counter[p["dport"]] += 1

print("Porte sorgente più comuni:", sport_counter.most_common(10))
print("Porte destinazione più comuni:", dport_counter.most_common(10))

dns_queries = Counter()

for p in packets:
    if "dnsquery" in p:
        dns_queries[p["dnsquery"]] += 1

print(dns_queries.most_common(10))
