from collections import defaultdict
import json

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
