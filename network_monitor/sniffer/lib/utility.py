import json

OUTPUT_FILE = "packet_log.json"
IP_LOG_FILE = "ip_log.json" 
IP_PROTO_LOG_FILE = "ip_proto_log.json"
IO_LOG_FILE = "io_log.json" 


def save_to_json(entry, path):
    # converti valori non serializzabili
    entry_clean = {k: str(v) if not isinstance(v, (int, float, str, bool, type(None))) else v
                   for k, v in entry.items()}

    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []

    data.append(entry_clean)

    with open(path, "w") as f:
        json.dump(data, f, indent=4)
    return True