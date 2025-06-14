import base64
import binascii
import collections
import csv
import json
import pygal

def read_telemetry():
    raw = open("cert.validation_success_by_ca.json").read()
    data = json.loads(raw)

    bins = collections.defaultdict(int)

    for release in data["data"]:
        for entry in release["non_norm_histogram"]:
            bins[entry["bin"]] += entry["value"]

    return bins

def read_bin_fingerprints():
    raw = open("KnownRootHashes.json").read()
    data = json.loads(raw)

    ret = {}
    for root in data["roots"]:
        ret[root["binNumber"]] = base64.b64decode(root["sha256Fingerprint"])

    return ret

def read_ca_owners():
    CAs = {}
    with open("AllCertificateRecordsCSVFormatv2.csv", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            raw = bytes.fromhex(row["SHA-256 Fingerprint"])
            CAs[raw] = row["CA Owner"]
    return CAs


bin_fingerprints = read_bin_fingerprints()
ca_owners = read_ca_owners()

CAs = collections.defaultdict(int)
total = 0

for bin, count in read_telemetry().items():
    if bin in bin_fingerprints:
        fingerprint = bin_fingerprints[bin]
        name = ca_owners[fingerprint]
        CAs[name] += count
        total += count

with open("CA.csv", "w") as f:
    w = csv.writer(f)
    w.writerow(["CA", "count"])
    for name, count in sorted(CAs.items(), key=lambda kv: kv[1], reverse=True):
        if count > 0:
            w.writerow([name, count])

def formatter(entry):
    if entry > 1_000_000_000:
        entry = int(entry/1_000_000_000)
        return f"{entry} B"
    if entry > 1_000_000:
        entry = int(entry/1_000_000)
        return f"{entry} M"
    return f"{entry:,}"

bar_chart = pygal.HorizontalBar(dynamic_print_values=True, pretty_print=True)
bar_chart.title = "Mozilla Handshakes by CA"
bar_chart.value_formatter = formatter
other = 0
threshold = int(0.0002 * total)
print("Graphing entries above threshold", threshold)


for name, count in sorted(CAs.items(), key=lambda kv: kv[1], reverse=True):
    # Skip entries below 0.01:
    if count >  threshold:
        bar_chart.add(name, count)
    else:
        other += count

bar_chart.add("Other", other)
bar_chart.render_to_file("CA.svg")
