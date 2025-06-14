import base64
import collections
import csv
import json
import matplotlib.ticker
import matplotlib.pyplot as plt

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
            # Some CA names have extra info after a , or in (, which we cut off
            CAs[raw] = row["CA Owner"].split(",")[0].split("(")[0]
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

@matplotlib.ticker.FuncFormatter
def human_format(num, pos):
    magnitude = 0
    while abs(num) >= 1000:
        magnitude += 1
        num /= 1000
    return '%.0f%s' % (int(num), ['', 'K', 'M', 'B'][magnitude])

other = 0
threshold = int(0.0002 * total)

names = []
values = []
for name, count in sorted(CAs.items(), key=lambda kv: kv[1], reverse=True):
    # Skip entries below 0.01:
    if count >  threshold:
        names += [name]
        values += [count]
    else:
        other += count

names += ["Other"]
values += [other]

names.reverse()
values.reverse()

fig, ax = plt.subplots(figsize=(16, 8))
ax.xaxis.set_major_formatter(human_format)

plt.barh(names, values)
plt.title("Firefox Certificate Validations by CA")
plt.tight_layout()

plt.savefig("CA.svg")
