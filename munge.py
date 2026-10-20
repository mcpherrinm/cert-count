import base64
import collections
import csv
import json
import matplotlib.ticker
import matplotlib.pyplot as plt

def read_telemetry():
    raw = open("cert.validation_success_by_ca_2.json").read()
    data = json.loads(raw)

    bins = collections.defaultdict(int)

    for release in data["response"]:
        for bin, value in release["non_norm_histogram"].items():
            bins[int(bin)] += value

    return bins

def read_bin_fingerprints():
    ret = {}
    with open("KnownRootHashes.txt") as hashes:
        for line in hashes:
            if len(line.strip()) == 0:
                continue
            if line.startswith("#"):
                continue
            root, bin_number, rest = line.split(" ", 2)
            ret[int(bin_number)] = base64.b64decode(root)

    return ret

def read_ca_owners():
    CAs = {}
    with open("AllCertificateRecordsCSVFormatv4.csv", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            raw = bytes.fromhex(row["SHA-256 Fingerprint"])
            # Some CA names have extra info after a , or in (, which we cut off
            CAs[raw] = row["CA Owner"].split(",")[0].split("(")[0]
    return CAs


bin_fingerprints = read_bin_fingerprints()
ca_owners = read_ca_owners()

spellings = collections.defaultdict(int)
total = 0

for bin, count in read_telemetry().items():
    if bin in bin_fingerprints:
        fingerprint = bin_fingerprints[bin]
        name = ca_owners[fingerprint]
        spellings[name] += count
        total += count

# CCADB isn't consistent about capitalization of CA names, so merge them
# case-insensitively, using whichever spelling has the most validations
merged = collections.defaultdict(list)
for name, count in spellings.items():
    merged[name.lower()].append((count, name))

CAs = {}
for variants in merged.values():
    CAs[max(variants)[1]] = sum(count for count, _ in variants)

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
top_n = 50

names = []
values = []
for i, (name, count) in enumerate(sorted(CAs.items(), key=lambda kv: kv[1], reverse=True)):
    if count == 0:
        continue
    if i < top_n:
        names += [name]
        values += [count]
    else:
        other += count

if other > 0:
    names += ["Other"]
    values += [other]

names.reverse()
values.reverse()

fig, ax = plt.subplots(figsize=(16, 8))
ax.set_xscale("log")
ax.xaxis.set_major_formatter(human_format)

plt.barh(names, values)
plt.title("Firefox Certificate Validations by CA")
plt.tight_layout()

plt.savefig("CA.svg")
