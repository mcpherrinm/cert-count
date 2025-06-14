import collections
import csv
import json

def read_telemetry():
    raw = open("cert.validation_success_by_ca.json").read()
    data = json.loads(raw)

    bins = collections.defaultdict(int)

    for release in data["data"]:
        for entry in release["non_norm_histogram"]:
            bins[entry["bin"]] += entry["value"]

    return bins

def read_bin_names():
    raw = open("KnownRootHashes.json").read()
    data = json.loads(raw)

    bin_names = {}

    for root in data["roots"]:
        bin_names[root["binNumber"]] = root["label"]

    return bin_names


bin_names = read_bin_names()

CAs = collections.defaultdict(int)

for bin, count in read_telemetry().items():
    if bin in bin_names:
        # This is pretty crappy but mostly works for merging roots by CA
        name = "_".join(bin_names[bin].split("_", 2)[0:2])
        CAs[name] += count

with open("CA.csv", "w") as f:
    w = csv.writer(f)
    w.writerow(["CA", "count"])
    for name, count in sorted(CAs.items(), key=lambda kv: kv[1], reverse=True):
        if count > 0:
            w.writerow([name, count])
