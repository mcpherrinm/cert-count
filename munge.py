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

# ISO 3166-1 alpha-2 codes for the (inconsistently spelled) countries in CCADB
COUNTRY_CODES = {
    "Algeria": "DZ",
    "Australia": "AU",
    "Austria": "AT",
    "Bangladesh": "BD",
    "Belgium": "BE",
    "Brasil": "BR",
    "Brazil": "BR",
    "Bulgaria": "BG",
    "Cabo Verde": "CV",
    "Canada": "CA",
    "Chile": "CL",
    "China": "CN",
    "中国": "CN",
    "Colombia": "CO",
    "Croatia": "HR",
    "Czech Republic": "CZ",
    "Denmark": "DK",
    "Estonia": "EE",
    "Finland": "FI",
    "France": "FR",
    "Germany": "DE",
    "Greece": "GR",
    "Hong Kong Special Administrative Region of the People's Republic of China": "HK",
    "Hungary": "HU",
    "India": "IN",
    "Indonesia": "ID",
    "Ireland": "IE",
    "Israel": "IL",
    "Italy": "IT",
    "Japan": "JP",
    "Latvia": "LV",
    "Lithuania": "LT",
    "Luxembourg": "LU",
    "Malaysia": "MY",
    "Mexico": "MX",
    "Netherlands": "NL",
    "NL": "NL",
    "Norway": "NO",
    "Pakistan": "PK",
    "Poland": "PL",
    "Polska": "PL",
    "Portugal": "PT",
    "Republic of Korea (South Korea)": "KR",
    "Romania": "RO",
    "Saudi Arabia": "SA",
    "Serbia": "RS",
    "Singapore": "SG",
    "Slovakia": "SK",
    "Slovenia": "SI",
    "South Africa": "ZA",
    "Spain": "ES",
    "SPAIN": "ES",
    "España": "ES",
    "Sri Lanka": "LK",
    "Sudan": "SD",
    "Sweden": "SE",
    "Switzerland": "CH",
    "Taiwan (Republic of China)": "TW",
    "Taiwan, Republic of China": "TW",
    "Thailand": "TH",
    "Tunisia": "TN",
    "Turkey": "TR",
    "UAE": "AE",
    "United Kingdom": "GB",
    "United Kingdom of Great Britain and Northern Ireland": "GB",
    "United States": "US",
    "United States of America": "US",
    "US": "US",
    "USA": "US",
    "Uruguay": "UY",
    "Venezuela": "VE",
}

# Business-type suffixes that don't help identify the CA, compared case-insensitively
BUSINESS_SUFFIXES = ["LLC", "nv-sa", "S.A.", "Co.", "GmbH", "Limited", "AG", "Ltd.", "Inc."]

def strip_business_suffix(name):
    for suffix in BUSINESS_SUFFIXES:
        if name.lower().endswith(" " + suffix.lower()):
            return name[:-len(suffix)].strip()
    return name

def read_ca_owners():
    CAs = {}
    with open("AllCertificateRecordsCSVFormatv4.csv", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            raw = bytes.fromhex(row["SHA-256 Fingerprint"])
            # Some CA names have extra info after a , or in (, which we cut off
            name = strip_business_suffix(row["CA Owner"].split(",")[0].split("(")[0].strip())
            country = COUNTRY_CODES[row["Country"]]
            CAs[raw] = (name, country)
    return CAs


bin_fingerprints = read_bin_fingerprints()
ca_owners = read_ca_owners()

spellings = collections.defaultdict(int)
countries = {}
total = 0

for bin, count in read_telemetry().items():
    if bin in bin_fingerprints:
        fingerprint = bin_fingerprints[bin]
        name, country = ca_owners[fingerprint]
        spellings[name] += count
        countries[name.lower()] = country
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
    w.writerow(["CA", "country", "count"])
    for name, count in sorted(CAs.items(), key=lambda kv: kv[1], reverse=True):
        if count > 0:
            w.writerow([name, countries[name.lower()], count])

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
        names += [f"{name} ({countries[name.lower()]})"]
        values += [count]
    else:
        other += count

if other > 0:
    names += ["Other"]
    values += [other]

names.reverse()
values.reverse()

def plot(filename, scale):
    fig, ax = plt.subplots(figsize=(16, 8))
    ax.set_xscale(scale)
    ax.xaxis.set_major_formatter(human_format)

    ax.barh(names, values)
    ax.set_title("Firefox Certificate Validations by CA")
    fig.tight_layout()

    fig.savefig(filename)
    plt.close(fig)

plot("CA.svg", "log")
plot("CA-linear.svg", "linear")
