import json
import argparse
import os

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Convert a hosts file into a single-rule Little Snitch .lsrules file")
parser.add_argument("input", help="Path to the input hosts file")
parser.add_argument("-o", "--output", help="Path for output .lsrules file (default: blocklist.lsrules)", default="blocklist.lsrules")
args = parser.parse_args()

input_file = args.input
output_file = args.output

if not os.path.isfile(input_file):
    print(f"Error: Input file '{input_file}' does not exist.")
    exit(1)

domains = set()  # Use a set to remove duplicates

with open(input_file, "r") as f:
    for line in f:
        line = line.strip()
        if line == "" or line.startswith("#"):
            continue
        domains.add(line)

# Create a single deny rule for all domains
rule = {
    "action": "deny",
    "remote-domains": sorted(list(domains)),
    "processes": ["Any Process"],
    "ports": ["Any Port"],
    "protocols": ["Any"],
    "direction": "Any",
    "comment": "Imported from hosts file"
}

with open(output_file, "w") as f:
    json.dump([rule], f, indent=2)

print(f"Converted {len(domains)} unique domains from '{input_file}' into a single-rule '{output_file}'")

