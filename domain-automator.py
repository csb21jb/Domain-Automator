import os


def print_banner():
    print(r"""
   ____                        _                         _                        _             
 |  __ \                      (_)             /\        | |                      | |            
 | |  | | ___  _ __ ___   __ _ _ _ __        /  \  _   _| |_ ___  _ __ ___   __ _| |_ ___  _ __ 
 | |  | |/ _ \| '_ ` _ \ / _` | | '_ \      / /\ \| | | | __/ _ \| '_ ` _ \ / _` | __/ _ \| '__|
 | |__| | (_) | | | | | | (_| | | | | |    / ____ \ |_| | || (_) | | | | | | (_| | || (_) | |   
 |_____/ \___/|_| |_| |_|\__,_|_|_| |_|   /_/    \_\__,_|\__\___/|_| |_| |_|\__,_|\__\___/|_|   
    """)
    print("\nWritten by CB")
    print("\nA Domain Enumeration Tool based on the Harvester tool by Christian Martorella")
    print("\nVersion 1.0\n")
 
print_banner()

# Get the target domain from the user
print("For example: facebook.com or google.com")
target_domain = input("Enter the target domain to scan: ")

# List of sources
sources = [
    "baidu", "bufferoverun", "crtsh", "hackertarget",
    "otx", "projectdiscovery", "rapiddns", "sublist3r",
    "threatcrowd", "trello", "urlscan", "vhost", "virustotal", "zoomeye"
]

# Create a directory to store JSON files
print("Creating a directory to save the files")
if not os.path.exists(f"{target_domain}_output"):
    os.mkdir(f"{target_domain}_output")

# Loop through sources and run theHarvester
for source in sources:
    output_filename = f"{target_domain}_output/{source}_{target_domain}.json"
    command = f"theHarvester -d {target_domain} -b {source} -f {output_filename}"
    os.system(command)

# Concatenate and process JSON files
os.system(f"cat {target_domain}_output/*.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > {target_domain}_subdomains.txt")

# Look for subdomains with an 
print("Looking for subdomains with an IP address that has a : in it")
os.system(f"cat {target_domain}_output/*.json | jq -r '.hosts[]' 2>/dev/null | grep -E ':.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > {target_domain}_subdomains_with_IP.txt")

# Remove the JSON files and the folder in the {target_domain}_output directory
print("Removing the JSON files")
os.system(f"rm -rf {target_domain}_output")




print("Subdomain harvesting and merging completed.")

