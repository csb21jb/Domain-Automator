import subprocess
import argparse
import os
import re
import glob
import time
import urllib.request
import socket

def print_banner():
    print(r"""

  _____                        _                         _                        _
 |  __ \                      (_)             /\        | |                      | |
 | |  | | ___  _ __ ___   __ _ _ _ __        /  \  _   _| |_ ___  _ __ ___   __ _| |_ ___  _ __
 | |  | |/ _ \| '_ ` _ \ / _` | | '_ \      / /\ \| | | | __/ _ \| '_ ` _ \ / _` | __/ _ \| '__|
 | |__| | (_) | | | | | | (_| | | | | |    / ____ \ |_| | || (_) | | | | | | (_| | || (_) | |
 |_____/ \___/|_| |_| |_|\__,_|_|_| |_|   /_/    \_\__,_|\__\___/|_| |_| |_|\__,_|\__\___/|_|

           🔍 A Unified DNS Recon Tool by CB 🔍
    """)


def download_file(url, dest):
    if not os.path.exists(dest):
        print(f"Downloading {dest} from {url}...")
        try:
            urllib.request.urlretrieve(url, dest)
            print("Download complete.\n")
        except Exception as e:
            print(f"Error downloading {dest}: {e}")
    else:
        print(f"{dest} already exists.\n")

def run_command(cmd, out_file=None):
    print(f"▶ Running: {cmd}")
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, encoding='utf-8')
        if out_file:
            with open(out_file, 'a') as f:
                f.write(result)
        return result
    except subprocess.CalledProcessError:
        return ""

def run_dig(domain, axfr_server):
    # Perform a DNS zone transfer (AXFR)
    return run_command(f"dig axfr {domain} @{axfr_server} +all", out_file=f"{domain}_temp.txt")

def run_dnsrecon(domain):
    return run_command(f"dnsrecon -d {domain} -a", out_file=f"{domain}_dnsrecon.txt")

def run_dnsenum(domain):
    return run_command(f"dnsenum {domain}", out_file=f"{domain}_dnsenum.txt")

def run_massdns(domain, wordlist_file, resolvers_file):
    out_file = f"{domain}_massdns.txt"
    cmd = f"massdns -r {resolvers_file} -t A -o S -w {out_file} {wordlist_file} -q {domain}"
    return run_command(cmd)

def run_theharvester(domain):
    out_file = f"{domain}_theharvester.txt"
    cmd = f"theHarvester -d {domain} -b all"
    print(f"▶ Running TheHarvester: {cmd}")
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, encoding='utf-8')
        with open(out_file, 'w') as f:
            f.write(result)
        print(f"✔ TheHarvester output saved to {out_file}")
        return result
    except subprocess.CalledProcessError as e:
        print(f"Error running TheHarvester: {e}")
        return ""

def extract_subdomains_from_text(filepath, domain):
    # Regex to match subdomains ending with the target domain.
    pattern = re.compile(r"([\w\.-]+\." + re.escape(domain) + r")\b")
    with open(filepath, 'r') as f:
        return set(re.findall(pattern, f.read()))

def generate_subdomains_wordlist(domain):
    """
    Generate a subdomains wordlist (subdomains.txt) based on dnsrecon output.
    """
    dnsrecon_file = f"{domain}_dnsrecon.txt"
    if not os.path.exists(dnsrecon_file):
        print(f"{dnsrecon_file} not found! Cannot generate wordlist from dnsrecon.")
        return []

    subdomains = set()
    pattern = re.compile(r"([\w\.-]+\." + re.escape(domain) + r")\b")
    with open(dnsrecon_file, "r") as f:
        for line in f:
            matches = pattern.findall(line)
            subdomains.update(matches)

    with open("subdomains.txt", "w") as out_file:
        for sub in sorted(subdomains):
            out_file.write(f"{sub}\n")
    print(f"Subdomain wordlist saved to subdomains.txt with {len(subdomains)} entries.")
    return list(subdomains)

def consolidate_output(domain):
    """
    Consolidate subdomain outputs from various tools into a single deduplicated file.
    """
    subdomains = set()

    # Combine outputs from dnsrecon, dnsenum, TheHarvester, and the dig AXFR result.
    for file_pattern in [f"{domain}_dns*.txt", f"{domain}_theharvester.txt"]:
        for filename in glob.glob(file_pattern):
            subdomains.update(extract_subdomains_from_text(filename, domain))

    if os.path.exists(f"{domain}_temp.txt"):
        subdomains.update(extract_subdomains_from_text(f"{domain}_temp.txt", domain))

    # Add massdns results (assuming the first field is a subdomain)
    massdns_file = f"{domain}_massdns.txt"
    if os.path.exists(massdns_file):
        with open(massdns_file, 'r') as f:
            for line in f:
                if line and line[0] != ';':
                    subdomain = line.split()[0].rstrip('.')
                    subdomains.add(subdomain)

    final_output = f"{domain}_all_subdomains.txt"
    with open(final_output, 'w') as f:
        for sub in sorted(subdomains):
            f.write(f"{sub}\n")
    print(f"✅ Combined subdomains saved to {final_output}")

def consolidate_all_info(domain):
    """
    Consolidate all discovered information (IP addresses, emails, hostnames) from tool outputs into one file.
    """
    info = ""
    files_to_parse = [
        f"{domain}_dnsrecon.txt",
        f"{domain}_dnsenum.txt",
        f"{domain}_temp.txt",
        f"{domain}_massdns.txt",
        f"{domain}_theharvester.txt",
        "subdomains.txt"
    ]

    for filepath in files_to_parse:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                info += f.read() + "\n"

    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    email_pattern = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    hostname_pattern = re.compile(r"\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})\b")

    ips = set(ip_pattern.findall(info))
    emails = set(email_pattern.findall(info))
    hosts = set(host for host in hostname_pattern.findall(info)
                if host not in ips and '@' not in host)

    final_file = f"{domain}_all_info.txt"
    with open(final_file, 'w') as f:
        f.write("=== IP Addresses ===\n")
        for ip in sorted(ips):
            f.write(f"{ip}\n")
        f.write("\n=== Emails ===\n")
        for email in sorted(emails):
            f.write(f"{email}\n")
        f.write("\n=== Hostnames ===\n")
        for host in sorted(hosts):
            f.write(f"{host}\n")

    print(f"✅ Consolidated info (IPs, Emails, Hostnames) saved to {final_file}")

def cleanup_intermediate_files(domain):
    """
    Remove intermediate output files, leaving only the final consolidated files.
    """
    files_to_remove = [
        f"{domain}_temp.txt",
        f"{domain}_dnsrecon.txt",
        f"{domain}_dnsenum.txt",
        f"{domain}_theharvester.txt",
        f"{domain}_massdns.txt",
        "subdomains.txt"
    ]
    for filepath in files_to_remove:
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                print(f"Removed intermediate file: {filepath}")
            except Exception as e:
                print(f"Could not remove {filepath}: {e}")

def is_ip(s):
    try:
        socket.inet_aton(s)
        return True
    except socket.error:
        return False

def get_domain_and_axfr_server(target):
    """
    Given a target (domain or IP), determine:
      - Domain: via reverse lookup (if target is an IP) or use it as provided.
      - AXFR server: if domain, get an authoritative nameserver; if IP, use it directly.
    Returns a tuple (domain, axfr_server).
    """
    if is_ip(target):
        try:
            host_info = socket.gethostbyaddr(target)
            domain = host_info[0]
            print(f"Reverse lookup found domain: {domain}")
        except socket.herror:
            print("Reverse DNS lookup failed; using the provided IP as domain.")
            domain = target
        axfr_server = target
    else:
        domain = target
        ns_records = run_command(f"dig ns {domain} +short").splitlines()
        if ns_records:
            try:
                axfr_server = socket.gethostbyname(ns_records[0])
                print(f"Using authoritative nameserver: {ns_records[0]} ({axfr_server})")
            except socket.gaierror:
                print("Error resolving NS record; defaulting to 8.8.8.8")
                axfr_server = "8.8.8.8"
        else:
            print("No NS records found; defaulting AXFR server to 8.8.8.8")
            axfr_server = "8.8.8.8"
    return domain, axfr_server

def main(target):
    # Determine domain and AXFR server from the single target argument.
    domain, axfr_server = get_domain_and_axfr_server(target)
    print_banner()
    time.sleep(2)

    # Step 1: Run DNS zone transfer using dig.
    run_dig(domain, axfr_server)

    # Step 2: Run DNS recon tools.
    run_dnsrecon(domain)
    run_dnsenum(domain)

    # Step 3: Run TheHarvester.
    run_theharvester(domain)

    # Step 4: Auto-generate a subdomain wordlist from dnsrecon output.
    generate_subdomains_wordlist(domain)

    # Step 5: Download resolver file from updated URL.
    resolvers_url = "https://raw.githubusercontent.com/blechschmidt/massdns/refs/heads/master/lists/resolvers.txt"
    download_file(resolvers_url, "resolvers.txt")

    # Step 6: Run massdns using the auto-generated wordlist.
    run_massdns(domain, "subdomains.txt", "resolvers.txt")

    # Step 7: Consolidate subdomain outputs.
    consolidate_output(domain)

    # Step 8: Consolidate all info (IPs, emails, hostnames) into one file.
    consolidate_all_info(domain)

    # Final step: Clean up all intermediate files.
    cleanup_intermediate_files(domain)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unified DNS Recon Scanner")
    parser.add_argument("target", type=str, help="Target domain or IP (e.g., socom.com or 8.8.8.8)")
    args = parser.parse_args()
    main(args.target)
