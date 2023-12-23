
  
  _____                        _                         _                        _             
 |  __ \                      (_)             /\        | |                      | |            
 | |  | | ___  _ __ ___   __ _ _ _ __        /  \  _   _| |_ ___  _ __ ___   __ _| |_ ___  _ __ 
 | |  | |/ _ \| '_ ` _ \ / _` | | '_ \      / /\ \| | | | __/ _ \| '_ ` _ \ / _` | __/ _ \| '__|
 | |__| | (_) | | | | | | (_| | | | | |    / ____ \ |_| | || (_) | | | | | | (_| | || (_) | |   
 |_____/ \___/|_| |_| |_|\__,_|_|_| |_|   /_/    \_\__,_|\__\___/|_| |_| |_|\__,_|\__\___/|_|   



 
                                                                                                
# Domain-Automator

A tool for automated subdomain discovery and analysis!

## Summary
SubdomainHarvester automates the process of finding subdomains of a given domain. It queries various sources to gather subdomains, saves the results in JSON files, and processes them to extract unique subdomain names. This tool is designed to streamline the reconnaissance phase of penetration testing or cybersecurity assessments.

## Features

- **Subdomain Discovery**: Gathers subdomains from multiple sources like Baidu, VirusTotal, ThreatCrowd, etc.
- **JSON Data Management**: Saves and processes JSON files for each source.
- **IP Address Filtering**: Extracts subdomains that have specific IP address formats.
- **File Management**: Organizes output into text files for easy analysis.

## Requirements
- Python 3
- TheHarvester tool
- jq for JSON processing

## Installation
To use SubdomainHarvester, ensure you have Python 3 and TheHarvester installed on your system.

```bash
sudo apt update -y
sudo apt upgrade -y
sudo apt install python3 theharvester jq -y
```

## USAGE
```
python SubdomainHarvester.py
```
## OUTPUT
- JSON files for each source are saved in a directory named after the target domain.
- A consolidated list of unique subdomains is saved in a text file.
- Subdomains with specific IP formats are saved in a separate text file.

## Upcoming Features
- Enhanced parsing for more efficient subdomain extraction.
- Additional sources for subdomain discovery.
- Automated installation script.
- Improved error handling and reporting.
