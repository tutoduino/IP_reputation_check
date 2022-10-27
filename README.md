A python3 program to check the reputation of a list of IP addresses Initial release is based on information from Shodan, VirusTotal, APIVoid, AbuseIpDb and IpQualityScore. 
Free accounts of these services can be used, but it limits the amount of requests (per minute/day/month). 
API keys (SHODAN_API_KEY; VIRUS_TOTAL_KEY; APIVOID_KEY; ABUSEIPDB_KEY ; IPQS_KEY) must be stored in the .env file. 
Main program reads the IP addresses from stdin, CSV and PCAP files parsers are available

Usage for manual entry of IP list: $echo "8.8.8.8" | python3 ip_reputation_check.py
Usage with PCAP file: $python3 parse_pcap.py pcap_file.pcapng | python3 ip_reputation_check.py
Usage with CVS file (";" separator): $python3 parse_ip_csv.py csv_file.csv | python3 ip_reputation_check.py

Example:
$echo "139.162.99.243" | python3 ip_reputation_check.py
139.162.99.243 is a public IP address
Shodan           -> Number of open ports: 1
Shodan           -> Hostnames: ['scan-42.security.ipip.net']
AbuseIpDb        -> Number of reports: 2343
AbuseIpDb        -> Confidence of Abuse: 100
ApiVoid          -> Risk score: 100
ApiVoid          -> Detection rate: 14%
VirusTotal       -> Number of reports saying it is malicious: 3
VirusTotal       -> Number of reports saying it is suspicious: 0
VirusTotal       -> Reputation (<0 is suspicious): 0
VirusTotal       -> Harmless votes: 0
VirusTotal       -> Malicious votes: 0
IpQualityScore   -> Fraud score (>75 is suspicious): 100
IpQualityScore   -> Bot activity: True
IpQualityScore   -> VPN status: True
IpQualityScore   -> Proxy status: True
IpQualityScore   -> Tor status: False
