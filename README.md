# scouter
A command line python script for linux. A multipurpose tool for basic active enumeration tasks. Useful for penetration testing.

Requirements:
Python
arp-scan
telnet
host

Usage:
The -i (--ip_address) flag is required and is followed by the target ip. 
The -ps (--ping_sweep) flag takes a time value as an argument (in seconds), the time represents the amount of time to wait before each ping request times out. The entire domain of addresses from 0-255 is pinged and those who respond have their ip outputted.
The -a (--arp_scan) flag performs an arp-scan on the target ip, returning the ip, mac address and os of all machines that respond.
The -pa (--ping_arp) flag performs the ping sweep and the arp scan, returns the ip addresses found by each and the ip addresses found by both. Takes the same time argument as the ping sweep command.
The -p (--port_scan) is to be used alongisde the -pa flag. When used, ip addresses found by both the ping sweep and arp-scan are scanned for open ports on the port range 0-1023.
The -d (--dns_recon) flag performs a zone transfer on all name servers found by a host scan.
