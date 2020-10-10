import argparse
import subprocess

def get_args():
    #Assign description to help doc
    parser = argparse.ArgumentParser(description='Performs some basic active enumeration tasks')
    #Add arguments
    parser.add_argument(
        '-i', '--ip_address', type=str, help='ip address of target', required=True
        )
    parser.add_argument(
        '-ps', '--ping_sweep', type=str, help='pings all ips across the network range, the argument sets the time(in seconds) to wait for a reply', required=False
        )
    parser.add_argument(
        '-a', '--arp_scan', action='store_true', help='uses arp-scan to return the ip, mac addresses and os of every machine on the network', required=False
    )
    parser.add_argument(
        '-pa', '--ping_arp', type=str, help='pings all ips on the network then uses an arp scan to match them to mac addresses, the argument sets the time(in seconds) to wait for a ping reply'
    )
    parser.add_argument(
        '-p', '--port_scan', action='store_true', help='checks for open ports on ips discovered by ping_arp and returns them with the output'
    )
    parser.add_argument(
        '-d', '--dns_recon', action='store_true', help='when selected, the given ip/address from the -i flag will be used to run the host command'
    )
    #Array for all arguments passed in
    args = parser.parse_args()
    #Assign args to variables then return them
    IP = args.ip_address
    PING_TIMEOUT = args.ping_sweep
    ARP_SCAN = args.arp_scan
    PING_ARP = args.ping_arp
    PORT_SCAN = args.port_scan
    DNS_RECON = args.dns_recon
    return IP, PING_TIMEOUT, ARP_SCAN, PING_ARP, PORT_SCAN, DNS_RECON

#Get args and assing to global values
IP, PING_TIMEOUT, ARP_SCAN, PING_ARP, PORT_SCAN, DNS_RECON = get_args()

#Uses Ping to check all machines on the network for online status, does not work if target blocks ICMP
if PING_TIMEOUT != None:
    HOST_NUMBER_POSITION = IP.rindex('.')
    IP_DOMAIN = IP[0:HOST_NUMBER_POSITION+1]
    for i in range(1,254):
        HOST_NUMBER = IP_DOMAIN+str(i)
        cmd = 'timeout ' + PING_TIMEOUT + ' ping ' + HOST_NUMBER + ' -c 1 | grep "64 bytes from"'
        subprocess.call(cmd, shell=True)

#Simply calls the arp-scan command on the whole network range
if ARP_SCAN == True:
    cmd = 'arp-scan -l'
    subprocess.call(cmd, shell=True)

if PING_ARP != None:
    HOST_NUMBER_POSITION = IP.rindex('.')
    IP_DOMAIN = IP[0:HOST_NUMBER_POSITION+1]

    #Create an array of ips from the ping loop to use in comparison
    PING_IPS = []
    for i in range(1,254):
        HOST_NUMBER = IP_DOMAIN+str(i)
        cmd = 'timeout ' + PING_ARP + ' ping ' + HOST_NUMBER + ' -c 1 | grep "64 bytes from" | grep -Eo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"'
        #continue on error
        try:
            online_ip = subprocess.check_output(cmd, shell=True)
        except:
            continue;
        #removes '\n' from end of each ip
        slashIndex = online_ip.index('\n')
        online_ip = online_ip[0:slashIndex]
        PING_IPS.append(online_ip)

    #Create an array of ips from the ARP command to use in comparison
    ARP_IPS = []
    cmd = 'arp-scan -l | grep -Eo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"'
    process = subprocess.Popen(cmd, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = process.stdout.readlines()
    if len(output) >= 1:
        for line in output:
            #removes '\n' from end of each ip
            slashIndex = line.index('\n')
            line = line[0:slashIndex]
            ARP_IPS.append(line)

    BOTH_IPS = []
    for ip in PING_IPS:
        if ip in ARP_IPS:
            BOTH_IPS.append(ip)

    print "-------------Ip Addresses Discovered With ICMP echo-------------"
    for ip in PING_IPS:
        print ip
    print "-------------Ip Addresses Discovered With arp-scan-------------"
    for ip in ARP_IPS:
        print ip
    print "-------------Ip Addresses Discovered With Both (and ports if using -p)-------------"
    for ip in BOTH_IPS:
        OPEN_PORTS = []
        #scan first 1024 ports on any machine that came up in both scans
        if PORT_SCAN == True:
            for port in range(0,1023):
                try:
                    cmd = 'timeout 0.5 telnet ' + ip + ' ' + str(port) + ' | grep "Connected to"'
                    process = subprocess.Popen(cmd, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    output = process.stdout.readlines()
                except:
                    continue;
                if len(output) >= 1:
                    for line in output:
                        if "Connected" in line:
                            OPEN_PORTS.append(str(port))
                        else:
                            continue;
            print (ip + " has the following ports open: ")
            if len(OPEN_PORTS) == 0:
                print "None"
            else:
                print(', '.join(OPEN_PORTS))

if DNS_RECON == True:
    #get all name servers
    cmd = 'host -t ns ' + IP
    process = subprocess.Popen(cmd, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = process.stdout.readlines()
    if len(output) >= 1:
        NAMES = []
        for line in output:
            if "name server" in line:
                # the + 7 is to account for the word 'server '
                name = line.index('server') + 7
                line = line[name:-1]
                NAMES.append(line)

        #output when no name servers are found
        if len(NAMES) == 0:
            print "No name servers found using " + IP

        #performs a DNS zone transfer for every name server discovered
        for name in NAMES:
            cmd = 'host -l ' + IP + ' ' + name
            print "---------------------DNS Zone Transfer using name server " + name + "---------------------"
            subprocess.call(cmd, shell=True)
