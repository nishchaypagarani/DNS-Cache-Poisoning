# 514-DNS-Cache-Poisoning

The project as presented was run on Ubuntu 24.04 VM

the following is needed for the project to work:

mongodb server (needs to be up and running)

The following are the python libraries which can be installed via pip
dnslib
pymongo
scapy

Note that at the start of the program, the victim_dns will print the port at which it will be sending the dns queries, this needs to be copied and pasted into birthday_attack and kaminsky exploit as the dport.
Another requirement to run the project properly is that iface in the attack vector scripts needs to match the loopback interface on the specific machine it's being run on (which can be found using ifconfig on linux)