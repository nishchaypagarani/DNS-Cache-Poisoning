import socket
import random
from dnslib import DNSRecord
from dnslib import DNSHeader
from dnslib import DNSQuestion
from dnslib import RR
from dnslib import RD
from dnslib import A
from dnslib import SOA
from pymongo import MongoClient
from datetime import datetime



mongo_client = MongoClient("mongodb://localhost:27017/")

mongo_db = mongo_client.victim_dns
mongo_db.dns_records.create_index("date", expireAfterSeconds=120)

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.bind(('', 0))
print(client.getsockname())

print(mongo_db.list_collection_names())

def check_db(qname):
        # self.rname = rname
        # self.rtype = rtype
        # self.rclass = rclass
        # self.ttl = ttl
    # rr = mongo_db.dns_records.find_one({"name": qname})
    # if rr:
    #     return DNSRecord.parse(rr["record"])
    # else:
    #     return None
    rr = mongo_db.dns_records.find({"qname": qname, "section": "ANSWER"})
    auth = mongo_db.dns_records.find({"qname": qname, "section": "AUTH"})
    additional = mongo_db.dns_records.find({"qname": qname, "section": "ADDITIONAL"})
    print(rr,auth,additional)
    rrL = []
    for i in rr:
        print("i: ", qname, " data: ", i["data"])
        rrL.append(RR(rname=i["name"], rtype=i["type"], rclass=i["class"], rdata=A(data=i["data"])))
    authL = []
    for i in auth:
        authL.append(RR(rname=i["name"], rtype=i["type"], rclass=i["class"],  rdata=SOA(i["mname"],i["rname"],i["times"])))
    additionalL = []
    for i in additional:
        additionalL.append(RR(rname=i["name"], rtype=i["type"], rclass=i["class"], rdata=SOA(i["mname"],i["rname"],i["times"])))
    if len(rrL) > 0 or len(authL) > 0 or len(additionalL) > 0:
        print("*********Found records*********")
        print(rrL, authL, additionalL)
        return DNSRecord(rr = rrL, auth= authL, ar=additionalL)
    else:
        return None

def add_to_DB(qname,records: DNSRecord):
    print("Add To DB: ", qname)
    print("Records: ", records)
    dbList = []
    for i in records.rr:
        dbList.append({"qname":qname,"name": i.get_rname().label, "type": i.rtype, "class": i.rclass, "data": i.rdata.toZone().strip(), "section": "ANSWER"})
    for i in records.auth:
        dbList.append({"qname":qname,"name": i.get_rname().label, "type": i.rtype, "class": i.rclass, "mname": i.rdata.mname.label, "rname": i.rdata.rname.label, "times": i.rdata.times, "section": "AUTH"})
    for i in records.ar:
        dbList.append({"qname":qname,"name": i.get_rname().label, "type": i.rtype, "class": i.rclass, "mname": i.rdata.mname.label, "rname": i.rdata.rname.label, "times": i.rdata.times, "section": "ADDITIONAL"})
    if len(dbList)>0:
        mongo_db.dns_records.insert_many(dbList)



def unbound_dns_bailiwick(qname, records: DNSRecord):
    rr = []
    for i in records.rr:
        if(i.rname == qname):
            rr.append(i)
    return DNSRecord(rr=rr)

def no_bailiwick(qname, records: DNSRecord):
    return records


def unbound_query(qname):
    forward_addr = ("8.8.8.8", 53) # dns and port
    ri = random.randint(0,100)
    q = DNSRecord(header=DNSHeader(id=ri), q=DNSQuestion(qname=qname))
    print(client.getsockname())
    client.sendto(bytes(q.pack()), forward_addr)
    data, _ = client.recvfrom(512)
    print("Data \n", data)
    d = DNSRecord.parse(data)
    valid_records = unbound_dns_bailiwick(qname, d)
    print("Valid Records ",valid_records)
    print("\n\n")
    add_to_DB(qname, d)
    # mongo_db.dns_records.insert_one({"name": qname, "record": valid_records.pack()})
    print("\n\n\n", d)
    return valid_records.format()

def no_bailiwick_query(qname):
    forward_addr = ("8.8.8.8", 53) # dns and port
    ri = random.randint(0,100)
    q = DNSRecord(header=DNSHeader(id=ri), q=DNSQuestion(qname=qname))
    print(client.getsockname())
    client.sendto(bytes(q.pack()), forward_addr)
    data, _ = client.recvfrom(512)
    d = DNSRecord.parse(data)
    valid_records = no_bailiwick(qname, d)
    add_to_DB(qname, valid_records)
    # mongo_db.dns_records.insert_one({"name": qname, "record": valid_records.pack()})
    print("\n\n\n", valid_records)
    return valid_records.format()

def query(qname):
    rr = check_db(qname)
    if rr:
        return rr.format()
    return unbound_query(qname)

UDP_IP = "127.0.0.1"
UDP_PORT = 5005

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    res = query(data.decode())
    sock.sendto(res.encode(),addr)