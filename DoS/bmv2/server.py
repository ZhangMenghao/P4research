#!/usr/bin/python
from scapy.all import *

# Interacts with a client by going through the three-way handshake.
# Shuts down the connection immediately after the connection has been established.
# Akaljed Dec 2010, http://www.akaljed.wordpress.com

# Wait for client to connect.
a=sniff(count=1,filter="tcp and host 10.0.0.20 and port 80")

# some variables for later use.
ValueOfPort=a[0].sport
SeqNr=a[0].seq
AckNr=a[0].seq+1

# Generating the IP layer:
ip=IP(src="10.0.0.20", dst="10.0.0.10")
# Generating TCP layer:
TCP_SYNACK=TCP(sport=80, dport=ValueOfPort, flags="SA", seq=SeqNr, ack=AckNr, options=[('MSS', 1460)])

#send SYNACK to remote host AND receive ACK.
ANSWER=sr1(ip/TCP_SYNACK)

# Capture next TCP packets with dport 80. (contains http GET request)
GEThttp = sniff(filter="tcp and port 80",count=1,prn=lambda x:x.sprintf("{IP:%IP.src%: %TCP.dport%}"))
AckNr=AckNr+len(GEThttp[0].load)
SeqNr=a[0].seq+1

# Print the GET request
# (Sanity check: size of data should be greater than 1.)
if len(GEThttp[0].load)>1: print GEThttp[0].load

# Generate custom http file content.
html1="HTTP/1.1 200 OK\x0d\x0aDate: Wed, 29 Sep 2010 20:19:05 GMT\x0d\x0aServer: Testserver\x0d\x0aConnection: Keep-Alive\x0d\x0aContent-Type: text/html; charset=UTF-8\x0d\x0aContent-Length: 291\x0d\x0a\x0d\x0a<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\"><html><head><title>Testserver</title></head><body bgcolor=\"black\" text=\"white\" link=\"blue\" vlink=\"purple\" alink=\"red\"><p><font face=\"Courier\" color=\"blue\">-Welcome to test server-------------------------------</font></p></body></html>"

# Generate TCP data
data1=TCP(sport=80, dport=ValueOfPort, flags="PA", seq=SeqNr, ack=AckNr, options=[('MSS', 1460)])

# Construct whole network packet, send it and fetch the returning ack.
ackdata1=sr1(ip/data1/html1)
# Store new sequence number.
SeqNr=ackdata1.ack

# Generate RST-ACK packet
Bye=TCP(sport=80, dport=ValueOfPort, flags="FA", seq=SeqNr, ack=AckNr, options=[('MSS', 1460)])

send(ip/Bye)

# The End
