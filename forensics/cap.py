#!/usr/bin/python

from scapy.all import *

flag = ""
packets = rdpcap("cap.pcap")

for frame in packets:
    if "&x" in str(frame.getlayer(IP)):
        data = str(frame)
        # extract hex
        flag+= data[data.find("&x=")+3:]

with open("flag.bmp",'w') as f:
    f.write(flag.decode("hex"))
