import re

with open("../CyberSecurity2022.pcap","rb")as file:
    rePattern = re.compile(rb'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})')
    print(rePattern.findall(file.read()))