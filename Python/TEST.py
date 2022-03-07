import re

with open("../CyberSecurity2022.pcap","rb")as file:
    rePattern = re.compile(rb'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
    print(rePattern.findall(file.read()))