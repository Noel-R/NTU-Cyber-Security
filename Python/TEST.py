import re

with open("CyberSecurity2022.pcap","rb")as file:
    rePattern = re.compile(rb'(?:[[:xdigit:]]{2}([-:]))(?:[[:xdigit:]]{2}\1){4}[[:xdigit:]]{2}$')
    print(rePattern.findall(file.read()))