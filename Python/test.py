import re

with open("CyberSecurity2022.pcap", 'rb') as f:

    rePattern = re.compile(r'(?:http:\/\/)[a-z, A-Z 0-9 .]+(?:.top)')
    print(rePattern.findall(f.read()[24:].decode('utf-8', 'ignore')))