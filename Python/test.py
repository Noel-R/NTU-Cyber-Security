import re

with open("CyberSecurity2022.pcap", 'rb') as f:

    data = f.read()[24:].decode('utf-8', 'ignore')

    rePattern = re.compile(r'(?:http:\/\/)[a-z, A-Z 0-9 .]+(?:.top)')
    reWebPatter = re.compile(r'(?:http|https)?(?:\:\/\/)(?:www\.)?(?:[a-zA-z,.!?-]\w+(?:\.)?)+(?:\.com|\.net|\.top){1}(?:\/(?:[a-zA-z0-9,.!?-]\w+)*)*')
    print(rePattern.findall(data))
    print(reWebPatter.findall(data))
