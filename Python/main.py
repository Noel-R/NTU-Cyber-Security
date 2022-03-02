import sys, re, datetime

packets = []


def main(args):
    if args[0]:
        with open(args[1], 'rb') as file:

            MagicNumber = [file.read(4).hex()]

            if MagicNumber[0] == 'd4c3b2a1': MagicNumber.append('little')
            else: MagicNumber.append('big')

            HeaderDict = {
                "Major Version Number": int.from_bytes(file.read(2), MagicNumber[1]),
                "Minor Version Number": int.from_bytes(file.read(2), MagicNumber[1]),
                "Time Zone": int.from_bytes(file.read(4), MagicNumber[1]),
                "Accuracy of Timestamp": int.from_bytes(file.read(4), MagicNumber[1]),
                "Snapshot Length": int.from_bytes(file.read(4), MagicNumber[1]),
                "Networks": int.from_bytes(file.read(4), MagicNumber[1])
            }

            for key, value in HeaderDict.items():
                if key == "Networks":
                    if value == 0: HeaderDict["Networks"] = f"{value} - Null"
                    if value == 1: HeaderDict["Networks"] = f"{value} - Ethernet"
                elif key == "Snapshot Length":
                    if value != 65535: HeaderDict["Snapshot Length"] = f"{value} - Packets Shouldn't be Captured"
                    else: HeaderDict["Snapshot Length"] = f"{value} - Packets Should be Captured"

            running = True
            while running:
                try:

                    packetHeader = [int.from_bytes(file.read(4), MagicNumber[1]) for i in range(4)]
                    if packetHeader[0] == 0:
                        raise Exception
                    packetHeader[0] = datetime.datetime.fromtimestamp(packetHeader[0])

                    packetData = file.read(packetHeader[2])
                    packets.append([packetHeader, packetData])

                except Exception:
                    running = False

        with open("temp.txt", 'w') as temp:
            information = \
                f'''
                                File Information
                    
                    File Name: {args[1]}                         
                    
                                Global Header
                    
                    MagicNumber: {MagicNumber[0]} - {MagicNumber[1]}
                    Major Version Number: {HeaderDict.get("Major Version Number")}
                    Minor Version Number: {HeaderDict.get("Minor Version Number")}
                    Timezone: {HeaderDict.get("Timezone")}
                    Accuracy of Timestamps: {HeaderDict.get("Accuracy of Timestamps")}
                    Network Type: {HeaderDict.get("Networks")}
                    Snapshot Length: {HeaderDict.get("Snapshot Length")}
                    
                                Packet Information
                                
                    Number of Packets: {len(packets)}
                '''

            temp.write(information)

        with open("temp.txt", 'r') as temp:
            print(temp.read())


if __name__ == '__main__':
    main(sys.argv)
