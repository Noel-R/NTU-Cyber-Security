import sys, re, datetime

packets = []


def main(args):
    if args[0]:
        with open(args[1], 'rb') as file:

            MagicNumber = [file.read(4).hex()]

            if MagicNumber[0] == 'd4c3b2a1': MagicNumber.append('little')
            else: MagicNumber.append('big')

            print(MagicNumber[1])

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
                    if value == 0: print(f"{key}: {value} - Null")
                    if value == 1: print(f"{key}: {value} - Ethernet")
                elif key == "Snapshot Length":
                    if value != 65535: print(f"{key}: {value} - Packets Shouldn't be Captured")
                    else: print(f"{key}: {value} - Packets Should be Captured")
                else:
                    print(f"{key}: {value}")

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
            print(len(packets))
            print(packets[0])


if __name__ == '__main__':
    main(sys.argv)
