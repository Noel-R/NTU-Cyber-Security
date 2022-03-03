import sys, re, datetime, os

packets = []
firstRun = True


def main(args):
    global firstRun
    if firstRun:
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
        firstRun = False

    print(
    f'''
                    -=Packet Capture Analyser=-         
                
                Hello, this tool is made for very basic
                packet capture analysis, specifically
                the packet capture provided for coursework
                by NTU Cyber Security Course.
                
                Please select one of the below options:
                
                    1 - Print File Information
                    2 - Analyse Specific Packet
                    3 - Quit
    
    ''')

    running = True
    while running:
        try:

            choice = int(input())

            if choice == 1:
                printInfo()
            elif choice == 2:
                print("Analyse Packet")
            elif choice == 3:
                print("Quit")
                os.remove("temp.txt")
                quit()

        except ValueError:
            print("Please choose a valid option.")
            pass


def printInfo():

    with open("temp.txt", 'r') as temp:
        print(temp.read())

    try:

        choice = str(input(f"\nWould you like to save the file? Y / N: ")).lower()

        if choice == 'y':
            with open("PCAP_Saved.txt", 'w') as file:
                temp = open("temp.txt", 'r')
                file.write(temp.read())
                temp.close()
            print("Saved as PCAP_Saved.txt")
            os.system('CLS')
            args = []
            main(args)
        elif choice == 'n':
            print("Returning to menu.")
            os.system('CLS')

    except ValueError:
        print("Invalid input, please use 'Y' or 'N'.")
        printInfo()


if __name__ == '__main__':
    main(sys.argv)
