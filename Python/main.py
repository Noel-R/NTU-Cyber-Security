import sys, re, datetime, os

packets = []
firstRun = True


def main():
    global firstRun
    args = sys.argv
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
                clearConsole()
                printInfo()
            elif choice == 2:
                AnalysePacket()
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
            clearConsole()
            main()
        elif choice == 'n':
            print("Returning to menu.")
            clearConsole()
            main()

    except ValueError:
        print("Invalid input, please use 'Y' or 'N'.")
        printInfo()


def AnalysePacket():
    def getPacket(number):
        print(
        f"""
                    Packet Number: {number + 1}
                    
                    Timestamp: {packets[number][0][0]}
                    Included Length: {packets[number][0][2]}
                    Original Length: {packets[number][0][3]}
                    
                    Data: {packets[number][1].strip()}
        
        
                    <- P --- RETURN --- N ->
        """)

        try:
            choice = str(input()).upper()
            if choice == "N" and number + 1 <= len(packets):
                getPacket(number + 1)
            elif choice == "P" and number - 1 > 0:
                getPacket(number - 1)
            elif choice == "RETURN":
                clearConsole()
                main()
            else:
                raise Exception

        except ValueError:
            print("Invalid input, use 'P', 'N' or 'RETURN'.")
            getPacket(number)

        except Exception:
            print("The specified packet is out of range, returning to previous packet.")
            getPacket(number)

    analysing = True
    while analysing:
        try:

            choice = int(input(f"Choose a packet, from 1 - {len(packets)}: "))
            if 0 >= choice or choice > len(packets):
                raise ValueError
            else:
                getPacket(choice - 1)

        except ValueError:
            print(f"Error. Please choose a packet, from 1 - {len(packets)}")
            pass


def clearConsole():
    cmd = 'clear'
    if os.name in ('nt', 'dos'):
        cmd = 'cls'
    os.system(cmd)


if __name__ == '__main__':
    main()
