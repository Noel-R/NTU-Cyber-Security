# Imports, Re for Regular Expressions, Datetime for Converting times, Sys to parse command line arguments.

import sys, datetime, re

# This is a class made for the ease of use and file handling.
# The class is responsible for all operations with the file.
# Mainly: Decomposing the file, documenting it.


class PacketCapture:

    def __init__(self, filename):

        # Placeholder variables for later use.

        self.globalHeaderDict = {}
        self.packetList = []
        self.packetAmount = 0
        self.MagicNumber = None

        # Compiled Regular Expressions to search for.

        self.websitePattern = re.compile(rb'(?:http|https)?(?:\:\/\/)(?:www\.)?(?:[a-zA-z,.!?-]\w+(?:\.)?)+(?:\.com|\.net|\.top){1}(?:\/(?:[a-zA-z0-9,.!?-]\w+)*)*')

        # Try to open the file, return and delete this object if bad filepath.
        # If successfull, start the main decomposition of the file with initialRun().

        try:

            self.file = open(filename, 'rb')
            self.initialRun()

        except (IOError, FileNotFoundError):
            print(f"Encountered an error while opening {filename}."
                  " Please provide a correct filepath with extension.")
            del self

    def initialRun(self):

        # Read the first 4 bytes of the file, which is the magic number.

        MagicNumber = [self.file.read(4).hex()]

        # If the number is equal to the below value, it must be little endian, else it is big endian.

        if MagicNumber[0] == 'd4c3b2a1':
            MagicNumber.append('little')
        else:
            MagicNumber.append('big')

        # Appoint this to a class wide variable.

        self.MagicNumber = MagicNumber[1]

        # Define the global header, read the values in from the file and convert it from bytes to an integer.

        self.globalHeaderDict = {
            "Magic Number": f"{MagicNumber[0]} - {MagicNumber[1]}",
            "Major Version Number": int.from_bytes(self.file.read(2), self.MagicNumber),
            "Minor Version Number": int.from_bytes(self.file.read(2), self.MagicNumber),
            "Time Zone": int.from_bytes(self.file.read(4), self.MagicNumber),
            "Accuracy of Timestamp": int.from_bytes(self.file.read(4), self.MagicNumber),
            "Snapshot Length": int.from_bytes(self.file.read(4), self.MagicNumber),
            "Networks": int.from_bytes(self.file.read(4), self.MagicNumber),
        }

        # Check for the 'Networks' key in globalHeaderDict to change it's value to the network type.
        # Check for the 'Snapshot Length' key in globalHeaderDict to change it's value to packet capture type.

        for key, val in self.globalHeaderDict.items():
            if key == "Networks":
                if val == 1:
                    self.globalHeaderDict[key] = f"{val} - Ethernet"
                else:
                    self.globalHeaderDict[key] = f"{val} - Unset"
            if key == "Snapshot Length":
                if val == 65535:
                    self.globalHeaderDict[key] = f"{val} - Packets Should be Captured."
                else:
                    self.globalHeaderDict[key] = f"{val} - Packets Shouldn't be Captured."

        # Start a while loop to loop through packets in the file.

        packetSearching = True
        while packetSearching:
            # Try to get the packet header from the file and append it to the packetList, if it is equal to '0',
            # means that it is the end of the file so raise an exception and break the loop.
            try:
                packetHeader = [int.from_bytes(self.file.read(4), MagicNumber[1]) for i in range(4)]
                if packetHeader[0] == 0:
                    raise Exception
                packetHeader[0] = datetime.datetime.fromtimestamp(packetHeader[0])

                # Using the included length, read the data in the packet and record it in an array with the packet
                # header.

                packetData = self.file.read(packetHeader[2])
                self.packetList.append([packetHeader, packetData])

            except Exception:
                packetSearching = False

        # Update the amount of packets, by getting the length of the packetList.

        self.packetAmount = len(self.packetList)

    def globalHeader(self):

        # Print the global header information when requested from the menu.
        # Using the values found in the globalHeaderDict.

        print(
            f"""
                            -=  Global Header  =-

                        The .PCAP files Global Header.

                            -= Header  Details =-

                    Magic Number:           {self.globalHeaderDict.get("Magic Number")}
                    Major Version Number:   {self.globalHeaderDict.get("Major Version Number")} 
                    Minor Version Number:   {self.globalHeaderDict.get("Minor Version Number")}
                    Time Zone:              {self.globalHeaderDict.get("Time Zone")}
                    Accuracy of Timestamp:  {self.globalHeaderDict.get("Accuracy of Timestamp")}
                    Snapshot Length:        {self.globalHeaderDict.get("Snapshot Length")}
                    Network Type:           {self.globalHeaderDict.get("Networks")}

                            -=  SAVE | RETURN  =-

            """)

        # Start a while loop to wait for an input from the user. Record it and parse it as needed.

        here = True
        while here:
            try:
                choice = str(input("Choice: "))
                if choice.lower() in ["save", "s", "sav"]:
                    # If Save is selected, open a new file as write, then write the header to it.
                    with open("GlobalHeader.txt", "w") as f:
                        f.write(
                            f"""
                                                    -=  Global Header  =-

                                                The .PCAP files Global Header.

                                                    -= Header  Details =-

                                            Magic Number:           {self.globalHeaderDict.get("Magic Number")}
                                            Major Version Number:   {self.globalHeaderDict.get("Major Version Number")} 
                                            Minor Version Number:   {self.globalHeaderDict.get("Minor Version Number")}
                                            Time Zone:              {self.globalHeaderDict.get("Time Zone")}
                                            Accuracy of Timestamp:  {self.globalHeaderDict.get("Accuracy of Timestamp")}
                                            Snapshot Length:        {self.globalHeaderDict.get("Snapshot Length")}
                                            Network Type:           {self.globalHeaderDict.get("Networks")}
                        """)

                    # Once saved, break out of the while loop and return to menu.

                    print("Saved as GlobalHeader.txt")
                    here = False

                elif choice.lower() in ["return", "ret", "r", "back", "menu"]:

                    # If the return option is selected, break the loop and return to menu.

                    here = False
                else:

                    # If choice is not within the options, raise an exception to restart loop.

                    raise ValueError

            except ValueError:

                # If the input is unrecognized, loop again and wait for another response.

                print("Invalid input, use RETURN or SAVE to proceed.")

    def searchPackets(self):

        # This function is called from the menu, if searchPackets is selected. It searches through the packet list
        # for the packet specified.

        # Starts a while loop for this menu option and asks the user what packet to go to. Also sets a variable
        # that is only true the first time this function is called.

        Searching = True
        firstRun = True
        packetNum = 1

        while Searching:

            # Try loop surrounding the operation, for error handling.

            try:

                # On first run, check if the input is between the range, then show the packet if successfull.
                # Else, it raises a value error and asks the user for alternative input.

                if firstRun:

                    try:
                        packetNum = int(input(f"Which Packet? (1 - {self.packetAmount}): "))

                        if self.packetAmount >= packetNum >= 1:
                            self.showPacket(packetNum)
                            firstRun = False

                        elif packetNum > self.packetAmount or packetNum < 1:
                            raise ValueError

                    except ValueError:
                        print(f"Please choose a paket between 1 and {self.packetAmount}.")
                        continue

                else:

                    # If it is not the first run, I.e a user has already used the menu, or first run is completed,
                    # Wait for user input, check if the input is valid and follow through then return to this loop.

                    try:

                        # Ask for user input.

                        choice = str(input("Choice: ")).lower()

                        if choice in ["save", "s", "sav"]:

                            # If the user wants to save the packet, save the packet and return to the loop.

                            print(f"Saved as Packet.txt !")
                            continue

                        elif choice in ["first", "fir", "f"]:

                            # Take the user to the first packet, set the current packet to 1

                            packetNum = 1
                            self.showPacket(packetNum)
                            continue

                        elif choice in ["previous", "prev", "p", "pre"]:

                            # Take the user to previous packet, handle problems if packet doesn't exist or
                            # is out of range.

                            if packetNum > 1:
                                packetNum = packetNum - 1
                                self.showPacket(packetNum)
                            else:
                                print("Packet out of range.")
                            continue

                        elif choice in ["return", "ret", "r"]:

                            # If they want to return, raise an error (AttributeError no reason in particular).

                            raise AttributeError

                        elif choice in ["next", "nex", "n"]:

                            # Take the user to the next packet, handle problems if packet doesn't exist or
                            # is out of range.

                            if packetNum < self.packetAmount:
                                packetNum = packetNum + 1
                                self.showPacket(packetNum)
                            else:
                                print("Packet out of range.")
                            continue

                        elif choice in ["last", "las", "l"]:

                            # Set the packet Number to the last packet, and go to it.

                            packetNum = self.packetAmount
                            self.showPacket(self.packetAmount)
                            continue
                        else:

                            # If choice is not in above options, raise a value error.

                            raise ValueError

                    except ValueError:

                        # Make sure the user uses a valid option, if not return to loop.

                        print("Please choose a valid Option. [FIRST PREV SAVE RETURN NEXT LAST]")
                        continue

                    except AttributeError:

                        # Raising another error to get out of the nested try statement and return.

                        raise ValueError

            except ValueError:

                # Take the user to the menu by stopping the while loop and letting the program continue.

                print("Returning to Menu.")
                Searching = False

    def showPacket(self, packetNum):

        # This function is accessed by the packet Search menu option,
        # it shows the packet specified by 'packetNum'.
        # Since the packetList is an array, it starts from Zero. Therefore we take one from the desired
        # packet number to accommodate for this.

        packetNum = packetNum - 1
        currPacket = self.packetList[packetNum]

        # Printing the information taken from the packet in packet list,
        # using the header and data previously recorded.

        print(
            f"""

                            -= Packet {packetNum + 1} =-

                    Displays Information about specified packet.                    

                            -= Packet Information =-

                        Epoch Time:             {datetime.datetime.timestamp(currPacket[0][0])}
                        Timestamp GMT+00:00:    {currPacket[0][0]}
                        Included Length:        {currPacket[0][2]}
                        Original Length:        {currPacket[0][3]}

                            -=  Included RawData  =-

                            Raw Data: {currPacket[1]}
                            Regex Search: {self.websitePattern.findall(currPacket[1])}

                  -= FIRST | BACK | SAVE | RETURN | NEXT | LAST =-
        """)

        # Returning to the prior function.

        return

    def task3(self):
        print("Task 3")

    def task4(self):
        print("Task 4")


def menu():

    # Print the main menu text, basic information and options menu.

    print(
        f"""
                -=Packet Capture Analyser=-
                
            This is a basic tool made for the course
            Cyber Security, NTU. It is used for the
            basic analysis of .pcap files without
            the use of modules such as dpkt and scapy.
            
                        -=Options=-
                    
                1 [ Check Global Header ]
                2 [   Search Packets    ]
                3 [       Task 3        ]
                4 [       Task 4        ]
                5 [        Quit         ]

    """)

    # Start a persistent while loop, exited only by shutdown or a menu option.

    while True:

        # Catch exception when the user input is out of range.

        try:

            option = int(input("\nChoice: "))

            if option in range(1, 6):

                # Return the desired option to the prior function.

                return option

            else:

                raise ValueError

        except ValueError:

            print("\nPlease choose a valid Option. [1 ,2, 3, 4, 5]\n")

# If the name of this file is main in the package, this is automatically ran.


if __name__ == '__main__':

    # Set basic variables to start a loop.

    running = True
    firstRun = True

    while running:

        # Check if its the first time ran, if so ensure that the filepath is either set in the command line
        # or manually through user input.

        if firstRun:

            if len(sys.argv) > 1:

                if ".pcap" in sys.argv[1]:

                    # If there is a valid filename/path in the command line arguments,
                    # use this to create a PacketCapture Object and set first run to false.

                    pcapClass = PacketCapture(filename=sys.argv[1])
                    firstRun = False

            else:

                # If no file is defined in the command line arguments, ask for manual input of filepath.

                print("Please provide a location for the .pcap file.")

                try:

                    # Ask for filepath.

                    filename = str(input("Filename: "))

                    if ".pcap" in filename:

                        # Check if .pcap is in filename (preliminary check)
                        # If so, use the filepath to create a PacketCapture Object and set firstRun to false.

                        pcapClass = PacketCapture(filename=filename)
                        firstRun = False

                    else:

                        # If the preliminary check fails, raise a pre emptive value error.

                        raise ValueError

                except ValueError:

                    # Continue the loop with firstRun still on True.

                    continue

        else:

            # If firstRun is false check if the object has been created with a file attribute.

            try:

                if hasattr(pcapClass, 'file'):

                    # If the object exists, show the menu and request input then direct accordingly.

                    option = menu()

                    if option == 1:  # Global Header
                        pcapClass.globalHeader()
                    elif option == 2:  # Packet Search
                        pcapClass.searchPackets()
                    elif option == 3:  # Task 3
                        pcapClass.task3()
                    elif option == 4:  # Task 4
                        pcapClass.task4()
                    elif option == 5:  # Quit

                        # If quitting, close the file and quit the program.

                        pcapClass.file.close()
                        quit()

                else:

                    # If the object doesn't exist, it will raise an AttributeError automatically this is just in case.

                    raise AttributeError

            except AttributeError:

                # Return to manually add the filepath in the firstRun Section.

                firstRun = True
