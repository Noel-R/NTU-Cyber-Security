import datetime
import os


class pcapFile:
    def __init__(self, filename):
        self.size = os.path.getsize(filename)
        self.filename = filename

        self.magicNumber     = None
        self.majVerNum       = None
        self.minVerNum       = None
        self.timeZone        = None
        self.accOfTimestamps = None
        self.snapLen         = None
        self.Network         = None

        self.Packets = []

        self.getHeader()

        print(f"\t\t-= File Information=-\n"
              f"\tFilename: {self.filename}\n"
              f"\tSize: {self.size}\n"
              f"\t\t-===================-\n\n"
              f"\t\t-=  Global Header  =-\n"
              f"\tMagic Number: {self.magicNumber}\n\tMajor Version Number: {self.majVerNum}\n\tMinor Version Number: "
              f"{self.minVerNum}\n\tTime Zone: {self.timeZone}\n\tAccuracy of Timestamps: {self.accOfTimestamps}\n\t"
              f"Snapshot Length: {self.snapLen}\n\tNetwork type: {self.Network}\n"
              f"\t\t-===================-\n\n")
        i = 1
        for packet in self.Packets:
            print(f"\t\t-==== Packet {i}====-\n"
                  f"\tTimestamp:                {packet[0]}\n"
                  f"\tIncluded Length:          {packet[2]}\n"
                  f"\tOriginal Length:          {packet[3]}\n"
                  f"Data:                       {packet[4]}\n"
                  f"\tOperation Code:           {int(packet[4][:2]        ,base = 16)}\n"
                  f"\tHardware Type:            {int(packet[4][2:4]       ,base = 16)}\n"
                  f"\tHardware Address Length:  {int(packet[4][4:6]       ,base = 16)}\n"
                  f"\tHops:                     {int(packet[4][6:8]       ,base = 16)}\n"
                  f"\tTransaction Identifier:   {int(packet[4][8:16]      ,base = 16)}\n"
                  f"\tSeconds:                  {int(packet[4][16:20]     ,base = 16)}\n"
                  f"\tFlags:                    {int(packet[4][20:24]     ,base = 16)}\n"
                  f"\tClient IP:                "
                  f"{int(packet[4][30:32],base = 16)}.{int(packet[4][28:30],base = 16)}."
                  f"{int(packet[4][26:28],base = 16)}.{int(packet[4][24:26],base = 16)}\n"
                  f"\tThis IP:                  "
                  f"{int(packet[4][38:40],base = 16)}.{int(packet[4][34:36],base = 16)}."
                  f"{int(packet[4][36:38],base = 16)}.{int(packet[4][32:34],base = 16)}\n"
                  f"\tServer IP:                "
                  f"{int(packet[4][40:42],base = 16)}.{int(packet[4][42:44],base = 16)}."
                  f"{int(packet[4][44:46],base = 16)}.{int(packet[4][46:48],base = 16)}\n"
                  f"\tGateway IP:               "
                  f"{int(packet[4][48:50],base = 16)}.{int(packet[4][50:52],base = 16)}."
                  f"{int(packet[4][52:54],base = 16)}.{int(packet[4][54:56],base = 16)}\n"
                  f"\tClient Hardware Address:  {packet[4][56:88]}\n"
                  f"\tServer Name:              {packet[4][88:216]}\n"
                  f"\tBoot File Name:           {packet[4][216:472]}\n"
                  f"\tOptions:                  {packet[4][472:]}\n"
                  f"\t\t-===================-")

    def getHeader(self):
        with open(self.filename, 'rb') as f:

            if f.read(4) == b'0xa1b2c3d4':
                self.magicNumber = "big"
            else:
                self.magicNumber = "little"

            self.majVerNum        = int.from_bytes(f.read(2), self.magicNumber)
            self.minVerNum        = int.from_bytes(f.read(2), self.magicNumber)
            self.timeZone         = int.from_bytes(f.read(4), self.magicNumber)
            self.accOfTimestamps  = int.from_bytes(f.read(4), self.magicNumber)
            self.snapLen          = int.from_bytes(f.read(4), self.magicNumber)
            self.Network          = int.from_bytes(f.read(4), self.magicNumber)

            i = 0
            cur_Size = 24
            while cur_Size < self.size:
                try:
                    self.Packets.append([datetime.datetime.fromtimestamp(int.from_bytes(f.read(4), self.magicNumber)),
                                         int.from_bytes(f.read(4), self.magicNumber),
                                         int.from_bytes(f.read(4), self.magicNumber),
                                         int.from_bytes(f.read(4), self.magicNumber)])
                    self.Packets[i].append(f.read(self.Packets[i][2]).hex())
                    i += 1
                    cur_Size += 16 + self.Packets[i][2]
                except:
                    return


def main():
    running = True

    while running:
        # Main Menu
        print("\t\t-= Main Menu=-\n"
              "\t Option 1 - PCAP File\n"
              "\t Option 2 -TBD\n"
              "\t Option 3 -TBD\n"
              "\t Exit\n")
        choice = getInput()
        if choice[0]:
           chooseOption(choice[1])


def getInput():
    try:
        choice = int(input(""))
        return [True, choice]
    except ValueError as e:
        print("Incorrect input. Try again.")
        return [False, None]


def chooseOption(choice):
    if choice == 1:
        pcapFunc(str(input("Full PCAP file path: ")))


def pcapFunc(filename):
    try:

        test = open(filename, 'r')
        test.close()

    except IOError as e:

        print("Incorrect pcap file. Try again.")
        return

    newFile = pcapFile(filename)


if __name__ == '__main__':
    main()
