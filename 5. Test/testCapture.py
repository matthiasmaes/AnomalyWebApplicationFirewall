# import socket, sys, time, platform, struct

# # Special lists used for calculations.
# lengthList = []
# diameterList = []

# # Special lists used to hold unpacked info and calculation results.
# unpackedInfo = []
# calculationList = []

# # Check the OS the application is running on.
# os = platform.system()
# linux = 'Linux'
# windows = 'Windows'

# def eth(packet, extractedAttIndex, printKey):
#     # Header lengths.
#     ethHeaderLength = 14

#     # Get Ethernet header using begin and end.
#     # No need for windows calibration, Ethernet support under Linux only.
#     begin = 0
#     end = begin + ethHeaderLength
#     ethHeader = packet[begin:end]

#     # Unpack the header because it originally in hex.
#     # The regular expression helps unpack the header.
#     # ! signifies we are unpacking a network endian.
#     # 6s signifies we are unpacking a string of size 6 bytes.
#     # H signifies we are unpacking an integer of size 2 bytes.
#     ethHeaderUnpacked = struct.unpack('!6s6sH', ethHeader)
        
#     # The first 6s is 6 bytes and contains the destination address.
#     ethDestAddress = ethHeaderUnpacked[0]
    
#     # The second 6s is 6 bytes and contains the source address.
#     ethSourceAddress = ethHeaderUnpacked[1]
    
#     # The first H is 2 bytes and contains the packet length.
#     ethType = socket.ntohs(ethHeaderUnpacked[2])
    
#     # Properly unpack and format the destination address.
#     ethDestAddress = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(ethDestAddress[0]), ord(ethDestAddress[1]), ord(ethDestAddress[2]), ord(ethDestAddress[3]), ord(ethDestAddress[4]), ord(ethDestAddress[5]))
    
#     # Properly unpack and format the source address.
#     ethSourceAddress = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(ethSourceAddress[0]), ord(ethSourceAddress[1]), ord(ethSourceAddress[2]), ord(ethSourceAddress[3]), ord(ethSourceAddress[4]), ord(ethSourceAddress[5]))
    
#     # Check if the print key is 0.
#     # If true, header information will be printed.
#     #   Check if the user selected extracted attribute index is 0.
#     #   If true, all attributes will be printed.
#     #   If false, the attribute the user selected extracted attribute index corresponds to will be printed.
#     # If false, the attribute the user selected attribute index corresponds to will be returned.
#     if printKey == 0:
#         # Print Ethernet Header
#         unpackedInfo.append('\n********************\n** Ethernet (MAC) **\n********************')
        
#         if (extractedAttIndex == 1) or (extractedAttIndex == 0):
#                 unpackedInfo.append('Destination Address: ' + str(ethDestAddress))
#         if (extractedAttIndex == 2) or (extractedAttIndex == 0):
#                 unpackedInfo.append('Source Address: ' + str(ethSourceAddress))
#         if (extractedAttIndex == 3) or (extractedAttIndex == 0):
#                 unpackedInfo.append('EtherType: ' + str(ethType))
#     else:
#         if (extractedAttIndex == 1):
#             return str(ethDestAddress)
#         if (extractedAttIndex == 2):
#             return str(ethSourceAddress)
#         if (extractedAttIndex == 3):
#             return str(ethType)
    
# def arp(packet, extractedAttIndex, printKey):
#     # Header lengths.
#     ethHeaderLength = 14
#     arpHeaderLength = 28
    
#     # Get ARP header using begin and end.
#     begin = ethHeaderLength
#     end = begin + arpHeaderLength
#     arpHeader = packet[begin:end]
    
#     # Unpack the header because it originally in hex.
#     # The regular expression helps unpack the header.
#     # ! signifies we are unpacking a network endian.
#     # H signifies we are unpacking an integer of size 2 bytes.
#     # B signifies we are unpacking an integer of size 1 byte.
#     # 6s signifies we are unpacking a string of size 6 bytes.
#     # 4s signifies we are unpacking a string of size 4 bytes.
#     arpHeaderUnpacked = struct.unpack('!HHBBH6s4s6s4s', arpHeader)
    
#     # The first H is 2 bytes and contains the hardware type.
#     arpHardwareType = socket.ntohs(arpHeaderUnpacked[0])
    
#     # The second H is 2 bytes and contains the protocol type.
#     arpProtocolType = socket.ntohs(arpHeaderUnpacked[1])
    
#     # The first B is 1 byte and contains the hardware address length.
#     arpHardAddressLength = arpHeaderUnpacked[2]
    
#     # The second B is 1 byte and contains the protocol address length.
#     arpProtAddressLength = arpHeaderUnpacked[3]
    
#     # The third H is 2 bytes and contains the operation.
#     arpOperation = arpHeaderUnpacked[4]

#     # The first 6s is 6 bytes and contains the sender hardware address.
#     arpSenderHardAddress = arpHeaderUnpacked[5]
    
#     # The first 4s is 4 bytes and contains the sender protocol address.
#     arpSenderProtAddress = socket.inet_ntoa(arpHeaderUnpacked[6])
    
#     # The second 6s is 6 bytes and contains the target hardware address.
#     arpTargetHardAddress = arpHeaderUnpacked[7]
    
#     # The second 4s is 4 bytes and contains the target protocol address.
#     arpTargetProtAddress = socket.inet_ntoa(arpHeaderUnpacked[8])
    
#     # Properly unpack and format the source MAC address.
#     arpSenderHardAddress = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(arpSenderHardAddress[0]), ord(arpSenderHardAddress[1]), ord(arpSenderHardAddress[2]), ord(arpSenderHardAddress[3]), ord(arpSenderHardAddress[4]), ord(arpSenderHardAddress[5]))
    
#     # Properly unpack and format the destination MAC address.
#     arpTargetHardAddress = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(arpTargetHardAddress[0]), ord(arpTargetHardAddress[1]), ord(arpTargetHardAddress[2]), ord(arpTargetHardAddress[3]), ord(arpTargetHardAddress[4]), ord(arpTargetHardAddress[5]))
    
#     # Check if the print key is 0.
#     # If true, header information will be printed.
#     #   Check if the user selected extracted attribute index is 0.
#     #   If true, all attributes will be printed.
#     #   If false, the attribute the user selected extracted attribute index corresponds to will be printed.
#     # If false, the attribute the user selected attribute index corresponds to will be returned.
#     if printKey == 0:
#         # Print ARP Header
#         unpackedInfo.append('\n*******************\n******* ARP *******\n*******************')
        
#         if (extractedAttIndex == 1) or (extractedAttIndex == 0):
#             unpackedInfo.append('Hardware Type: ' + str(arpHardwareType))
#         if (extractedAttIndex == 2) or (extractedAttIndex == 0):    
#             unpackedInfo.append('Protocol Type: ' + str(arpProtocolType))
#         if (extractedAttIndex == 3) or (extractedAttIndex == 0):    
#             unpackedInfo.append('Hardware Address Length: ' + str(arpHardAddressLength))
#         if (extractedAttIndex == 4) or (extractedAttIndex == 0):    
#             unpackedInfo.append('Protocol Address Length: ' + str(arpProtAddressLength))
#         if (extractedAttIndex == 5) or (extractedAttIndex == 0):    
#             unpackedInfo.append('Operation: ' + str(arpOperation))
#         if (extractedAttIndex == 6) or (extractedAttIndex == 0):    
#             unpackedInfo.append('Sender Hardware Address: ' + str(arpSenderHardAddress))
#         if (extractedAttIndex == 7) or (extractedAttIndex == 0):    
#             unpackedInfo.append('Sender Protocol Address: ' + str(arpSenderProtAddress))
#         if (extractedAttIndex == 8) or (extractedAttIndex == 0):    
#             unpackedInfo.append('Target Hardware Address: ' + str(arpTargetHardAddress))
#         if (extractedAttIndex == 9) or (extractedAttIndex == 0):    
#             unpackedInfo.append('Target Protocol Address: ' + str(arpTargetProtAddress))
            
#         # Separator 
#         unpackedInfo.append('\n----------------------------------------')   
#     else:
#         if (extractedAttIndex == 1):
#             return str(arpHardwareType)
#         if (extractedAttIndex == 2):    
#             return str(arpProtocolType)
#         if (extractedAttIndex == 3):    
#             return str(arpHardAddressLength)
#         if (extractedAttIndex == 4):    
#             return str(arpProtAddressLength)
#         if (extractedAttIndex == 5):    
#             return str(arpOperation)
#         if (extractedAttIndex == 6):    
#             return str(arpSenderHardAddress)
#         if (extractedAttIndex == 7):    
#             return str(arpSenderProtAddress)
#         if (extractedAttIndex == 8):    
#             return str(arpTargetHardAddress)
#         if (extractedAttIndex == 9):    
#             return str(arpTargetProtAddress)

# def ip(packet, extractedAttIndex, printKey):
#     # Header lengths.
#     ethHeaderLength = 14
#     ipHeaderLength = 20
    
#     # Get IP header using begin and end.
#     # Specific Linux and Windows calibration is needed.
#     if os == linux: 
#         begin = ethHeaderLength
#         end = begin + ipHeaderLength
#     elif os == windows:
#         begin = 0
#         end = begin + ipHeaderLength
#     ipHeader = packet[begin:end]

#     # Unpack the header because it originally in hex.
#     # The regular expression helps unpack the header.
#     # ! signifies we are unpacking a network endian.
#     # B signifies we are unpacking an integer of size 1 byte.
#     # H signifies we are unpacking an integer of size 2 bytes.
#     # 4s signifies we are unpacking a string of size 4 bytes.
#     ipHeaderUnpacked = struct.unpack('!BBHHHBBH4s4s' , ipHeader)
    
#     # The first B is 1 byte and contains the version and header length.
#     # Both are 4 bits each, split ipHeaderUnpacked[0] in "half".
#     ipVersionAndHeaderLength = ipHeaderUnpacked[0]
#     ipVersion = ipVersionAndHeaderLength >> 4
#     ipHeaderLength = ipVersionAndHeaderLength & 0xF

#     # The second B is 1 byte and contains the service type and ECN.
#     ipDSCPAndECN = ipHeaderUnpacked[1]
#     ipDSCP = ipDSCPAndECN >> 2
#     ipECN = ipDSCPAndECN & 0x3

#     # The first H is 2 bytes and contains the total length.
#     ipTotalLength = ipHeaderUnpacked[2]
    
#     # The second H is 2 bytes and contains the total length.
#     ipIdentification = ipHeaderUnpacked[3]

#     # The third H is 2 bytes and contains the flags and fragment offset.
#     # Flags is 3 bits and fragment offset is 13 bits.
#     # Split ipHeaderUnpacked[4].
#     ipFlagsAndFragmentOffset = ipHeaderUnpacked[4]
#     ipFlags = ipFlagsAndFragmentOffset >> 13
#     ipFragmentOffset = ipFlagsAndFragmentOffset & 0x1FFF

#     # The third B is 1 byte and contains the time to live.
#     ipTimeToLive = ipHeaderUnpacked[5]
        
#     # Our fourth B is 1 byte and contains the protocol.
#     ipProtocol = ipHeaderUnpacked[6]
    
#     # The fourth H is 2 bytes and contains the header checksum.
#     ipHeaderChecksum = ipHeaderUnpacked[7]

#     # The first 4s is 4 bytes and contains the source address.
#     ipSourceAddress = socket.inet_ntoa(ipHeaderUnpacked[8]);

#     # The second 4s is 4 bytes and contains the dest address.
#     ipDestAddress = socket.inet_ntoa(ipHeaderUnpacked[9]);

#     # Check if the print key is 0.
#     # If true, header information will be printed.
#     #   Check if the user selected extracted attribute index is 0.
#     #   If true, all attributes will be printed.
#     #   If false, the attribute the user selected extracted attribute index corresponds to will be printed.
#     # If false, the attribute the user selected attribute index corresponds to will be returned.
#     if printKey == 0:
#         # Print IP Header
#         # Some segments of the header are switched back to hex form because that
#         #   is the format wireshark has it.
#         unpackedInfo.append('\n********************\n******** IP ********\n********************')
        
#         if (extractedAttIndex == 1) or (extractedAttIndex == 0):
#             unpackedInfo.append('Version: ' + str(ipVersion))
#         if (extractedAttIndex == 2) or (extractedAttIndex == 0):
#             unpackedInfo.append('Header Length: ' + str(ipHeaderLength) + ' 32-bit words')
#         if (extractedAttIndex == 3) or (extractedAttIndex == 0):
#             unpackedInfo.append('Differentiated Services Code Point: ' + format(ipDSCP, '#04X') + ' , ' + str(ipDSCP))
#         if (extractedAttIndex == 4) or (extractedAttIndex == 0):
#             unpackedInfo.append('Explicit Congestion Notification: ' + format(ipECN, '#04X') + ' , ' + str(ipECN))
#         if (extractedAttIndex == 5) or (extractedAttIndex == 0):
#             unpackedInfo.append('Total Length: ' + str(ipTotalLength) + ' bytes')
#         if (extractedAttIndex == 6) or (extractedAttIndex == 0):
#             unpackedInfo.append('Identification: ' + format(ipIdentification, '#04X') + ' , ' + str(ipIdentification))
#         if (extractedAttIndex == 7) or (extractedAttIndex == 0):
#             unpackedInfo.append('Flags: ' + format(ipFlags, '#04X') + ' , ' + str(ipFlags))
#         if (extractedAttIndex == 8) or (extractedAttIndex == 0):
#             unpackedInfo.append('Fragment Offset: ' + str(ipFragmentOffset) + ' eight-byte blocks')
#         if (extractedAttIndex == 9) or (extractedAttIndex == 0):
#             unpackedInfo.append('Time to Live: ' + str(ipTimeToLive) + ' hops')
#         if (extractedAttIndex == 10) or (extractedAttIndex == 0):
#             unpackedInfo.append('Protocol: ' + str(ipProtocol))
#         if (extractedAttIndex == 11) or (extractedAttIndex == 0):
#             unpackedInfo.append('Header Checksum: ' + format(ipHeaderChecksum, '#04X'))
#         if (extractedAttIndex == 12) or (extractedAttIndex == 0):
#             unpackedInfo.append('Source Address: ' + str(ipSourceAddress))
#         if (extractedAttIndex == 13) or (extractedAttIndex == 0):
#             unpackedInfo.append('Destination Address: ' + str(ipDestAddress))
#     else:
#         if (extractedAttIndex == 1):
#             return str(ipVersion)
#         if (extractedAttIndex == 2):
#             return str(ipHeaderLength)
#         if (extractedAttIndex == 3):
#             return format(ipDSCP, '#04X')
#         if (extractedAttIndex == 4):
#             return format(ipECN, '#04X')
#         if (extractedAttIndex == 5):
#             return str(ipTotalLength)
#         if (extractedAttIndex == 6):
#             return format(ipIdentification, '#04X')
#         if (extractedAttIndex == 7):
#             return format(ipFlags, '#04X')
#         if (extractedAttIndex == 8):
#             return str(ipFragmentOffset)
#         if (extractedAttIndex == 9):
#             return str(ipTimeToLive)
#         if (extractedAttIndex == 10):
#             return str(ipProtocol)
#         if (extractedAttIndex == 11):
#             return format(ipHeaderChecksum, '#04X')
#         if (extractedAttIndex == 12):
#             return str(ipSourceAddress)
#         if (extractedAttIndex == 13):
#             return str(ipDestAddress)
            
# def icmp(packet, extractedAttIndex, printKey):
#     # Header lengths.
#     ethHeaderLength = 14
#     ipHeaderLength = 20
#     icmpHeaderLength = 8
    
#     # Get ICMP header using begin and end.
#     # Specific Linux and Windows calibration is needed.
#     if os == linux:
#         begin = ethHeaderLength + ipHeaderLength
#         end = begin + icmpHeaderLength
#     elif os == windows:
#         begin = ipHeaderLength
#         end = begin + icmpHeaderLength
#     icmpHeader = packet[begin:end]

#     # Unpack the header because it originally in hex.
#     # The regular expression helps unpack the header.
#     # ! signifies we are unpacking a network endian.
#     # B signifies we are unpacking an integer of size 1 byte.
#     # H signifies we are unpacking an integer of size 2 bytes.
#     # L signifies we are unpacking a long of size 4 bytes.
#     icmpHeaderUnpacked = struct.unpack('!BBHL', icmpHeader)

#     # The first B is 1 byte and contains the type.
#     icmpType = icmpHeaderUnpacked[0]

#     # The second B is 1 byte and contains the code.
#     icmpCode = icmpHeaderUnpacked[1]

#     # The first H is 2 bytes and contains the checksum.
#     icmpChecksum = icmpHeaderUnpacked[2]

#     # Check if the type is 1 or 8, if so, unpack the identifier and sequence number.
#     if (icmpType == 0) or (icmpType == 8):
#         # The first L is 4 bytes and contains the rest of the header.
#         icmpIdentifier = icmpHeaderUnpacked[3] >> 16
#         icmpSeqNumber = icmpHeaderUnpacked[3] & 0xFFFF
    
#     # Check if the print key is 0.
#     # If true, header information will be printed.
#     #   Check if the user selected extracted attribute index is 0.
#     #   If true, all attributes will be printed.
#     #   If false, the attribute the user selected extracted attribute index corresponds to will be printed.
#     # If false, the attribute the user selected attribute index corresponds to will be returned.
#     if printKey == 0:
#         if (icmpType == 0) or (icmpType == 8):
#             # Print ICMP Header
#             # Some segments of the header are switched back to hex form because that
#             #   is the format wireshark has it.
#             unpackedInfo.append('\n********************\n******* ICMP *******\n********************')
            
#             if (extractedAttIndex == 1) or (extractedAttIndex == 0):
#                 unpackedInfo.append('Type: ' + str(icmpType))
#             if (extractedAttIndex == 2) or (extractedAttIndex == 0):
#                 unpackedInfo.append('Code: ' + str(icmpCode))
#             if (extractedAttIndex == 3) or (extractedAttIndex == 0):
#                 unpackedInfo.append('Checksum: ' + format(icmpChecksum, '#04X'))
#             if (extractedAttIndex == 4) or (extractedAttIndex == 0):
#                 unpackedInfo.append('Identifier: ' + str(icmpIdentifier))
#             if (extractedAttIndex == 5) or (extractedAttIndex == 0):
#                 unpackedInfo.append('Sequence Number: ' + str(icmpSeqNumber))
#         else:
#             unpackedInfo.append('\n********************\n******* ICMP *******\n********************')
            
#             if (extractedAttIndex == 1) or (extractedAttIndex == 0):
#                 unpackedInfo.append('Type: ' + str(icmpType))
#             if (extractedAttIndex == 2) or (extractedAttIndex == 0):
#                 unpackedInfo.append('Code: ' + str(icmpCode))
#             if (extractedAttIndex == 3) or (extractedAttIndex == 0):
#                 unpackedInfo.append('Checksum: ' + format(icmpChecksum, '#04X'))
#             if (extractedAttIndex == 4) or (extractedAttIndex == 0):
#                 unpackedInfo.append('Attribute not available.')
#             if (extractedAttIndex == 5) or (extractedAttIndex == 0):
#                 unpackedInfo.append('Attribute not available.')
                
#         # Separator 
#         unpackedInfo.append('\n----------------------------------------')
#     else:
#         if (icmpType == 0) or (icmpType == 8):
#             if (extractedAttIndex == 1):
#                 return str(icmpType)
#             if (extractedAttIndex == 2):
#                 return str(icmpCode)
#             if (extractedAttIndex == 3):
#                 return format(icmpChecksum, '#04X')
#             if (extractedAttIndex == 4):
#                 return str(icmpIdentifier)
#             if (extractedAttIndex == 5):
#                 return str(icmpSeqNumber)
#         else:           
#             if (extractedAttIndex == 1):
#                 return str(icmpType)
#             if (extractedAttIndex == 2):
#                 return str(icmpCode)
#             if (extractedAttIndex == 3):
#                 return format(icmpChecksum, '#04X')
#             if (extractedAttIndex == 4):
#                 return 'Attribute not available.'
#             if (extractedAttIndex == 5):
#                 return 'Attribute not available.'
    
# def tcp(packet, extractedAttIndex, printKey):
#     # Header lengths.
#     ethHeaderLength = 14
#     ipHeaderLength = 20
#     tcpHeaderLength = 20

#     # Get TCP header using begin and end.
#     # Specific Linux and Windows calibration is needed.
#     if os == linux:
#         begin = ethHeaderLength + ipHeaderLength
#         end = begin + tcpHeaderLength
#     elif os == windows:
#         begin = ipHeaderLength
#         end = begin + tcpHeaderLength
#     tcpHeader = packet[begin:end]

#     # Unpack the header because it originally in hex.
#     # The regular expression helps unpack the header.
#     # ! signifies we are unpacking a network endian.
#     # H signifies we are unpacking an integer of size 2 bytes.
#     # L signifies we are unpacking a long of size 4 bytes.
#     # B signifies we are unpacking an integer of size 1 byte.
#     tcpHeaderUnpacked = struct.unpack('!HHLLBBHHH', tcpHeader)
    
#     # The first H is 2 bytes and contains the source port.
#     tcpSourcePort = tcpHeaderUnpacked[0]
    
#     # The second H is 2 bytes and contains the destination port.
#     tcpDestPort = tcpHeaderUnpacked[1]

#     # The first L is 2 bytes and contains the sequence number.
#     tcpSeqNumber = tcpHeaderUnpacked[2]
    
#     # The second L is 4 bytes and contains the acknowledgement number.
#     tcpAckNumber = tcpHeaderUnpacked[3]
    
#     # The first B is 1 byte and contains the data offset, reserved bits, and NS flag.
#     # Split tcpHeaderUnpacked[4]
#     tcpDataOffsetAndReserved = tcpHeaderUnpacked[4]
#     tcpDataOffset = tcpDataOffsetAndReserved >> 4
#     tcpReserved = (tcpDataOffsetAndReserved >> 1) & 0x7
#     tcpNSFlag = tcpDataOffsetAndReserved & 0x1
    
#     # The second B is 1 byte and contains the rest of the flags.
#     # Split tcpHeaderUnpacked[5].
#     tcpRestOfFLags = tcpHeaderUnpacked[5]
#     tcpCWRFlag = tcpRestOfFLags >> 7
#     tcpECEFlag = (tcpRestOfFLags >> 6) & 0x1
#     tcpURGFlag = (tcpRestOfFLags >> 5) & 0x1
#     tcpACKFlag = (tcpRestOfFLags >> 4) & 0x1
#     tcpPSHFlag = (tcpRestOfFLags >> 3) & 0x1
#     tcpRSTFlag = (tcpRestOfFLags >> 2) & 0x1
#     tcpSYNFlag = (tcpRestOfFLags >> 1) & 0x1
#     tcpFINFlag = tcpRestOfFLags & 0x1
    
#     # The third H is 2 bytes and contains the window size.
#     tcpWindowSize = tcpHeaderUnpacked[6]
    
#     # The fourth H is 2 byte and conntains the checksum.
#     tcpChecksum = tcpHeaderUnpacked[7]
    
#     # The fifth H is 2 bytes and constains the urgent pointer.
#     tcpUrgentPointer = tcpHeaderUnpacked[8]
    
#     # Check if the print key is 0.
#     # If true, header information will be printed.
#     #   Check if the user selected extracted attribute index is 0.
#     #   If true, all attributes will be printed.
#     #   If false, the attribute the user selected extracted attribute index corresponds to will be printed.
#     # If false, the attribute the user selected attribute index corresponds to will be returned.
#     if printKey == 0:
#         # Print TCP Header
#         # Some segments of the header are switched back to hex form because that
#         #   is the format wireshark has it.
#         unpackedInfo.append('\n*******************\n******* TCP *******\n*******************')
    
#         if (extractedAttIndex == 1) or (extractedAttIndex == 0):
#             unpackedInfo.append('Source Port: ' + str(tcpSourcePort))
#         if (extractedAttIndex == 2) or (extractedAttIndex == 0):
#             unpackedInfo.append('Destination Port: ' + str(tcpDestPort))
#         if (extractedAttIndex == 3) or (extractedAttIndex == 0):
#             unpackedInfo.append('Sequence Number: ' + str(tcpSeqNumber))
#         if (extractedAttIndex == 4) or (extractedAttIndex == 0):
#             unpackedInfo.append('Acknowledgment Number: ' + str(tcpAckNumber))
#         if (extractedAttIndex == 5) or (extractedAttIndex == 0):
#             unpackedInfo.append('Data Offset: ' + str(tcpDataOffset) + ' 32-bit words')
#         if (extractedAttIndex == 6) or (extractedAttIndex == 0):
#             unpackedInfo.append('Reserved: ' + format(tcpReserved, '03b') + '. .... ....')
#         if (extractedAttIndex == 7) or (extractedAttIndex == 0):
#             unpackedInfo.append('NS Flag:  ' + '...' + format(tcpNSFlag, '01b') + ' .... ....')
#         if (extractedAttIndex == 8) or (extractedAttIndex == 0):
#             unpackedInfo.append('CWR Flag: ' + '.... ' + format(tcpCWRFlag, '01b') + '... ....')
#         if (extractedAttIndex == 9) or (extractedAttIndex == 0):
#             unpackedInfo.append('ECE Flag: ' + '.... .' + format(tcpECEFlag, '01b') + '.. ....')
#         if (extractedAttIndex == 10) or (extractedAttIndex == 0):
#             unpackedInfo.append('URG Flag: ' + '.... ..' + format(tcpURGFlag, '01b') + '. ....')
#         if (extractedAttIndex == 11) or (extractedAttIndex == 0):
#             unpackedInfo.append('ACK Flag: ' + '.... ...' + format(tcpACKFlag, '01b') + ' ....')
#         if (extractedAttIndex == 12) or (extractedAttIndex == 0):
#             unpackedInfo.append('PSH Flag: ' + '.... .... ' + format(tcpPSHFlag, '01b') + '...')
#         if (extractedAttIndex == 13) or (extractedAttIndex == 0):
#             unpackedInfo.append('RST Flag: ' + '.... .... .' + format(tcpRSTFlag, '01b') + '..')
#         if (extractedAttIndex == 14) or (extractedAttIndex == 0):
#             unpackedInfo.append('SYN Flag: ' + '.... .... ..' + format(tcpSYNFlag, '01b') + '.')
#         if (extractedAttIndex == 15) or (extractedAttIndex == 0):
#             unpackedInfo.append('FIN Flag: ' + '.... .... ...' + format(tcpFINFlag, '01b'))
#         if (extractedAttIndex == 16) or (extractedAttIndex == 0):
#             unpackedInfo.append('Window Size: ' + str(tcpWindowSize) + ' bytes')
#         if (extractedAttIndex == 17) or (extractedAttIndex == 0):
#             unpackedInfo.append('Urgent Pointer: ' + str(tcpUrgentPointer))
#         if (extractedAttIndex == 18) or (extractedAttIndex == 0):
#             unpackedInfo.append('Checksum: ' + format(tcpChecksum, '#04X'))
    
#         # Separator 
#         unpackedInfo.append('\n----------------------------------------')   
#     else:
#         if (extractedAttIndex == 1):
#             return str(tcpSourcePort)
#         if (extractedAttIndex == 2):
#             return str(tcpDestPort)
#         if (extractedAttIndex == 3):
#             return str(tcpSeqNumber)
#         if (extractedAttIndex == 4):
#             return str(tcpAckNumber)
#         if (extractedAttIndex == 5):
#             return str(tcpDataOffset)
#         if (extractedAttIndex == 6):
#             return format(tcpReserved, '03b')
#         if (extractedAttIndex == 7):
#             return format(tcpNSFlag, '01b')
#         if (extractedAttIndex == 8):
#             return format(tcpCWRFlag, '01b')
#         if (extractedAttIndex == 9):
#             return format(tcpECEFlag, '01b')
#         if (extractedAttIndex == 10):
#             return format(tcpURGFlag, '01b')
#         if (extractedAttIndex == 11):
#             return format(tcpACKFlag, '01b')
#         if (extractedAttIndex == 12):
#             return format(tcpPSHFlag, '01b')
#         if (extractedAttIndex == 13):
#             return format(tcpRSTFlag, '01b')
#         if (extractedAttIndex == 14):
#             return format(tcpSYNFlag, '01b')
#         if (extractedAttIndex == 15):
#             return format(tcpFINFlag, '01b')
#         if (extractedAttIndex == 16):
#             return str(tcpWindowSize)
#         if (extractedAttIndex == 17):
#             return str(tcpUrgentPointer)
#         if (extractedAttIndex == 18):
#             return format(tcpChecksum, '#04X')

# def udp(packet, extractedAttIndex, printKey):
#     # Header lengths.
#     ethHeaderLength = 14
#     ipHeaderLength = 20
#     udpHeaderLength = 8
    
#     # Get UDP header using begin and end.
#     # Specific Linux and Windows calibration is needed.
#     if os == linux:
#         begin = ethHeaderLength + ipHeaderLength
#         end = begin + udpHeaderLength
#     elif os == windows:
#         begin = ipHeaderLength
#         end = begin + udpHeaderLength
#     udpHeader = packet[begin:end]

#     # Unpack the header because it originally in hex.
#     # The regular expression helps unpack the header.
#     # ! signifies we are unpacking a network endian.
#     # H signifies we are unpacking an integer of size 2 bytes.
#     udpHeaderUnpacked = struct.unpack('!HHHH', udpHeader)
     
#     # The first H is 2 bytes and contains the source port.
#     udpSourcePort = udpHeaderUnpacked[0]
    
#     # The second H is 2 bytes and contains the destination port.
#     udpDestPort = udpHeaderUnpacked[1]
    
#     # The third H is 2 bytes and contains the packet length.
#     udpLength = udpHeaderUnpacked[2]
    
#     # The fourth H is 2 bytes and contains the header checksum.
#     udpChecksum = udpHeaderUnpacked[3]
    
#     # Check if the print key is 0.
#     # If true, header information will be printed.
#     #   Check if the user selected extracted attribute index is 0.
#     #   If true, all attributes will be printed.
#     #   If false, the attribute the user selected extracted attribute index corresponds to will be printed.
#     # If false, the attribute the user selected attribute index corresponds to will be returned.
#     if printKey == 0:
#         # Print UDP Header
#         unpackedInfo.append('\n*******************\n******* UDP *******\n*******************')
        
#         if (extractedAttIndex == 1) or (extractedAttIndex == 0):
#             unpackedInfo.append('Source Port: ' + str(udpSourcePort))
#         if (extractedAttIndex == 2) or (extractedAttIndex == 0):
#             unpackedInfo.append('Destination Port: ' + str(udpDestPort))
#         if (extractedAttIndex == 3) or (extractedAttIndex == 0):
#             unpackedInfo.append('Length: ' + str(udpLength) + ' bytes')
#         if (extractedAttIndex == 4) or (extractedAttIndex == 0):
#             unpackedInfo.append('Checksum: ' + format(udpChecksum, '#04X'))

#         # Separator 
#         unpackedInfo.append('\n----------------------------------------')   
#     else:
#         if (extractedAttIndex == 1):
#             return str(udpSourcePort)
#         if (extractedAttIndex == 2):
#             return str(udpDestPort)
#         if (extractedAttIndex == 3):
#             return str(udpLength)
#         if (extractedAttIndex == 4):
#             return format(udpChecksum, '#04X')
            
# def findProtocol(packet):
#     # Will hold the packet protocol.
#     packetProtocol = ''
    
#     # If the OS is Linux, unpack Ethernet's protocol.
#     # If the OS is Windows, mimic unpacking Ethernet's protocol.
#     if os == linux:
#         ethProtocol = eth(packet, 3, 1)
#         ethProtocol = int(ethProtocol)
#     elif os == windows:
#         ethProtocol = 8

#     # Find if the Ethernet protocol is ARP or IP.
#     # If the protocol is 1544, meaning ARP, then set packetProtocol to 0.
#     # If the protocol is 8, meaning IP, find the protocol within IP.
#     if ethProtocol == 1544:
#         packetProtocol = 1
#     elif ethProtocol == 8:
#         # Unpack IP's protocol.
#         ipProtocol = ip(packet, 10, 1)
#         ipProtocol = int(ipProtocol)
        
#         # If the protocol is 1, meaning ICMP, then set packetProtocol to 2 (Linux) or 1 (Windows).
#         # If the protocol is 6, meaning TCP, then set packetProtocol to 3 (Linux) or 2 (Windows).
#         # If the protocol is 17, meaning UDP, then set packetProtocol to 4 (Linux) or 3 (Windows).
#         if os == linux:
#             if ipProtocol == 1:
#                 packetProtocol = 2
#             elif ipProtocol == 6:
#                 packetProtocol = 3
#             elif ipProtocol == 17:
#                 packetProtocol = 4
#         elif os == windows:
#             if ipProtocol == 1:
#                 packetProtocol = 1
#             elif ipProtocol == 6:
#                 packetProtocol = 2
#             elif ipProtocol == 17:
#                 packetProtocol = 3
            
#     # Return the packet protocol.
#     return packetProtocol
    
# def extractAllAtt(packet):
#     # All attributes for each protocol will be displayed.
#     extractedAttIndex = 0
    
#     # Attributes will be printed.
#     printKey = 0
    
#     # If the OS is Linux, unpack Ethernet's protocol.
#     # If the OS is Windows, mimic unpacking Ethernet's protocol.
#     if os == linux:
#         # Unpack the Ethernet (MAC) information.
#         eth(packet, extractedAttIndex, printKey)
    
#         # Find the packet's Ethernet protocol.
#         ethProtocol = eth(packet, 3, 1)
#         ethProtocol = int(ethProtocol)
#     elif os == windows:
#         ethProtocol = 8

#     # Find if the Ethernet protocol is ARP or IP.
#     if ethProtocol == 1544:
#         # Unpack the ARP information.
#         arp(packet, extractedAttIndex, printKey)
#     elif ethProtocol == 8:
#         # Unpack IP's information.
#         ip(packet, extractedAttIndex, printKey)
        
#         # Find the packet's IP protocol.
#         ipProtocol = ip(packet, 10, 1)
#         ipProtocol = int(ipProtocol)
            
#         # If the protocol is 1, meaning ICMP, then unpack the ICMP information.
#         # If the protocol is 6, meaning TCP, then unpack the TCP information.
#         # If the protocol is 17, meaning UDP, then unpack the UDP information.
#         if ipProtocol == 1:
#             icmp(packet, extractedAttIndex, printKey)
#         elif ipProtocol == 6:
#             tcp(packet, extractedAttIndex, printKey)
#         elif ipProtocol == 17:
#             udp(packet, extractedAttIndex, printKey)

# def filterAndExtract(packet, filteredProtocolIndex, extractedAttIndex):
#     # Get the protocol index of the packet.
#     protocolIndex = findProtocol(packet)
    
#     if os == linux:
#         if (filteredProtocolIndex == protocolIndex) or (filteredProtocolIndex == 0):
#             # Attributes will be printed.
#             printKey = 0

#             # Find the user selected filtered protocol index.
#             if filteredProtocolIndex == 0:
#                 if extractedAttIndex >= 1:
#                     eth(packet, extractedAttIndex, printKey)

#                     # Separator
#                     unpackedInfo.append('\n----------------------------------------')
#                 elif extractedAttIndex == 0:
#                     extractAllAtt(packet)
#             elif filteredProtocolIndex == 1:
#                 # The user selected extracted attribute index will be calibrated (if needed) to specify which attribute to extract.
#                 if extractedAttIndex >= 4:
#                     arp(packet, extractedAttIndex - 3, printKey)
#                 elif extractedAttIndex >= 1:
#                     eth(packet, extractedAttIndex, printKey)

#                     # Separator
#                     unpackedInfo.append('\n----------------------------------------')
#                 elif extractedAttIndex == 0:
#                     extractAllAtt(packet)
#             elif filteredProtocolIndex == 2:
#                 if extractedAttIndex >= 17:
#                     icmp(packet, extractedAttIndex - 16, printKey)
#                 elif extractedAttIndex >= 4:
#                     ip(packet, extractedAttIndex - 3, printKey)

#                     unpackedInfo.append('\n----------------------------------------')   
#                 elif extractedAttIndex >= 1:    
#                     eth(packet, extractedAttIndex, printKey)

#                     unpackedInfo.append('\n----------------------------------------')
#                 elif extractedAttIndex == 0:
#                     extractAllAtt(packet)
#             elif filteredProtocolIndex == 3:
#                 if extractedAttIndex >= 17: 
#                     tcp(packet, extractedAttIndex - 16, printKey)
#                 elif extractedAttIndex >= 4:
#                     ip(packet, extractedAttIndex - 3, printKey)

#                     unpackedInfo.append('\n----------------------------------------')   
#                 elif extractedAttIndex >= 1:    
#                     eth(packet, extractedAttIndex, printKey)

#                     unpackedInfo.append('\n----------------------------------------')   
#                 elif extractedAttIndex == 0:
#                     extractAllAtt(packet)
#             elif filteredProtocolIndex == 4:
#                 if extractedAttIndex >= 17: 
#                     udp(packet, extractedAttIndex - 16, printKey)
#                 elif extractedAttIndex >= 4:
#                     ip(packet, extractedAttIndex - 3, printKey)

#                     unpackedInfo.append('\n----------------------------------------')   
#                 elif extractedAttIndex >= 1:    
#                     eth(packet, extractedAttIndex, printKey)

#                     unpackedInfo.append('\n----------------------------------------')   
#                 elif extractedAttIndex == 0:
#                     extractAllAtt(packet)
#             return 0
#         else:
#             return 1    
#     elif os == windows:
#         if (filteredProtocolIndex == protocolIndex) or (filteredProtocolIndex == 0):
#             # Attributes will be printed.
#             printKey = 0
            
#             # Find the user selected filtered protocol index.
#             if filteredProtocolIndex == 0:
#                 if extractedAttIndex >= 1:
#                     ip(packet, extractedAttIndex, printKey)

#                     # Separator
#                     unpackedInfo.append('\n----------------------------------------')
#                 elif extractedAttIndex == 0:
#                     extractAllAtt(packet)
#             elif filteredProtocolIndex == 1:
#                 # The user selected extracted attribute index will be calibrated (if needed) to specify which attribute to extract.
#                 if extractedAttIndex >= 14: 
#                     icmp(packet, extractedAttIndex - 13, printKey)
#                 elif extractedAttIndex >= 1:
#                     ip(packet, extractedAttIndex, printKey)
                        
#                     # Separator 
#                     unpackedInfo.append('\n----------------------------------------')   
#                 elif extractedAttIndex == 0:
#                     extractAllAtt(packet)
#             elif filteredProtocolIndex == 2:
#                 if extractedAttIndex >= 14: 
#                     tcp(packet, extractedAttIndex - 13, printKey)
#                 elif extractedAttIndex >= 1:
#                     ip(packet, extractedAttIndex, printKey)
                        
#                     unpackedInfo.append('\n----------------------------------------')   
#                 elif extractedAttIndex == 0:
#                     extractAllAtt(packet)
#             elif filteredProtocolIndex == 3:
#                 if extractedAttIndex >= 14: 
#                     udp(packet, extractedAttIndex - 13, printKey)
#                 elif extractedAttIndex >= 1:
#                     ip(packet, extractedAttIndex, printKey)
                        
#                     unpackedInfo.append('\n----------------------------------------')   
#                 elif extractedAttIndex == 0:
#                     extractAllAtt(packet)
#             return 0
#         else:
#             return 1            
                
# def findMaxDiameter():
#     # Find the maximum diameter of all the packets.
#     maxDiameter = max(diameterList)
    
#     # Print the maximum diameter.
#     calculationList.append('Max Diameter: ' + str(maxDiameter) + ' hops')
    
# def findMaxPacketLength():
#     # Find the maximum packet length of all the packets.
#     maxLength = max(lengthList)

#     # Print the maximum packet length.
#     calculationList.append('Max Packet Length: ' + str(maxLength) + ' bytes')

# def findAvgDiameter():
#     # Hold the sum and the count of the diameters.
#     diameterSum = 0
#     count = 0
#     avgDiameter = 0
    
#     # Add all of the diameters together.
#     for diameter in diameterList:
#         diameterSum = diameterSum + diameter
#         count = count + 1
        
#     # Divide diameterSum by count to give average.
#     avgDiameter = diameterSum / count
#     calculationList.append('Avg Diameter: ' + str(avgDiameter) + ' hops')

# def findAvgPacketLength():
#     # Hold the sum and the count of the packet lengths.
#     lengthSum = 0
#     count = 0
#     avgLength = 0
    
#     # Add all of the lengths together.
#     for length in lengthList:
#         lengthSum = lengthSum + length
#         count = count + 1

#     # Divide lengthSum by count to give average.
#     avgLength = lengthSum / count
#     calculationList.append('Avg Packet Length: ' + str(avgLength) + ' bytes')

# def startSniff():
#     try:
#         while True:
#             # Ask the user if they would like to begin sniffing.
#             decision = raw_input('Sniff the network? Y/N: ')
            
#             # Y runs the rest of the application.
#             # N exits the application.
#             if (decision == 'Y') or (decision == 'y'):
#                 break
#             elif (decision == 'N') or (decision == 'n'):
#                 close()
#             else:
#                 print('\nUnsupported input...')
#     except KeyboardInterrupt:
#         print('')
#         close()

# def startFilter():
#     try:
#         while True:
#             # Ask the user if they would like to filter the packets.
#             decision = raw_input('Filter the packets by a specific protocol? Y/N: ')

#             # Y runs the rest of the application.
#             # N exits the application.
#             if (decision == 'Y') or (decision == 'y'):
#                 print('Select a protocol...')
#                 return 0
#             elif (decision == 'N') or (decision == 'n'):
#                 return 1
#             else:
#                 print('\nUnsupported input...')
#     except KeyboardInterrupt:
#         print('')
#         return 1

# def startExtract():
#     try:
#         while True:
#             # Ask the user if they would like to extract attributes.
#             decision = raw_input('Extract a specific attribute from the protocol? Y/N: ')
            
#             # Y runs the rest of the application.
#             # N exits the application.
#             if (decision == 'Y') or (decision == 'y'):
#                 print('Select an attribute...')
#                 return 0
#             elif (decision == 'N') or (decision == 'n'):
#                 return 1
#             else:
#                 print('\nUnsupported input...')
#     except KeyboardInterrupt:
#         print('')
#         return 1

# def startCalculations():
#     try:
#         while True:
#             # Ask the user if they would like to start calculations.
#             decision = raw_input('Would you like to do some calculations? Y/N: ')
            
#             # Y runs the rest of the application.
#             # N exits the application.
#             if (decision == 'Y') or (decision == 'y'):
#                 return 0
#             elif (decision == 'N') or (decision == 'n'):
#                 return 1
#             else:
#                 print('\nUnsupported input...')
#     except KeyboardInterrupt:
#         print('')
#         return 1    

# def filterOptions():
#     if os == linux:
#         # Loop if unsupported input.
#         while True:
#             # Display protocols and their index.
#             filteredProtocolIndex = raw_input('0: All\n1: ARP\n2: ICMP\n3: TCP\n4: UDP\nSelection: ')
            
#             # Check if the user selected filtered protocol index is supported input.
#             try:
#                 filteredProtocolIndex = int(filteredProtocolIndex)
#             except ValueError:
#                 print('\nUnsupported input, try again...')
#                 continue
            
#             # Check if the user selected filtered protocol index is in the index range.
#             # If true, return filteredProtocolIndex.
#             if (filteredProtocolIndex >= 0) and (filteredProtocolIndex <= 4):
#                 return filteredProtocolIndex
#             else:
#                 print('\nUnsupported input, try again...')
#                 continue
#     elif os == windows:
#         # Loop if unsupported input.
#         while True:
#             # Display protocols and their index.
#             filteredProtocolIndex = raw_input('0: All\n1: ICMP\n2: TCP\n3: UDP\nSelection: ')
            
#             # Check if the user selected filtered protocol index is supported input.
#             try:
#                 filteredProtocolIndex = int(filteredProtocolIndex)
#             except ValueError:
#                 print('\nUnsupported input, try again...')
#                 continue
            
#             # Check if the user selected filtered protocol index is in the index range.
#             # If true, return filteredProtocolIndex.
#             if (filteredProtocolIndex >= 0) and (filteredProtocolIndex <= 3):
#                 return filteredProtocolIndex
#             else:
#                 print('\nUnsupported input, try again...')
#                 continue
                
# def extractOptions(filteredProtocolIndex):
#     if os == linux:
#         # Establish the prompts for each protocol's attributes.
#         allAttributes = '0: All'
#         ethAttributes = '1: Destination Address\n2: Source Address\n3: EtherType'
#         arpAttributes = '4: Hardware Type\n5: Protocol Type\n6: Hardware Address Length\n7: Protocol Address Length\n8: Operation\n9: Sender Hardware Address\n10: Sender Protocol Address\n11: Target Hardware Address\n12: Target Protocol Address'
#         ipAttributes =  '4: Version\n5: Header Length\n6: Differentiated Services Code Point\n7: Explicit Congestion Notification\n8: Total Length\n9: Identification\n10: Flags\n11: Fragment Offset\n12: Time to Live\n13: Protocol\n14: Header Checksum\n15: Source Address\n16: Destination Address'
#         icmpAttributes = '17: Type\n18: Code\n19: Checksum\n20: Identifier (If available)\n21: Sequence Number (If available)'
#         tcpAttributes = '17: Source Port\n18: Destination Port\n19: Sequence Number\n20: Acknowledgment Number\n21: Data Offset\n22: Reserved\n23: NS Flag\n24: CWR Flag\n25: ECE Flag\n26: URG Flag\n27: ACK Flag\n28: PSH Flag\n29: RST Flag\n30: SYN Flag\n31: FIN Flag\n32: Window Size\n33: Urgent Pointer\n34: Checksum'
#         udpAttributes = '17: Source Port\n18: Destination Port\n19: Length\n20: Checksum'
        
#         # Loop if unsupported input.
#         while True:
#             # Find the user selected filtered protocol index.
#             # Return the user selected extracted attribute index.
#             if filteredProtocolIndex == 0:
#                 # Display the appropriate attributes and their index available to the filtered protocol.
#                 print(allAttributes)
#                 print(ethAttributes)
#                 extractedAttIndex = raw_input('Selection: ')
                
#                 # Check if the user selected extracted attribute index is supported input.
#                 try:
#                     extractedAttIndex = int(extractedAttIndex)
#                 except ValueError:
#                     print('\nUnsupported input, try again...')
#                     continue
                
#                 # Check if the user selected extracted attribute index is in the index range.
#                 # If true, return extractedAttIndex
#                 if (extractedAttIndex >= 0) or (extractedAttIndex <= 3):
#                     return extractedAttIndex
#                 else:
#                     print('\nUnsupported input, try again...')
#                     continue
#             elif filteredProtocolIndex == 1:
#                 # Display the appropriate attributes and their index available to the filtered protocol.
#                 print(allAttributes)
#                 print(ethAttributes)
#                 print(arpAttributes)
#                 extractedAttIndex = raw_input('Selection: ')
                
#                 # Check if the user selected extracted attribute index is supported input.
#                 try:
#                     extractedAttIndex = int(extractedAttIndex)
#                 except ValueError:
#                     print('\nUnsupported input, try again...')
#                     continue
                
#                 # Check if the user selected extracted attribute index is in the index range.
#                 # If true, return extractedAttIndex
#                 if (extractedAttIndex >= 0) or (extractedAttIndex <= 12):
#                     return extractedAttIndex
#                 else:
#                     print('\nUnsupported input, try again...')
#                     continue
#             elif filteredProtocolIndex == 2:
#                 print(allAttributes)
#                 print(ethAttributes)
#                 print(ipAttributes)
#                 print(icmpAttributes)
#                 extractedAttIndex = raw_input('Selection: ')
                
#                 try:
#                     extractedAttIndex = int(extractedAttIndex)
#                 except ValueError:
#                     print('\nUnsupported input, try again...')
#                     continue
                
#                 if (extractedAttIndex >= 0) or (extractedAttIndex <= 21):
#                     return extractedAttIndex
#                 else:
#                     print('\nUnsupported input, try again...')
#                     continue
#             elif filteredProtocolIndex == 3:
#                 print(allAttributes)
#                 print(ethAttributes)
#                 print(ipAttributes)
#                 print(tcpAttributes)
#                 extractedAttIndex = raw_input('Selection: ')
                
#                 try:
#                     extractedAttIndex = int(extractedAttIndex)
#                 except ValueError:
#                     print('\nUnsupported input, try again...')
#                     continue
                
#                 if (extractedAttIndex >= 0) or (extractedAttIndex <= 34):
#                     return extractedAttIndex
#                 else:
#                     print('\nUnsupported input, try again...')
#                     continue
#             elif filteredProtocolIndex == 4:
#                 print(allAttributes)
#                 print(ethAttributes)
#                 print(ipAttributes)
#                 print(udpAttributes)
#                 extractedAttIndex = raw_input('Selection: ')
                
#                 try:
#                     extractedAttIndex = int(extractedAttIndex)
#                 except ValueError:
#                     print('\nUnsupported input, try again...')
#                     continue
                
#                 if (extractedAttIndex >= 0) or (extractedAttIndex <= 20):
#                     return extractedAttIndex
#                 else:
#                     print('\nUnsupported input, try again...')
#                     continue
#     elif os == windows:
#         # Establish the prompts for each protocol's attributes.
#         allAttributes = '0: All'
#         ipAttributes =  '1: Version\n2: Header Length\n3: Differentiated Services Code Point\n4: Explicit Congestion Notification\n5: Total Length\n6: Identification\n7: Flags\n8: Fragment Offset\n9: Time to Live\n10: Protocol\n11: Header Checksum\n12: Source Address\n13: Destination Address'
#         icmpAttributes = '14: Type\n15: Code\n16: Checksum\n17: Identifier (If available)\n18: Sequence Number (If available)'
#         tcpAttributes = '14: Source Port\n15: Destination Port\n16: Sequence Number\n17: Acknowledgment Number\n18: Data Offset\n19: Reserved\n20: NS Flag\n21: CWR Flag\n22: ECE Flag\n23: URG Flag\n24: ACK Flag\n25: PSH Flag\n26: RST Flag\n27: SYN Flag\n28: FIN Flag\n29: Window Size\n30: Urgent Pointer\n31: Checksum'
#         udpAttributes = '14: Source Port\n15: Destination Port\n16: Length\n17: Checksum'
        
#         # Loop if unsupported input.
#         while True:
#             # Find the user selected filtered protocol index.
#             # Return the user selected extracted attribute index.
#             if filteredProtocolIndex == 0:
#                 # Display the appropriate attributes and their index available to the filtered protocol.
#                 print(allAttributes)
#                 print(ipAttributes)
#                 extractedAttIndex = raw_input('Selection: ')
                
#                 # Check if the user selected extracted attribute index is supported input.
#                 try:
#                     extractedAttIndex = int(extractedAttIndex)
#                 except ValueError:
#                     print('\nUnsupported input, try again...')
#                     continue
                
#                 # Check if the user selected extracted attribute index is in the index range.
#                 # If true, return extractedAttIndex
#                 if (extractedAttIndex >= 0) or (extractedAttIndex <= 3):
#                     return extractedAttIndex
#                 else:
#                     print('\nUnsupported input, try again...')
#                     continue
#             elif filteredProtocolIndex == 1:
#                 # Display the appropriate attributes and their index available to the filtered protocol.
#                 print(ipAttributes)
#                 print(icmpAttributes)
#                 extractedAttIndex = raw_input('Selection: ')
                
#                 # Check if the user selected extracted attribute index is in the index range.
#                 # If true, return extractedAttIndex
#                 try:
#                     extractedAttIndex = int(extractedAttIndex)
#                 except ValueError:
#                     print('\nUnsupported input, try again...')
#                     continue

#                 if (extractedAttIndex >= 0) or (extractedAttIndex <= 18):
#                     return extractedAttIndex
#                 else:
#                     print('\nUnsupported input, try again...')
#                     continue
#             elif filteredProtocolIndex == 2:
#                 print(ipAttributes)
#                 print(tcpAttributes)
#                 extractedAttIndex = raw_input('Selection: ')
                
#                 try:
#                     extractedAttIndex = int(extractedAttIndex)
#                 except ValueError:
#                     print('\nUnsupported input, try again...')
#                     continue
                
#                 if (extractedAttIndex >= 0) or (extractedAttIndex <= 21):
#                     return extractedAttIndex
#                 else:
#                     print('\nUnsupported input, try again...')
#                     continue
#             elif filteredProtocolIndex == 3:
#                 print(ipAttributes)
#                 print(udpAttributes)
#                 extractedAttIndex = raw_input('Selection: ')
                
#                 try:
#                     extractedAttIndex = int(extractedAttIndex)
#                 except ValueError:
#                     print('\nUnsupported input, try again...')
#                     continue
                
#                 if (extractedAttIndex >= 0) or (extractedAttIndex <= 17):
#                     return extractedAttIndex
#                 else:
#                     print('\nUnsupported input, try again...')
#                     continue

# def prepareCalculationData(packet):
#     # If the OS is Linux, unpack Ethernet's protocol.
#     # If the OS is Windows, mimic unpacking Ethernet's protocol.
#     if os == linux:
#         # Find the packet's Ethernet protocol.
#         ethProtocol = eth(packet, 3, 1)
#         ethProtocol = int(ethProtocol)
#     elif os == windows:
#         ethProtocol = 8

#     # Find if the Ethernet protocol is IP.
#     # If the protocol is 8, meaning IP, find the diameter and find the protocol within IP.
#     if ethProtocol == 8:
#         # Append the IP total length to the length list.
#         # Append the diameters to the diameter list using TTL.
#         # These will be used for calculations.
#         ipTotalLength = ip(packet, 5, 1)
#         ipTotalLength = int(ipTotalLength)
#         lengthList.append(ipTotalLength)
            
#         # Find the diameter of the network.
#         # Different servers have different operating systems that have different TTLs.
#         # Cisco is 255, Windows is 128, Linux is 64.
#         ipTimeToLive = ip(packet, 9, 1)
#         ipTimeToLive = int(ipTimeToLive)
        
#         if ipTimeToLive > 128:
#             diameterList.append(255 - ipTimeToLive)
#         elif ipTimeToLive > 64:
#             diameterList.append(128 - ipTimeToLive)
#         else:
#             diameterList.append(64 - ipTimeToLive)
            
#         return 0
#     else:
#         return 1

# def calculateData():
#     try:        
#         findMaxDiameter()
#         findMaxPacketLength()
#         findAvgDiameter()
#         findAvgPacketLength()
#     except KeyboardInterrupt:
#         print('\nCalculations stopped.')

# def close():
#     try:
#         # Exit the application.
#         print('Goodbye.')
#         time.sleep(1)
#         sys.exit()
#     except KeyboardInterrupt:
#         sys.exit()

# def sniff():
#     try:
#         # Ask user to filter by protocol.
#         # If true, set filteredProtcolIndex to selected protocol.
#         # If false, set filteredProtocolIndex to 0 (All).
#         if startFilter() == 0:
#             filteredProtocolIndex = filterOptions()
#         else:
#             filteredProtocolIndex = 0

#         # Ask user to extract an attribute.
#         # If true, set extractedAttIndex to selected attribute.
#         # If false, set extractedAttIndex to 0 (All).
#         if startExtract() == 0:
#             extractedAttIndex = extractOptions(filteredProtocolIndex)
#         else:
#             extractedAttIndex = 0

#         # Notify the user the application is sniffing.
#         print('Sniffing... Ctrl+c to stop...')

#         # If Linux, set up the raw socket the Linux way.
#         # If Windows, set up the raw socket the Windows way.
#         if os == linux:
#             # Create the raw socket.
#             sock = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))

#             # Sniff packets. Will loop until user presses Ctrl+c.
#             while True:
#                 # Recieve the packets in the network.
#                 # Packet will be a tuple, use the first element in the tuple.
#                 packet = sock.recvfrom(65565)
#                 packet = packet[0]      
                
#                 # Delete the data inside the lists containing unpacked info and calculations.
#                 # This is needed as these lists can contain data about a current packet being sniffed.
#                 del unpackedInfo[:]
#                 del calculationList[:]      

#                 # Filter and extract packet info using packet, filteredProtocolIndex and extractedAttIndex.
#                 # Save the packet for other operations.
#                 filterAndExtractVar = filterAndExtract(packet, filteredProtocolIndex, extractedAttIndex)
                
#                 # Check if the user selected filtered protocol index is supported.
#                 # If true, print the unpacked info.
#                 if filterAndExtractVar == 0:
#                     for i in range(len(unpackedInfo)):
#                         print(unpackedInfo[i])
                    
#                     prepareCalculationDataVar = prepareCalculationData(packet)
                    
#                     if prepareCalculationDataVar == 0:
#                         calculateData()

#         elif os == windows:
#             # The public network interface.
#             HOST = socket.gethostbyname(socket.gethostname())

#             # Create a raw socket and bind it to the public interface.
#             sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
#             sock.bind((HOST, 0))

#             # Include IP headers
#             sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

#             # Receive all packages.
#             sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
#             # Sniff packets. Will loop until user presses Ctrl+c.
#             while True: 
#                 # Recieve the packets in the network.
#                 # Packet will be a tuple, use the first element in the tuple.
#                 packet = sock.recvfrom(65565)
#                 packet = packet[0]      
                
#                 # Delete the data inside the lists containing unpacked info and calculations.
#                 # This is needed as these lists can contain data about a current packet being sniffed.
#                 del unpackedInfo[:]
#                 del calculationList[:]      

#                 # Filter and extract packet info using packet, filteredProtocolIndex and extractedAttIndex.
#                 # Save the packet for other operations.
#                 filterAndExtractVar = filterAndExtract(packet, filteredProtocolIndex, extractedAttIndex)
                
#                 # Check if the user selected filtered protocol index is supported.
#                 # If true, print the unpacked info.
#                 if filterAndExtractVar == 0:
#                     for i in range(len(unpackedInfo)):
#                         print(unpackedInfo[i])
                    
#                     prepareCalculationDataVar = prepareCalculationData(packet)
                    
#                     if prepareCalculationDataVar == 0:
#                         calculateData()
#     except socket.error, msg:
#         print('Socket could not be created. \nError code: ' + str(msg[0]) + '\nMessage: ' + msg[1])
#         close()
#     except KeyboardInterrupt:
#         print('\nSniffing stopped.')
        
#         # Disable promiscuous mode under Windows.
#         if os == windows:
#             sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
  
#         # Close the socket.
#         sock.close()

#         if startCalculations() == 0:
#             for i in range(len(calculationList)):
#                 print(calculationList[i])

# def main():
#     if (os == linux) or (os == windows):
#         while True:
#             # Ask the user to begin sniffing.
#             startSniff()
            
#             # Begin sniffing.
#             sniff()
#     else:
#         print('The OS you are running is not supported.')
        
#     close()

# if __name__ == '__main__':
#     main()