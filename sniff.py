import socket
import struct
import binascii

list2 = ['Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)', 'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)', 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)' ]

s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
count=int(0)
while True:
    data= s.recvfrom(65565)
    if "HTTP" in data[0][54:] and "2375" in data[0][54:]:
        raw=data[0][54:]
        if "\r\n\r\n" in raw:
            count=count+1
            print count
            line=raw.split('\r\n\r\n')[0]
            print "[*] Header Captured "
            storeobj=struct.unpack("!BBHHHBBH4s4s", data[0][14:34])
            _source_address =socket.inet_ntoa(storeobj[8])
            _destination_address =socket.inet_ntoa(storeobj[9])
            data={"Source Address":_source_address,
            "Destination Address":_destination_address}
            print data
            print line[line.find('HTTP'):]
            for i in list2:
                if i in raw:
                    print('This can be a meterpreter attempt' )
                    break
