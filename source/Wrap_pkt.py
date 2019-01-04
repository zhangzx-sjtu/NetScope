from scapy.all import *

class Wrap_pkt():
    def __init__(self, id=None, time=None, src=None, dst=None, proto=None, packet=None, info=None):
        self.id = id
        self.time = time # Time
        self.src = src
        self.dst = dst
        self.proto = proto # Protocols
        self.info = info
        self.packet = packet  # Packets entities.

        # Attributes dicts
        self.Ethernet = {}  # Everyone has it
        self.IP = {}  # Only ip
        self.ARP = {} # Only arp 
        self.IPv6 = {} # Only ipv6 

        self.underIP = {} # only ip :for the protocols under IP layer
        self.underUDP = {} # only udp :for the protocols under UDP layer

    def info_initialize(self): # Initialize the Wrap_pkt class to extract header information of a packet.
        self.Ethernet = self.get_Ethernet_information()
        if self.proto == 'arp':
            self.ARP = self.get_ARP_information()
        elif self.proto == 'ipv6':
            self.IPv6 = self.get_IPv6_information()
        elif self.proto is not None:
            # tcp/udp/icmp/dns/dhcp
            self.IP = self.get_IP_information()
            if self.proto == 'tcp':
                self.underIP = self.get_TCP_information()
            elif self.proto == 'icmp':
                self.underIP = self.get_ICMP_information()
            elif self.proto == 'igmp':
                self.underIP = self.get_IGMP_information()
            elif self.proto == 'udp':
                self.underIP = self.get_UDP_information()
            elif self.proto == 'dhcp':
                self.underIP = self.get_UDP_information()
                self.underUDP = self.get_DHCP_information()
            elif self.proto == 'dns':
                self.underIP = self.get_UDP_information()
                self.underUDP = self.get_DNS_information()
            else:
                pass
        else:
            pass

    def get_IP_information(self): # Extract header information from an IP packet.

        contents = ['version', 'ihl', 'tos', 'len','id', 'flags', 'frag',
                    'ttl', 'proto', 'chksum', 'src', 'dst', 'options']
        res = {}

        for content in contents:
             res[content] = getattr(self.packet.getlayer(IP), content, '')

        return res

    def get_IPv6_information(self): # Extract header information from an IPv6 packet.
        contents = ['version', 'tc', 'fl', 'plen', 'nh', 'hlim', 'src', 'dst']
        res = {}

        for content in contents:
            res[content] = getattr(self.packet.getlayer(IPv6), content, '')

        return res

    def get_TCP_information(self): # Extract header information from an TCP packet.
        contents = ['sport', 'dport', 'seq', 'ack', 'dataofs', 'reserved', 'flags',
                    'window', 'chksum', 'urgptr', 'options']
        res = {}

        for content in contents:
            res[content] = getattr(self.packet.getlayer(TCP), content, '')

        return res

    def get_IGMP_information(self): # Extract header information from an IGMP packet.
	# Note that there is no IGMP packet class in lib Scapy.
	# We should analyze it by ourselves in the raw data.
        contents = ['type', 'mrt','chksum','group_addr']

        res = {}
        raw_data_int = []
        raw_data_str = self.packet.getlayer(Raw).load
        print raw_data_str
        for i in range(0,16):
            raw_data_int.append(ord(raw_data_str[i]))
        
        if raw_data_int[0] == 17:
            res['type'] = 'Membership Query'
        elif raw_data_int[0] == 18:
            res['type'] = 'Version 1 Membership Report'
        elif raw_data_int[0] == 22:
            res['type'] = 'Version 2 Membership Report'
        elif raw_data_int[0] == 34:
            res['type'] = 'Version 3 Membership Report'
        else:
            res['type'] = 'Version 2 Leave Group'

        if res['type'] == 'Membership Query':
            res['mrt'] = str(raw_data_int[1])
        else:
            res['mrt'] = 'Reserved'

        res['chksum'] = ord(raw_data_str[2])*256+ord(raw_data_str[3])
        
        if res['type'] == 'Membership Query':
            res['group_addr'] = str(raw_data_int[4])+'.'+str(raw_data_int[5])+'.'+str(raw_data_int[6])+'.'+str(raw_data_int[7])
        else:
            res['group_addr'] = 'Reserved'
        
        return res 

    def get_UDP_information(self): # Extract header information from an UDP packet.

        contents = ['sport', 'dport', 'len', 'chksum']

        res = {}
        for content in contents:
            res[content] = getattr(self.packet.getlayer(UDP), content, '')

        return res

    def get_ICMP_information(self): # Extract header information from an ICMP packet.
        contents = ['type', 'code', 'chksum', 'id', 'seq']
        res = {}
        for content in contents:
            res[content] = getattr(self.packet.getlayer(ICMP), content, '')

        return res

    def get_ARP_information(self): # Extract header information from an ARP packet.
        contents = ['hwtype', 'ptype', 'hwlen', 'plen', 'op', 'hwsrc', 'psrc', 'hwdst', 'pdst']
        res = {}
        for content in contents:
            res[content] = getattr(self.packet.getlayer(ARP), content, '')

        return res

    def get_DNS_information(self): # Extract header information from an DNS packet.
        contents = ['id', 'qr', 'opcode', 'rcode']
        res = {}
        for content in contents:
            res[content] = getattr(self.packet.getlayer(DNS), content, '')
        res['qname'] = self.packet.getlayer(DNS).qd.qname
        res['qtype'] = self.packet.getlayer(DNS).qd.qtype
        res['qclass'] = self.packet.getlayer(DNS).qd.qclass        
        a = self.packet.getlayer(DNSRR)
        res['rdata'] = []
        i = 0
        try:
            while True:
                res['rdata'].append(a[i].rdata)
                i = i + 1
        except:
            return res    

        return res

    def get_DHCP_information(self): # Extract header information from an DHCP packet.
        contents = ['options']
        res = {}
        for content in contents:
            res[content] = getattr(self.packet.getlayer(DHCP),content, '')
        
        return res

    def get_Ethernet_information(self): # Extract header information from Ethernet layer.
        contents = ['src', 'dst', 'type']
        res = {}
        for content in contents:
            res[content] = getattr(self.packet.getlayer(Ether), content, '')

        return res
 
'''-----------------------------------------------------------------------------------''' 
if __name__ == "__main__":
    a = Wrap_pkt()
    a.packet = sniff(iface="ens33",count=1,filter='igmp')[0]
    c = a.get_IGMP_information()
    print c