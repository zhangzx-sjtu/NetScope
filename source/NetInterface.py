from scapy.all import *
import fcntl

''' In this module, we get the network adapter information'''

class NetInterface():
    def __init__(self):
        self.data_dict = self.get_dev_information()
        self.ip_address_dict = self.get_ip_information()

    def get_dev_information(self):  
        '''
        get the network adapters' information
        return in the form of dict
        {name:[receive_byte, transmit_packets]}
        and name is string
        the elements in the list are also string  (unit:MB)
        '''
        with open('/proc/net/dev') as f:
            lines = f.readlines()
        # lines includes all the network adapter information

        data = {}
        for line in lines[2:]:
            # every line includes the information of one NA
            line = line.split(':')

            NA_name = line[0].strip()  # the network adapter's name
            info = line[1].split()
            NA_receive_byte = format(float(info[0])/(1024*1024),'0.2f')
            #NA_receive_packets = format(float(info[1])/(1024*1024),'0.2f')
            NA_transmit_bytes = format(float(info[8])/(1024*1024),'0.2f')
            #NA_transmit_packets = format(float(info[9])/(1024*1024),'0.2f')

            # use list to store the information of a network adapter
            NA_data = [NA_receive_byte, NA_transmit_bytes]

            data[NA_name] = NA_data

        return data

    def get_ip_information(self):
        '''
        get the ip address of each network adapter
        return in the form of dict
        {name:ip_address}  e.g. {'etho':'192.168.1.100'}
        '''

        ip_address_dict = {}
        for name in self.data_dict:
            ip_address_dict[name] = self.get_ip_address(name)

        return ip_address_dict

    def get_ip_address(self, NA_name):
        '''
        A well-known method to get the ip address of a network adapter
        '''
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            addr = socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,
                struct.pack('256s', NA_name[:15])
            )[20:24])
            return addr
        except:
            return ""

    def get_name_list(self):
        '''get the name list'''

        return self.data_dict.keys()


if __name__ == "__main__":
    a = NetInterface()
    print a.data_dict
    print a.ip_address_dict

