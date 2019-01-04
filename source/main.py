from PyQt4 import QtCore, QtGui
from scapy.all import *
from MainWindow import Ui_MainWindow
from InterfaceGUI import InterfaceGUI
from Filter import MyFilterGUI
from Searcher import MySearcherGUI
from Wrap_pkt import Wrap_pkt
from recombination_ip import RecombinationIPGUI
from FilesRecombine import FilesRecombineGUI
import webbrowser
import os
import threading
import time

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class myapp(QtGui.QMainWindow, Ui_MainWindow):#The object of our app.
    def __init__(self):
        super(self.__class__, self).__init__()
        self.setupUi(self)
        self.w_pkts = {} # The dictionary of acquired packets (instances of class "Wrap_pkt")
        self.raw_pkts = {} # The dictionary of aquired packets (without header extractions)
        self.id_list = []
        self.BEGIN = False # Whether the sniffing process has started.
        self.STOP = True # Whether the sniffing process has stopped.
        self.priviledge = True
        self.filter_rule = None
        self.searcher_rule = None
        self.count = 0 # The number of sniffed packets.
        self.init_time = 0 
        self.thread_is_on = 0 # Whether the sniffing thread is on.
        self.e = threading.Event()
        self.app_init()  # Extra init-process in mainwindow
		
        # First we have to choose an interface.
        self.do_interface()
        
    def app_init(self):#The necessary initialization process of some GUI items, including colors, fonts, signals, slots, and etc.
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("icon/icon.png"),QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.setWindowIcon(icon)
        self.PacketList.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.PacketList.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.PacketList.setSelectionMode(QtGui.QAbstractItemView.ExtendedSelection)
        self.PacketList.setColumnWidth(0, 70)
        self.PacketList.setColumnWidth(1, 120)
        self.PacketList.setColumnWidth(2, 120)
        self.PacketList.setColumnWidth(3, 80)
        self.PacketList.horizontalHeader().font().setBold(True);
        self.PacketList.horizontalHeader().setStyleSheet(_fromUtf8("font: 14pt \"Times New Roman\";\n" "border-width: 0px;"))
        self.PacketList.setStyleSheet(_fromUtf8("font: 13pt \"Times New Roman\";\n" "border-width: 0px;\n" "selection-background-color: rgb(27,1,137);"))
        self.Ethernet_text.setStyleSheet(_fromUtf8("font: 12pt \"Times New Roman\";\n" "background-color: rgb(235,247,249);\n" "border-width: 0px;"))
        self.ip_text.setStyleSheet(_fromUtf8("font: 12pt \"Times New Roman\";\n"  "background-color: rgb(235,247,249);\n" "border-width: 0px;"))
        self.more_text.setStyleSheet(_fromUtf8("font: 12pt \"Times New Roman\";\n" "background-color: rgb(235,247,249);\n" "border-width: 0px;"))
        self.RawDataHex.setStyleSheet(_fromUtf8("font: 12pt \"Times New Roman\";\n" "background-color: rgb(255, 246, 239);\n" "border-width: 0px;"))
        self.RawDataStr.setStyleSheet(_fromUtf8("font: 12pt \"Times New Roman\";\n" "background-color: rgb(255, 246, 239);\n" "border-width: 0px;"))
        self.actionOpen.triggered.connect(self.open_pcap)
        self.actionSave_as_pcap.triggered.connect(self.save_pcap)
        self.actionSave_as_txt.triggered.connect(self.save_txt)
        self.actionChange_Interface.triggered.connect(self.do_interface)
        self.actionBegin.triggered.connect(self.start_sniffing)
        self.actionStop.triggered.connect(self.stop_sniffing)
        self.actionClear_History.triggered.connect(self.clean)
        self.actionFilter.triggered.connect(self.do_filter)
        self.actionSearch.triggered.connect(self.do_searcher)
        self.actionIP_Recombine.triggered.connect(self.recombine_ip)
        self.actionFTP_Files_Monitoring.triggered.connect(self.File_reconstruct)
        self.actionAbout.triggered.connect(self.help)
        self.actionExit.triggered.connect(self.my_close)

    def start_sniffing(self):#Start sniffing in another thread.
        print "Try to Start!"
        self.BEGIN = True
        self.STOP = False
        self.e.clear()
        time.sleep(0.2)
        self.priviledge = True
        self.thread = threading.Thread(target=self.sniffing)
        self.thread.start()

        time.sleep(0.2)
        if self.priviledge:
            self.StartButton.setEnabled(False)
            self.StopButton.setEnabled(True)

            print "the thread is on!"
        else:
            self.Begin = False
            self.Stop = True
            QtGui.QMessageBox.critical(self, "Error", 'You do not have enough priviledge')
        
    def stop_sniffing(self):#Stop sniffing.
        self.BEGIN = False
        self.STOP = True
        self.StartButton.setEnabled(True)
        self.StopButton.setEnabled(False)
        self.e.set()
        print 'Stop the thread'

    def sniffing(self):# We use the function "sniff()" in lib Scapy.
        try:
            sniff(iface = self.interface_name, prn = self.sniffing_callback,
                 filter = self.filter_rule, stop_filter = lambda p: self.e.is_set())
        except:
            self.priviledge = False

    def sniffing_callback(self, pkt):# Callback function which is executed every time when one new packet is acquired.
        if self.count == 0:
            # The first packet
            self.init_time = pkt.time
        self.count += 1
        w_pkt = Wrap_pkt(id = self.count, time = pkt.time - self.init_time,
                         info = pkt.summary(), packet = pkt)

        type = pkt.getlayer(Ether).type

        #The following process can determine the protocol of the packet.
        if type == 0x806:
            w_pkt.proto = 'arp'
            w_pkt.src = pkt.getlayer(ARP).psrc
            w_pkt.dst = pkt.getlayer(ARP).pdst
        elif type == 0x86dd:
            w_pkt.proto = 'ipv6'
            w_pkt.src = pkt.getlayer(IPv6).src
            w_pkt.dst = pkt.getlayer(IPv6).dst
        elif type == 0x800:
            w_pkt.src = pkt.getlayer(IP).src
            w_pkt.dst = pkt.getlayer(IP).dst
            type2 = pkt.getlayer(IP).proto
            if type2 == 1:
                w_pkt.proto = 'icmp'
            elif type2 == 2:
                w_pkt.proto = 'igmp'
            elif type2 == 6:
                w_pkt.proto = 'tcp'
            elif type2 == 17:
                try:
                    pkt.getlayer(DHCP).options
                    w_pkt.proto = 'dhcp'
                except:
                    try:
                        pkt.getlayer(DNS).opcode
                        w_pkt.proto = 'dns'
                    except:
                        w_pkt.proto = 'udp'
            else:
                pass
        else:
            pass

        w_pkt.info_initialize()
        self.w_pkts.update({str(w_pkt.id): w_pkt})  
        self.raw_pkts.update({str(w_pkt.id): pkt})
        self.id_list.append(w_pkt.id)
        self.show_packets(w_pkt) # Show the packets in the table.

    def show_packets(self,pkt): #Show packets in the table widget with different colors or fonts, etc.       
        item1 = QtGui.QTableWidgetItem(str(round(pkt.time,5)))
        item2 = QtGui.QTableWidgetItem(pkt.src)
        item3 = QtGui.QTableWidgetItem(pkt.dst)
        item4 = QtGui.QTableWidgetItem(pkt.proto.upper())
        item5 = QtGui.QTableWidgetItem(pkt.info)
        
		# Different colors.
        if pkt.proto == 'arp':
            item1.setBackgroundColor(QtGui.QColor(224,202,221))
            item2.setBackgroundColor(QtGui.QColor(224,202,221))
            item3.setBackgroundColor(QtGui.QColor(224,202,221))
            item4.setBackgroundColor(QtGui.QColor(224,202,221)) 
            item5.setBackgroundColor(QtGui.QColor(224,202,221)) 
        elif pkt.proto == 'ipv6':
            item1.setBackgroundColor(QtGui.QColor(229,231,231))
            item2.setBackgroundColor(QtGui.QColor(229,231,231))
            item3.setBackgroundColor(QtGui.QColor(229,231,231))
            item4.setBackgroundColor(QtGui.QColor(229,231,231))
            item5.setBackgroundColor(QtGui.QColor(229,231,231))
        elif pkt.proto == 'icmp':
            item1.setBackgroundColor(QtGui.QColor(251,234,179))
            item2.setBackgroundColor(QtGui.QColor(251,234,179))
            item3.setBackgroundColor(QtGui.QColor(251,234,179))
            item4.setBackgroundColor(QtGui.QColor(251,234,179))
            item5.setBackgroundColor(QtGui.QColor(251,234,179))
        elif pkt.proto == 'igmp':
            item1.setBackgroundColor(QtGui.QColor(254,194,253))
            item2.setBackgroundColor(QtGui.QColor(254,194,253))
            item3.setBackgroundColor(QtGui.QColor(254,194,253))
            item4.setBackgroundColor(QtGui.QColor(254,194,253))
            item5.setBackgroundColor(QtGui.QColor(254,194,253))
        elif pkt.proto == 'tcp':
            item1.setBackgroundColor(QtGui.QColor(250,214,221))
            item2.setBackgroundColor(QtGui.QColor(250,214,221))
            item3.setBackgroundColor(QtGui.QColor(250,214,221))
            item4.setBackgroundColor(QtGui.QColor(250,214,221))
            item5.setBackgroundColor(QtGui.QColor(250,214,221))
        elif pkt.proto == 'dns':
            item1.setBackgroundColor(QtGui.QColor(221,218,254))
            item2.setBackgroundColor(QtGui.QColor(221,218,254))
            item3.setBackgroundColor(QtGui.QColor(221,218,254))
            item4.setBackgroundColor(QtGui.QColor(221,218,254))
            item5.setBackgroundColor(QtGui.QColor(221,218,254))
        elif pkt.proto == 'dhcp':
            item1.setBackgroundColor(QtGui.QColor(212,236,230))
            item2.setBackgroundColor(QtGui.QColor(212,236,230))
            item3.setBackgroundColor(QtGui.QColor(212,236,230))
            item4.setBackgroundColor(QtGui.QColor(212,236,230))
            item5.setBackgroundColor(QtGui.QColor(212,236,230))
        elif pkt.proto == 'udp':
            item1.setBackgroundColor(QtGui.QColor(213,212,252))
            item2.setBackgroundColor(QtGui.QColor(213,212,252))
            item3.setBackgroundColor(QtGui.QColor(213,212,252))
            item4.setBackgroundColor(QtGui.QColor(213,212,252))
            item5.setBackgroundColor(QtGui.QColor(213,212,252))
        row_count = self.PacketList.rowCount()
        self.PacketList.insertRow(row_count) 
        self.PacketList.setItem(row_count,0,item1)
        self.PacketList.setItem(row_count,1,item2)
        self.PacketList.setItem(row_count,2,item3)
        self.PacketList.setItem(row_count,3,item4)
        self.PacketList.setItem(row_count,4,item5)
          
    def show_packet_details(self):# Show packet details in the tabwidget.
        id = self.id_list[self.PacketList.currentRow()]
        current_pkt = self.w_pkts[str(id)]
        current_pkt_raw = self.raw_pkts[str(id)]
        if current_pkt.proto == "arp":
            self.PacketInfo.setTabText(1,"ARP")
            self.PacketInfo.setTabText(2,"More...")
        if current_pkt.proto == "ipv6":
            self.PacketInfo.setTabText(1,"IPv6")
            self.PacketInfo.setTabText(2,"More...")
        if current_pkt.proto == "tcp": 
            self.PacketInfo.setTabText(1,"IP")
            self.PacketInfo.setTabText(2,"TCP")
        if current_pkt.proto == "icmp": 
            self.PacketInfo.setTabText(1,"IP")
            self.PacketInfo.setTabText(2,"ICMP")
        if current_pkt.proto == "igmp":
            self.PacketInfo.setTabText(1,"IP")
            self.PacketInfo.setTabText(2,"IGMP")
        if current_pkt.proto == "udp" or current_pkt.proto == "dhcp" or current_pkt.proto == "dns":
            self.PacketInfo.setTabText(1,"IP")
            self.PacketInfo.setTabText(2,"UDP")
       	# We devide a packet into three layers.
        # We can turn to the layer we want to see by cilcking the titles of tabwidgets.		
        self.show_ethernet_info(current_pkt)
        self.show_second_layer_info(current_pkt)
        self.show_third_layer_info(current_pkt)
        self.show_raw_content(current_pkt_raw)

    def show_raw_content(self,packet): #This function is to show the raw data in both 'string' and 'hex' format.
        raw = packet.getlayer(Raw)
        if raw != None:
            raw_length = len(raw.load)
            single_str = ''
            single_hex = ''
            for i in range(0, raw_length):
                single_hex = single_hex + '{:02x}'.format(ord(raw.load[i])) + ' '
                if ord(raw.load[i]) > 32 and ord(raw.load[i]) != 127:
                    single_str = single_str + raw.load[i]
                else:
                    single_str = single_str + '.'
            self.RawDataHex.setText(single_hex)
            self.RawDataStr.setText(single_str)
        else:
            self.RawDataStr.setText('')
            self.RawDataHex.setText('')
        self.RawDataHex.setReadOnly(True)
        self.RawDataStr.setReadOnly(True)

    def show_ethernet_info(self,packet):# Show ethernet info of packets. Packets in all protocols possess this property.
        self.Ethernet_text.clear()
        self.Ethernet_text.setColumnCount(2)
        self.Ethernet_text.setRowCount(3)
        self.Ethernet_text.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.Ethernet_text.setColumnWidth(0,120)
        self.Ethernet_text.setColumnWidth(1,200)
        self.Ethernet_text.horizontalHeader().setStretchLastSection(True)

        item = QtGui.QTableWidgetItem("Message Field")
        self.Ethernet_text.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem("Value")
        self.Ethernet_text.setHorizontalHeaderItem(1, item)

        item1 = QtGui.QTableWidgetItem('Source:')
        item2 = QtGui.QTableWidgetItem('Destination:')
        item3 = QtGui.QTableWidgetItem('Type:')

        self.Ethernet_text.setItem(0,0,item1)
        self.Ethernet_text.setItem(1,0,item2)
        self.Ethernet_text.setItem(2,0,item3)

        item4 = QtGui.QTableWidgetItem(packet.Ethernet['src'])
        item5 = QtGui.QTableWidgetItem(packet.Ethernet['dst'])

        # The type of the packets which is showed in the ethernet layer.
        if str(packet.Ethernet['type']) == "2048":
            type_str = 'IPv4 (0x0800)'
        elif str(packet.Ethernet['type']) == "2054":
            type_str = 'ARP (0x0806)'
        elif str(packet.Ethernet['type']) == "34916":
            type_Str = 'PPPoE (0x8864)'
        elif str(packet.Ethernet['type']) == "34525":
            type_str = 'IPv6 (0x86dd)'
        elif str(packet.Ethernet['type']) == "33024":
            type_str = '802.1Q tag (0x8100)'
        elif str(packet.Ethernet['type']) == "34887":
            type_str = 'MPLS Label (0x8847)'
        else:
            type_Str = 'Unknown (0d' + str(packet.Ethernet['type']) + ')'

        item6 = QtGui.QTableWidgetItem(type_str)
        self.Ethernet_text.setItem(0,1,item4)
        self.Ethernet_text.setItem(1,1,item5)
        self.Ethernet_text.setItem(2,1,item6)

    def show_second_layer_info(self,packet):# Show the second layer(IPv4 ARP IPv6)
        if packet.Ethernet['type'] == 2048:# Dealing with IPv4 packets
            self.ip_text.clear()
            self.ip_text.setColumnCount(4)
            self.ip_text.setRowCount(13)
            self.ip_text.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
            self.ip_text.setColumnWidth(0,120)
            self.ip_text.setColumnWidth(1,140)
            self.ip_text.setColumnWidth(2,120)
            self.ip_text.horizontalHeader().setStretchLastSection(True)
            
            item = QtGui.QTableWidgetItem("Message Field")
            self.ip_text.setHorizontalHeaderItem(0, item)
            item = QtGui.QTableWidgetItem("Value")
            self.ip_text.setHorizontalHeaderItem(1, item)
            item = QtGui.QTableWidgetItem("Option")
            self.ip_text.setHorizontalHeaderItem(2, item)
            item = QtGui.QTableWidgetItem("Value")
            self.ip_text.setHorizontalHeaderItem(3, item)

            item1 = QtGui.QTableWidgetItem('Version:')
            item2 = QtGui.QTableWidgetItem('Header Length:')
            item3 = QtGui.QTableWidgetItem('ToS:')
            item4 = QtGui.QTableWidgetItem('Length:')
            item5 = QtGui.QTableWidgetItem('ID:')
            item6 = QtGui.QTableWidgetItem('DF Flag:')
            item7 = QtGui.QTableWidgetItem('MF Flag:')
            item8 = QtGui.QTableWidgetItem('Fragment:')
            item9 = QtGui.QTableWidgetItem('TTL:')
            item10 = QtGui.QTableWidgetItem('Protocol:')
            item11 = QtGui.QTableWidgetItem('Checksum:')
            item12 = QtGui.QTableWidgetItem('Source:')
            item13 = QtGui.QTableWidgetItem('Destination:')

            self.ip_text.setItem(0,0,item1)
            self.ip_text.setItem(1,0,item2)
            self.ip_text.setItem(2,0,item3)
            self.ip_text.setItem(3,0,item4)
            self.ip_text.setItem(4,0,item5)
            self.ip_text.setItem(5,0,item6)
            self.ip_text.setItem(6,0,item7)
            self.ip_text.setItem(7,0,item8)
            self.ip_text.setItem(8,0,item9)
            self.ip_text.setItem(9,0,item10)
            self.ip_text.setItem(10,0,item11)
            self.ip_text.setItem(11,0,item12)
            self.ip_text.setItem(12,0,item13)
            
            #IP.version
            if packet.IP['version'] == 4:
                version = 'IPv4'
            elif packet.IP['version'] == 6:
                version = 'IPv6'
            else:
                version = 'Unknown (' + str(packet.IP['version']) + ')'
            item1 = QtGui.QTableWidgetItem(version)
            #IP.Internet.Header.Length
            item2 = QtGui.QTableWidgetItem(str(4*packet.IP['ihl']) + ' Bytes')
            #IP.Type of Service
            tos_str = '{:08b}'.format(packet.IP['tos'])
            if tos_str[3] == 1:\
                tos = "Lowest Delay"
            elif tos_str[4] == 1:
                tos = "Highest Capacity"
            elif tos_str[5] == 1:
                tos = "Highest Reliability"
            elif tos_str[6] == 1:
                tos = "Lowest Cost"
            else:
                tos = "Typical"
            item3 = QtGui.QTableWidgetItem(tos)
            #IP total length
            item4 = QtGui.QTableWidgetItem(str(packet.IP['len']) + ' Bytes')
            #IP.ID
            item5 = QtGui.QTableWidgetItem(str(packet.IP['id']))
            #IP "Don't Fragment" Flag and "More Fragment" Flag
            flag = packet.IP['flags']
            if flag == 2:
                item6 = QtGui.QTableWidgetItem('1')
                item7 = QtGui.QTableWidgetItem('0')
            elif flag == 1:
                item6 = QtGui.QTableWidgetItem('0')
                item7 = QtGui.QTableWidgetItem('1')
            else:
                item6 = QtGui.QTableWidgetItem('0')
                item7 = QtGui.QTableWidgetItem('0')
            #IP fragment            
            item8 = QtGui.QTableWidgetItem(str(8*packet.IP['frag']) + ' Bytes')
            #IP time to live
            item9 = QtGui.QTableWidgetItem(str(packet.IP['ttl']))
            #IP protocol
            protocol = packet.IP['proto']
            if protocol == 1:
                proto_str = 'ICMP'
            elif protocol == 2:
                proto_str = 'IGMP'
            elif protocol == 6:
                proto_str = 'TCP'
            elif protocol == 17:
                proto_str = 'UDP'
            else:
                proto_str = 'Unknown'
            item10 = QtGui.QTableWidgetItem(proto_str)
            #IP checksum
            item11 = QtGui.QTableWidgetItem(str(packet.IP['chksum']))
            #IP source
            item12 = QtGui.QTableWidgetItem(str(packet.IP['src']))
            #IP destination
            item13 = QtGui.QTableWidgetItem(str(packet.IP['dst']))            
            
            self.ip_text.setItem(0,1,item1)
            self.ip_text.setItem(1,1,item2)
            self.ip_text.setItem(2,1,item3)
            self.ip_text.setItem(3,1,item4)
            self.ip_text.setItem(4,1,item5)
            self.ip_text.setItem(5,1,item6)
            self.ip_text.setItem(6,1,item7)
            self.ip_text.setItem(7,1,item8)
            self.ip_text.setItem(8,1,item9)
            self.ip_text.setItem(9,1,item10)
            self.ip_text.setItem(10,1,item11)
            self.ip_text.setItem(11,1,item12)
            self.ip_text.setItem(12,1,item13)
            
			# Get the "options", if existed.
            if packet.IP['options'] != []:
                Alert_exists = 0
                options_len = len(packet.IP['options'])
                for i in range (0,options_len):
                    if isinstance(packet.IP['options'][i],IPOption_Router_Alert):
                        Alert_exists = 1
                        ip_copy_flag = packet.IP['options'][i].copy_flag
                        ip_optclass = packet.IP['options'][i].optclass
                        ip_option = packet.IP['options'][i].option
                        ip_length = packet.IP['options'][i].length
                        ip_alert =packet.IP['options'][i].alert
                        
                        item = QtGui.QTableWidgetItem("Router_Alert")
                        self.ip_text.setHorizontalHeaderItem(2, item)
                        item = QtGui.QTableWidgetItem("Copy Flag:")
                        self.ip_text.setItem(0,2,item)
                        item = QtGui.QTableWidgetItem("Optclass:")
                        self.ip_text.setItem(1,2,item)
                        item = QtGui.QTableWidgetItem("Option:")
                        self.ip_text.setItem(2,2,item)
                        item = QtGui.QTableWidgetItem("Length:")
                        self.ip_text.setItem(3,2,item)
                        item = QtGui.QTableWidgetItem("Alert:")
                        self.ip_text.setItem(4,2,item)
                        
                        item = QtGui.QTableWidgetItem(str(ip_copy_flag))
                        self.ip_text.setItem(0,3,item)
                        item = QtGui.QTableWidgetItem(str(ip_optclass))
                        self.ip_text.setItem(1,3,item)
                        item = QtGui.QTableWidgetItem(str(ip_option))
                        self.ip_text.setItem(2,3,item)
                        item = QtGui.QTableWidgetItem(str(ip_length))
                        self.ip_text.setItem(3,3,item)
                        item = QtGui.QTableWidgetItem(str(ip_alert))
                        self.ip_text.setItem(4,3,item)
                        
                        if Alert_exists == 0:
                            for i in range (0,options_len):
                                item = QtGui.QTableWidgetItem(str(packet.IP['options'][i][0]))
                                self.ip_text.setItem(i,2,item)
                                item = QtGui.QTableWidgetItem(str(packet.IP['options'][i][1]))
                                self.ip_text.setItem(i,3,item)
                        else:
                            i = 0
                            while i < options_len and isinstance(packet.IP['options'][i],IPOption_Router_Alert) != 1:
                                item = QtGui.QTableWidgetItem(str(packet.IP['options'][i][0]))
                                self.ip_text.setItem(6+i,2,item)
                                item = QtGui.QTableWidgetItem(str(packet.IP['options'][i][1]))
                                self.ip_text.setItem(6+i,3,item)
                                i = i + 1

        elif packet.Ethernet['type'] == 2054:# Dealing with ARP packets
            self.ip_text.clear()
            self.ip_text.setColumnCount(2)
            self.ip_text.setRowCount(9)
            self.ip_text.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
            self.ip_text.setColumnWidth(0,220)
            self.ip_text.horizontalHeader().setStretchLastSection(True)

            item = QtGui.QTableWidgetItem("Message Field")
            self.ip_text.setHorizontalHeaderItem(0, item)
            item = QtGui.QTableWidgetItem("Value")
            self.ip_text.setHorizontalHeaderItem(1, item)

            item1 = QtGui.QTableWidgetItem('Hardware Type:')
            item2 = QtGui.QTableWidgetItem('Protocol Type:')
            item3 = QtGui.QTableWidgetItem('Hardware Length:')
            item4 = QtGui.QTableWidgetItem('Protocol Length:')
            item5 = QtGui.QTableWidgetItem('Operation Type:')
            item6 = QtGui.QTableWidgetItem('Source Hardware Address:')
            item7 = QtGui.QTableWidgetItem('Source Protocol Address:')
            item8 = QtGui.QTableWidgetItem('Destination Hardware Address:')
            item9 = QtGui.QTableWidgetItem('Destination Protocol Address:')

            self.ip_text.setItem(0,0,item1)
            self.ip_text.setItem(1,0,item2)
            self.ip_text.setItem(2,0,item3)
            self.ip_text.setItem(3,0,item4)
            self.ip_text.setItem(4,0,item5)
            self.ip_text.setItem(5,0,item6)
            self.ip_text.setItem(6,0,item7)
            self.ip_text.setItem(7,0,item8)
            self.ip_text.setItem(8,0,item9)

            #ARP hardware type
            if (packet.ARP['hwtype'] == 1):
                hwtype = 'MAC'
            else:
                hwtype = 'Unknown (' + str(packet.ARP['hwtype']) + ')'
            item1 = QtGui.QTableWidgetItem(hwtype)
            #ARP protocol type
            if (packet.ARP['ptype'] == 0x800):
                ptype = 'IP'
            else:
                ptype = 'Unknown (0d' + str(packet.ARP['ptype']) + ')'
            item2 = QtGui.QTableWidgetItem(ptype)
            #ARP hardware length and protocol length
            item3 = QtGui.QTableWidgetItem(str(packet.ARP['hwlen']) + ' Bytes')
            item4 = QtGui.QTableWidgetItem(str(packet.ARP['plen']) + ' Bytes')
            #ARP Operation Code
            if packet.ARP['op'] == 1:
                item5 = QtGui.QTableWidgetItem('ARP Query')
            if packet.ARP['op'] == 2:
                item5 = QtGui.QTableWidgetItem('ARP Response')    
            #ARP Source and Destiantion                
            item6 = QtGui.QTableWidgetItem(packet.ARP['hwsrc'])
            item7 = QtGui.QTableWidgetItem(packet.ARP['psrc'])
            item8 = QtGui.QTableWidgetItem(packet.ARP['hwdst'])
            item9 = QtGui.QTableWidgetItem(packet.ARP['pdst'])

            self.ip_text.setItem(0,1,item1)
            self.ip_text.setItem(1,1,item2)
            self.ip_text.setItem(2,1,item3)
            self.ip_text.setItem(3,1,item4)
            self.ip_text.setItem(4,1,item5)
            self.ip_text.setItem(5,1,item6)
            self.ip_text.setItem(6,1,item7)
            self.ip_text.setItem(7,1,item8)
            self.ip_text.setItem(8,1,item9)

        elif packet.Ethernet['type'] == 34525:# Dealing with IPv6 packets
            self.ip_text.clear()
            self.ip_text.setColumnCount(2)
            self.ip_text.setRowCount(8)
            self.ip_text.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
            self.ip_text.setColumnWidth(0,180)
            self.ip_text.horizontalHeader().setStretchLastSection(True)

            item = QtGui.QTableWidgetItem("Message Field")
            self.ip_text.setHorizontalHeaderItem(0, item)
            item = QtGui.QTableWidgetItem("Value")
            self.ip_text.setHorizontalHeaderItem(1, item)

            item1 = QtGui.QTableWidgetItem('Version:')
            item2 = QtGui.QTableWidgetItem('Traffic Class:')
            item3 = QtGui.QTableWidgetItem('Flow Label:')
            item4 = QtGui.QTableWidgetItem('Payload Length:')
            item5 = QtGui.QTableWidgetItem('Next Header:')
            item6 = QtGui.QTableWidgetItem('Hop Limit:')
            item7 = QtGui.QTableWidgetItem('Source IP Address:')
            item8 = QtGui.QTableWidgetItem('Destination IP Address:')

            self.ip_text.setItem(0,0,item1)
            self.ip_text.setItem(1,0,item2)
            self.ip_text.setItem(2,0,item3)
            self.ip_text.setItem(3,0,item4)
            self.ip_text.setItem(4,0,item5)
            self.ip_text.setItem(5,0,item6)
            self.ip_text.setItem(6,0,item7)
            self.ip_text.setItem(7,0,item8)

            #IPv6 version
            if packet.IPv6['version'] == 6:
                item1 = QtGui.QTableWidgetItem('IPv6')
            else:
                item1 = QtGui.QTableWidgetItem('Unknown (' + str(packet.IPv6['version']) + ')')
            #IPv6 traffic class
            tos_str = '{:08b}'.format(packet.IPv6['tc'])
            if tos_str[3] == 1:
                tos = "Lowest Delay"
            elif tos_str[4] == 1:
                tos = "Highest Capacity"
            elif tos_str[5] == 1:
                tos = "Highest Reliability"
            elif tos_str[6] == 1:
                tos = "Lowest Cost"
            else:
                tos = "Typical"
            item2 = QtGui.QTableWidgetItem(tos)
            #IPv6 Flow Label
            item3 = QtGui.QTableWidgetItem(str(packet.IPv6['fl']))
            item4 = QtGui.QTableWidgetItem(str(packet.IPv6['plen']) + ' Bytes')
            #IPv6 Next Header
            if packet.IPv6['nh'] == 0:
                nh_str = 'IPv6 Hop-by-Hop Option'
            elif packet.IPv6['nh'] == 1:
                nh_str = 'ICMP'
            elif packet.IPv6['nh'] == 2:
                nh_str = 'IGMP'
            elif packet.IPv6['nh'] == 4:
                nh_str = 'IPv4 Encapsulation'
            elif packet.IPv6['nh'] == 6:
                nh_str = 'TCP'
            elif packet.IPv6['nh'] == 17:
                nh_str = 'UDP'
            elif packet.IPv6['nh'] == 41:
                nh_str = 'IPv6 Encapsulation'
            elif packet.IPv6['nh'] == 43:
                nh_str = 'IPv6 Routing Header'
            elif packet.IPv6['nh'] == 44:
                nh_str = 'IPv6 Fragment Header'
            elif packet.IPv6['nh'] == 50:
                nh_str = 'Encap Security Payload'
            elif packet.IPv6['nh'] == 51:
                nh_str = 'Authentication Header'
            elif packet.IPv6['nh'] == 58:
                nh_str = 'IPv6 ICMP'
            else:
                nh_str = 'Unknown (0d' + str(packet.IPv6['nh']) + ')'
            item5 = QtGui.QTableWidgetItem(nh_str)
            #IPv6 Hop Limit
            item6 = QtGui.QTableWidgetItem(str(packet.IPv6['hlim']))
            #IPv6 Address
            item7 = QtGui.QTableWidgetItem(packet.IPv6['src'])
            item8 = QtGui.QTableWidgetItem(packet.IPv6['dst'])
            
            self.ip_text.setItem(0,1,item1)
            self.ip_text.setItem(1,1,item2)
            self.ip_text.setItem(2,1,item3)
            self.ip_text.setItem(3,1,item4)
            self.ip_text.setItem(4,1,item5)
            self.ip_text.setItem(5,1,item6)
            self.ip_text.setItem(6,1,item7)
            self.ip_text.setItem(7,1,item8)

    def show_third_layer_info(self,packet):# Show the third layer: TCP/UDP/ICMP/IGMP/DNS/DHCP
        if packet.proto == "arp" or packet.proto == "ipv6":
            self.more_text.clear()
        elif packet.proto == "tcp":
            self.set_tcp_table(packet)
        elif packet.proto == "icmp":
            self.set_icmp_table(packet)
        elif packet.proto == "igmp":
            print 1
            self.set_igmp_table(packet)
        elif packet.proto == "udp":
            self.set_udp_table(packet)
        elif packet.proto == "dhcp":
            self.set_udp_table(packet)
            self.set_dhcp_table(packet)
        elif packet.proto == "dns":
            self.set_udp_table(packet)
            self.set_dns_table(packet)
        else:
            pass

    def set_tcp_table(self,packet):# Show TCP details
        self.more_text.clear()
        self.more_text.setColumnCount(4)
        self.more_text.setRowCount(13)
        self.more_text.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.more_text.setColumnWidth(0,120)
        self.more_text.setColumnWidth(1,140)
        self.more_text.setColumnWidth(2,120)
        self.more_text.horizontalHeader().setStretchLastSection(True)   

        item = QtGui.QTableWidgetItem("Message Field")
        self.more_text.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem("Value")
        self.more_text.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem("Option")
        self.more_text.setHorizontalHeaderItem(2, item)
        item = QtGui.QTableWidgetItem("Value")
        self.more_text.setHorizontalHeaderItem(3, item)  

        item1 = QtGui.QTableWidgetItem('Src Port:')
        item2 = QtGui.QTableWidgetItem('Dst Port:')
        item3 = QtGui.QTableWidgetItem('Seq Number:')
        item4 = QtGui.QTableWidgetItem('Ack Number:')
        item5 = QtGui.QTableWidgetItem('Header Length:')
        item6 = QtGui.QTableWidgetItem('Flag_URG:')
        item7 = QtGui.QTableWidgetItem('Flag_ACK:')
        item8 = QtGui.QTableWidgetItem('Flag_PUSH:')
        item9 = QtGui.QTableWidgetItem('Flag_RST:')
        item10 = QtGui.QTableWidgetItem('Flag_SYN:')
        item11 = QtGui.QTableWidgetItem('Flag_FIN:')
        item12 = QtGui.QTableWidgetItem('Window Size:')
        item13 = QtGui.QTableWidgetItem('Checksum:')   

        self.more_text.setItem(0,0,item1)
        self.more_text.setItem(1,0,item2)
        self.more_text.setItem(2,0,item3)
        self.more_text.setItem(3,0,item4)
        self.more_text.setItem(4,0,item5)
        self.more_text.setItem(5,0,item6)
        self.more_text.setItem(6,0,item7)
        self.more_text.setItem(7,0,item8)
        self.more_text.setItem(8,0,item9)
        self.more_text.setItem(9,0,item10)
        self.more_text.setItem(10,0,item11)
        self.more_text.setItem(11,0,item12)
        self.more_text.setItem(12,0,item13)

        #TCP Basic Informations:
        item1 = QtGui.QTableWidgetItem(str(packet.underIP['sport']))
        item2 = QtGui.QTableWidgetItem(str(packet.underIP['dport']))
        item3 = QtGui.QTableWidgetItem(str(packet.underIP['seq']))
        item4 = QtGui.QTableWidgetItem(str(packet.underIP['ack']))
        item5 = QtGui.QTableWidgetItem(str(4 * packet.underIP['dataofs']))
        #TCP flags: PSH ACK SYN URG RST FIN
        flag_str = '{:06b}'.format(int(packet.underIP['flags']))
        item6 = QtGui.QTableWidgetItem(flag_str[0])
        item7 = QtGui.QTableWidgetItem(flag_str[1])
        item8 = QtGui.QTableWidgetItem(flag_str[2])
        item9 = QtGui.QTableWidgetItem(flag_str[3])
        item10 = QtGui.QTableWidgetItem(flag_str[4])
        item11 = QtGui.QTableWidgetItem(flag_str[5])
        #TCP Window Size and Checksum:
        item12 = QtGui.QTableWidgetItem(str(packet.underIP['window']))
        item13 = QtGui.QTableWidgetItem(str(packet.underIP['chksum'])) 

        self.more_text.setItem(0,1,item1)
        self.more_text.setItem(1,1,item2)
        self.more_text.setItem(2,1,item3)
        self.more_text.setItem(3,1,item4)
        self.more_text.setItem(4,1,item5)
        self.more_text.setItem(5,1,item6)
        self.more_text.setItem(6,1,item7)
        self.more_text.setItem(7,1,item8)
        self.more_text.setItem(8,1,item9)
        self.more_text.setItem(9,1,item10)
        self.more_text.setItem(10,1,item11)
        self.more_text.setItem(11,1,item12)
        self.more_text.setItem(12,1,item13)
        
		# Get "options", if existed.
        if packet.underIP['options'] != []:
            print '1'
            options_len = len(packet.underIP['options'])
            print options_len
            for i in range (0,options_len):
                print str(packet.underIP['options'][i][0])
                item = QtGui.QTableWidgetItem(str(packet.underIP['options'][i][0]))
                self.more_text.setItem(i,2,item)
                print str(packet.underIP['options'][i][0])
                item = QtGui.QTableWidgetItem(str(packet.underIP['options'][i][1]))
                self.more_text.setItem(i,3,item)        

    def set_icmp_table(self,packet):# Show ICMP details
        self.more_text.clear()
        self.more_text.setColumnCount(2)
        self.more_text.setRowCount(5)
        self.more_text.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.more_text.setColumnWidth(0,120)
        self.more_text.horizontalHeader().setStretchLastSection(True)

        item = QtGui.QTableWidgetItem("Message Field")
        self.more_text.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem("Value")
        self.more_text.setHorizontalHeaderItem(1, item)
        
        item1 = QtGui.QTableWidgetItem('Type:')
        item2 = QtGui.QTableWidgetItem('Code:')
        item3 = QtGui.QTableWidgetItem('Checksum:')
        item4 = QtGui.QTableWidgetItem('ID:')
        item5 = QtGui.QTableWidgetItem('Seq Number:')
         
        self.more_text.setItem(0,0,item1)
        self.more_text.setItem(1,0,item2)
        self.more_text.setItem(2,0,item3)
        self.more_text.setItem(3,0,item4)
        self.more_text.setItem(4,0,item5)   

        #ICMP Type and Code:
        icmp_type = packet.underIP['type']
        icmp_code = packet.underIP['code']
        if icmp_type == 8:
            type_str = 'Echo-Request (Type = 8)'
            code_str = str(icmp_code)
        elif icmp_type == 0:
            type_str = 'Echo-Reply (Type = 0)'
            code_str = str(icmp_code)
        elif icmp_type == 3:
            type_str = 'Unreachable (Type = 3)'
            if icmp_code == 0:
                code_str = 'Network Unreachable (Code = 0)'
            elif icmp_code == 1:
                code_str = 'Host Unreachable (Code = 1)'
            elif icmp_code == 2:
                code_str = 'Protocol Unreachable (Code = 2)'
            elif icmp_code == 3:
                code_str = 'Port Unreachable (Code = 3)'
            else:
                code_str = str(icmp_code)   
        elif icmp_type == 11:
            type_str = 'Overtime'
            if icmp_code == 0:
                code_str = 'Transmission Overtime'
            elif icmp_Code == 1:
                code_str = 'Fragment Overtime'
            else:
                code_str = str(icmp_code)
        elif icmp_type == 13:
            type_str = 'Timestamp Request'
            code_str = str(icmp_code)            
        elif icmp_type == 14:
            type_str = 'Timestamp Reply'
            code_str = str(icmp_code)
        else:
            type_str = str(icmp_type)
            code_str = str(icmp_code) 

        item1 = QtGui.QTableWidgetItem(type_str)
        item2 = QtGui.QTableWidgetItem(code_str)
        #ICMP Checksum/ ID /SeqNumber
        item3 = QtGui.QTableWidgetItem(str(packet.underIP['chksum']))
        item4 = QtGui.QTableWidgetItem(str(packet.underIP['id']))
        item5 = QtGui.QTableWidgetItem(str(packet.underIP['seq']))    

        self.more_text.setItem(0,1,item1)
        self.more_text.setItem(1,1,item2)
        self.more_text.setItem(2,1,item3)
        self.more_text.setItem(3,1,item4)
        self.more_text.setItem(4,1,item5)

    def set_igmp_table(self,packet):# Show IGMP details
        self.more_text.clear()
        self.more_text.setColumnCount(2)
        self.more_text.setRowCount(4)
        self.more_text.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.more_text.setColumnWidth(0,120)
        self.more_text.horizontalHeader().setStretchLastSection(True)
        
        item = QtGui.QTableWidgetItem("Message Field")
        self.more_text.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem("Value")
        self.more_text.setHorizontalHeaderItem(1, item)    
        
        item1 = QtGui.QTableWidgetItem('Type:')
        item2 = QtGui.QTableWidgetItem('Max Resp Time:')
        item3 = QtGui.QTableWidgetItem('Checksum:')
        item4 = QtGui.QTableWidgetItem('Group Address:')
         
        self.more_text.setItem(0,0,item1)
        self.more_text.setItem(1,0,item2)
        self.more_text.setItem(2,0,item3)
        self.more_text.setItem(3,0,item4)
        
        item1 = QtGui.QTableWidgetItem(packet.underIP['type'])
        item2 = QtGui.QTableWidgetItem(packet.underIP['mrt'])
        #ICMP Checksum/ ID /SeqNumber
        item3 = QtGui.QTableWidgetItem(str(packet.underIP['chksum']))
        item4 = QtGui.QTableWidgetItem(packet.underIP['group_addr'])

        self.more_text.setItem(0,1,item1)
        self.more_text.setItem(1,1,item2)
        self.more_text.setItem(2,1,item3)
        self.more_text.setItem(3,1,item4)        
      
    def set_udp_table(self,packet):# Show UDP details (as well as DNS and DHCP)
        self.more_text.clear()
        self.more_text.setColumnCount(4)
        self.more_text.setRowCount(13)
        self.more_text.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.more_text.setColumnWidth(0,90)
        self.more_text.setColumnWidth(1,80)
        self.more_text.setColumnWidth(2,140)
        self.more_text.horizontalHeader().setStretchLastSection(True)
        
        item = QtGui.QTableWidgetItem("UDP Layer")
        self.more_text.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem("Value")
        self.more_text.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem("")
        self.more_text.setHorizontalHeaderItem(2, item)
        item = QtGui.QTableWidgetItem("")
        self.more_text.setHorizontalHeaderItem(3, item)
        
        item1 = QtGui.QTableWidgetItem('Src Port:')
        item2 = QtGui.QTableWidgetItem('Dst Port:')
        item3 = QtGui.QTableWidgetItem('Length:')
        item4 = QtGui.QTableWidgetItem('Checksum:')
        
        self.more_text.setItem(0,0,item1)
        self.more_text.setItem(1,0,item2)
        self.more_text.setItem(2,0,item3)
        self.more_text.setItem(3,0,item4)
        
        item1 = QtGui.QTableWidgetItem(str(packet.underIP['sport']))
        item2 = QtGui.QTableWidgetItem(str(packet.underIP['dport']))
        item3 = QtGui.QTableWidgetItem(str(packet.underIP['len']) + ' Bytes')
        item4 = QtGui.QTableWidgetItem(str(packet.underIP['chksum']))
        
        self.more_text.setItem(0,1,item1)
        self.more_text.setItem(1,1,item2)
        self.more_text.setItem(2,1,item3)
        self.more_text.setItem(3,1,item4)
        
    def set_dhcp_table(self,packet): # Show DHCP details under UDP layer.
        item = QtGui.QTableWidgetItem("DHCP Layer")
        self.more_text.setHorizontalHeaderItem(2, item)
        item = QtGui.QTableWidgetItem("Value")
        self.more_text.setHorizontalHeaderItem(3, item)
        
        dhcp_options = packet.underUDP['options']
        dhcp_message_type = dhcp_options[0][1]
        dhcp_request_addr = dhcp_options[1][1]
        dhcp_hostname = dhcp_options[2][1]
        
		# There are 8 different types in DHCP protocol.
        if dhcp_message_type == 1:
            message_type = 'DHCP Discover'
        elif dhcp_message_type == 2:
            message_type = 'DHCP Offer'
        elif dhcp_message_type == 3:
            message_type = 'DHCP Request'
        elif dhcp_message_type == 4:
            message_type = 'DHCP Decline'
        elif dhcp_message_type == 5:
            message_type = 'DHCP ACK'
        elif dhcp_message_type == 6:
            message_type = 'DHCP NAK'
        elif dhcp_message_type == 7:
            message_type = 'DHCP Release'
        elif dhcp_message_type == 8:
            message_type = 'DHCP Inform'
        else:
            message_type = 'Unknown (0d' + str(dhcp_message_type) + ')'
            
        item1 = QtGui.QTableWidgetItem("Message Type:")
        item2 = QtGui.QTableWidgetItem("Requested Address:")
        item3 = QtGui.QTableWidgetItem("Host Name:")
        
        self.more_text.setItem(0,2,item1)
        self.more_text.setItem(1,2,item2)
        self.more_text.setItem(2,2,item3)
        
        item1 = QtGui.QTableWidgetItem(message_type)
        item2 = QtGui.QTableWidgetItem(dhcp_request_addr)
        item3 = QtGui.QTableWidgetItem(dhcp_hostname)
        
        self.more_text.setItem(0,3,item1)
        self.more_text.setItem(1,3,item2)
        self.more_text.setItem(2,3,item3)

    def set_dns_table(self,packet):# Show DNS details under UDP layer.
        item = QtGui.QTableWidgetItem("DNS Layer")
        self.more_text.setHorizontalHeaderItem(2, item)
        item = QtGui.QTableWidgetItem("Value")
        self.more_text.setHorizontalHeaderItem(3, item)
        
        item1 = QtGui.QTableWidgetItem("ID:")
        item2 = QtGui.QTableWidgetItem("Type:")
        item3 = QtGui.QTableWidgetItem("Operation Code:")
        item4 = QtGui.QTableWidgetItem("Return Code:")
        item5 = QtGui.QTableWidgetItem("Query Name:")
        item6 = QtGui.QTableWidgetItem("Query Type:")
        item7 = QtGui.QTableWidgetItem("Query Class:")
        item8 = QtGui.QTableWidgetItem("Return Data:")
        
        self.more_text.setItem(0,2,item1)
        self.more_text.setItem(1,2,item2)
        self.more_text.setItem(2,2,item3)
        self.more_text.setItem(3,2,item4)
        self.more_text.setItem(4,2,item5)
        self.more_text.setItem(5,2,item6)
        self.more_text.setItem(6,2,item7)
        self.more_text.setItem(7,2,item8)
        
        #DNS ID
        item = QtGui.QTableWidgetItem(str(packet.underUDP['id']))
        self.more_text.setItem(0,3,item)
        #DNS Type(qr)
        if packet.underUDP['qr'] == 0:
            item = QtGui.QTableWidgetItem("Query")
        elif packet.underUDP['qr'] == 1:
            item = QtGui.QTableWidgetItem("Reply")
        else:
            item = QtGui.QTableWidgetItem("Unknown (0d" + str(packet['qr']) + ')')
        self.more_text.setItem(1,3,item)
        #DNS Operation Code
        if packet.underUDP['opcode'] == 0:
            item = QtGui.QTableWidgetItem("DNS Standard Query")
        elif packet.underUDP['opcode'] == 1:
            item = QtGui.QTableWidgetItem("DNS Reverse Query")
        elif packet.underUDP['opcode'] == 2:
            item = QtGui.QTableWidgetItem("Server Status Request")
        else:
            item = QtGui.QTableWidgetItem("Unknown (0d" + str(packet['opcode']) + ')')
            self.more_text.setItem(2,3,item)
        #DNS Return Code:
        if packet.underUDP['rcode'] == 0:
            item = QtGui.QTableWidgetItem("No Error")
        elif packet.underUDP['rcode'] == 3:
            item = QtGui.QTableWidgetItem("Name Error")
        elif packet.underUDP['rcode'] == 2:
            item = QtGui.QTableWidgetItem("Server Failure")
        else:
            item = QtGui.QTableWidgetItem("Unknown (0d" + str(packet['rcode']) + ')')
        self.more_text.setItem(3,3,item)
        #DNS Query name
        item = QtGui.QTableWidgetItem(str(packet.underUDP['qname']))
        self.more_text.setItem(4,3,item)
        #DNS qtype
        if packet.underUDP['qtype'] == 1:
            item = QtGui.QTableWidgetItem("Query for IPv4")
        elif packet.underUDP['qtype'] == 2:
            item = QtGui.QTableWidgetItem("Query for DNS Server")
        elif packet.underUDP['qtype'] == 28:
            item = QtGui.QTableWidgetItem("Query for IPv6")
        elif packet.underUDP['qtype'] == 13:
            item = QtGui.QTableWidgetItem("Query for Host Information")
        elif packet.underUDP['qtype'] == 12:
            item = QtGui.QTableWidgetItem("Query for Domain Name")
        else:
            item = QtGui.QTableWidgetItem("Unknown (0d" + str(dns_qd.qtype) + ')')
            self.more_text.setItem(5,3,item)
        #DNS qclass
        if packet.underUDP['qclass'] == 1:
            item = QtGui.QTableWidgetItem("Internet Data")
        else:
            item = QtGui.QTableWidgetItem("Unknown (0d" + str(dns_qd.qclass) + ')')
        self.more_text.setItem(6,3,item)
        #DNS return data
        re_data = packet.underUDP['rdata']
        re_len = len(re_data)
        for i in range (0,re_len):
            item = QtGui.QTableWidgetItem(re_data[i])
            self.more_text.setItem(7+i,3,item)

    def do_interface(self):# Change interface

        if not self.STOP:

            QtGui.QMessageBox.critical(self, "Error", 'You have to stop the sniffer first!')
            return
        else:
            self.iface = InterfaceGUI()
            self.iface.exec_()  # GUI has to be execuated!
            self.interface_name = self.iface.cur_interface

    def do_filter(self):#the filter function
        if not self.STOP:
            QtGui.QMessageBox.critical(self, "Error", 'You have to stop the sniffer first!')
            return
        else:
            self.filter= MyFilterGUI(filter_rule = self.filter_rule)
            self.filter.exec_()
            self.filter_rule = self.filter.filter_rule

    def do_searcher(self):#the searcher function
        if not self.STOP:
            QtGui.QMessageBox.critical(self, "Error", 'You have to stop the sniffer first!')
            return
        else:
            self.searcher = MySearcherGUI()
            self.searcher.exec_()
            self.searcher_rule = self.searcher.searcher_rule

            search_result_id = []

            for wpkt_id in self.w_pkts:
                w_pkt = self.w_pkts[wpkt_id]
                accept_flag = True
                for key in self.searcher_rule:
                    if self.searcher_rule[key] == '':
                        continue

                    if (key == 'Protocol' and w_pkt.proto != self.searcher_rule[key] ) \
                            or (key == 'Source' and w_pkt.src != self.searcher_rule[key]) \
                            or (key == 'Destination' and w_pkt.dst != self.searcher_rule[key]):

                        accept_flag = False
                        break
                    elif key == 'Begin_id' and w_pkt.id < int(self.searcher_rule[key]):
                        accept_flag = False
                        break
                    elif key == 'End_id' and w_pkt.id > int(self.searcher_rule[key]):
                        accept_flag = False
                        break

                if accept_flag:
                    search_result_id.append(wpkt_id)

            self.clear_text()
            self.id_list = []
            for id in search_result_id:
                self.show_packets(self.w_pkts[id])
                self.id_list.append(self.w_pkts[id].id)
        return

    def select_pkts_id(self):#to select certain packets
        selected_items = self.PacketList.selectedIndexes()
        selected_id_list = []  # str type
        for i in selected_items:
            if selected_id_list and str(int(i.row()) + 1) == selected_id_list[-1]:
                continue
            else:
                selected_id_list.append(str(int(i.row()) + 1))

        selected_id_list2 = list(set(selected_id_list))
        selected_id_list_tmp = [int(i) for i in selected_id_list2]
        selected_id_list_tmp.sort()
        selected_id_list = [str(i) for i in selected_id_list_tmp]

        return selected_id_list

    def open_pcap(self):#to open pcap files
        if not self.STOP:
            QtGui.QMessageBox.critical(self, "Error", 'You have to stop the sniffer first!')
            return
        else:
            fileName = QtGui.QFileDialog.getOpenFileName(self, "Open File", "../", "Pcap files (*.pcap)")
            if fileName:
                ans = QtGui.QMessageBox.question(self, '',
                                                    "Are you sure to open new pcap file?",
                                                    QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
                if ans == QtGui.QMessageBox.Yes:
                    try:
                        fileName = str(fileName)
                        pcap = rdpcap(fileName)
                        packets = list(pcap)
                        self.refresh(packets)
                    except ValueError:
                        QtGui.QMessageBox.information(self, "Error", "'" + fileName + "' is not a pcap file.")
                    except:
                        print "Unexpected error:", sys.exc_info()[0]
                else:
                    pass

    def save_pcap(self):#to save pcap files
        if self.count == 0:
            QtGui.QMessageBox.critical(self, "Error", "Packet list is empty.")
            return
        filename = QtGui.QFileDialog.getSaveFileName(self, "Save file", "../", ".pcap")
        if filename:
            try:
                filename = str(filename)
                selected_id_list = self.select_pkts_id()
                if not selected_id_list:
                    QtGui.QMessageBox.information(self, "Info", "Please select the packets you want to save.")
                    return

                # ask again
                ans = QtGui.QMessageBox.question(self, '',
                                                 "Are you sure to save?",
                                                 QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
                if ans == QtGui.QMessageBox.No:
                    return


                saved_raw_pkts = []

                for i in selected_id_list:
                    cur_pkt = self.raw_pkts.get(i, '')
                    if cur_pkt != '':
                        saved_raw_pkts.append(cur_pkt)



                pcap_writer = PcapWriter(filename + '.pcap')
                pcap_writer.write(saved_raw_pkts)
                QtGui.QMessageBox.information(self, "Success", "Save %s successfully!" % filename)
            except:
                print "Unexpected error:", sys.exc_info()[0]

    def save_txt(self):# to save txt files
        if self.count == 0:
            QtGui.QMessageBox.critical(self, "Error", "Packet list is empty.")
            return

        filename = QtGui.QFileDialog.getSaveFileName(self, "Save file", "../", ".txt")

        if filename:
            try:
                filename = str(filename)
                selected_id_list = self.select_pkts_id()
                if not selected_id_list:
                    QtGui.QMessageBox.information(self, "Info", "Please select the packets you want to save.")
                    return

                # ask again
                ans = QtGui.QMessageBox.question(self, '',
                                                 "Are you sure to save?",
                                                 QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
                if ans == QtGui.QMessageBox.No:
                    return


                saved_raw_pkts = []

                for i in selected_id_list:
                    cur_pkt = self.w_pkts.get(i, '')
                    if cur_pkt != '':
                        saved_raw_pkts.append(cur_pkt)

                with open(filename, 'w') as f:

                    mat = "{:^20}\t{:^20}\t{:^20}\t{:^20}\t{:^20}\t{:^60}"
                    line = mat.format("id", "time", "source", "destination", "protocol", "information")
                    f.write(line)
                    f.write(os.linesep)
                    for pkt in saved_raw_pkts:
                        line = mat.format(str(pkt.id), str(pkt.time), str(pkt.src), str(pkt.dst), str(pkt.proto), str(pkt.info))
                        f.write(line)
                        f.write(os.linesep)
                QtGui.QMessageBox.information(self, "Success", "Save %s successfully!" % filename)
            except:
                print "Unexpected error:", sys.exc_info()[0]

    def refresh(self, packets):
        self.clean()
        print 'len :' + str(len(packets))
        for packet in packets:
            self.sniffing_callback(packet)

    def clean(self):
        # but still sniffing 
        self.count = 0
        self.w_pkts = {}
        self.raw_pkts = {}
        self.id_list = []
        self.clear_text()

    def clear_text(self):# Clear all the display area.
        self.PacketList.clearContents()
        self.PacketList.setRowCount(0)  
        self.RawDataStr.clear()
        self.RawDataHex.clear()
        self.Ethernet_text.clear()
        self.ip_text.clear()
        self.more_text.clear()

    def closeEvent(self, QCloseEvent):
        self.my_close()

    def my_close(self):# Close the window
        self.stop_sniffing()
        os._exit(0)
        self.clean()

    def sort_frag(self,x,y):
        if x[1]<y[1]:
            return -1
        else:
            return 1

    def recombine_ip_prepare(self):# prepare for IP recombine/reassembling, i.e., get the result id

        recombine_dict = {} # "src/dst/ip_id" : [(id,frag)()()]  ip_id is not id!!
        result = [] # [[id,id,id],[],..] one [] refers to one recombination

        for wpkt_id in self.w_pkts:
            w_pkt = self.w_pkts[wpkt_id]
            if w_pkt.IP == {}:
                continue

            index = str(w_pkt.src).strip() + '/' + str(w_pkt.dst).strip() + '/' + str(w_pkt.IP['id'])
            if index not in recombine_dict.keys():
                recombine_dict[index] = [(str(w_pkt.id), int(w_pkt.IP['frag']))]
            else:
                recombine_dict[index].append((str(w_pkt.id), int(w_pkt.IP['frag'])))

        for ip_id in recombine_dict:
            if len(recombine_dict[ip_id]) < 2:
                continue
            lst = recombine_dict[ip_id]
            lst.sort(cmp = self.sort_frag)
            result.append([a[0] for a in lst])

        recombine_dict.clear()
        return result

    def recombine_ip(self):  # IP recombine/reassembling
        result = self.recombine_ip_prepare()
        self.recombination = RecombinationIPGUI(result, self.w_pkts, self.raw_pkts)
        self.recombination.exec_()  # GUI has to be execuated.

    def File_reconstruct(self):# Detect and reconstruct FTP files
        files = {}
        for i in self.raw_pkts:
            if self.raw_pkts[i].getlayer(TCP) != None: # Check if it is a TCP packet.
                pkt_tcp = self.raw_pkts[i].getlayer(TCP)
                if pkt_tcp.getlayer(Raw) != None: # Check if raw data transmitted.
                    pkt_raw = pkt_tcp.getlayer(Raw).load
                    if pkt_tcp.dport == 21 and 'RETR' in pkt_raw: # Check if it is a FTP packet.
                        filename = pkt_raw[5:-2]
                        files.update({filename: 0})
                        seq_id = pkt_tcp.seq
                        for j in self.raw_pkts:
                            if self.raw_pkts[j].getlayer(TCP) != None:
                                pkt_tcp_1 = self.raw_pkts[j].getlayer(TCP)
                                if pkt_tcp_1.ack == seq_id:
                                    pkt_raw_1 = pkt_tcp_1.getlayer(Raw).load
                                    num1 = int(pkt_raw_1.split(',')[4])
                                    num2 = int(pkt_raw_1.split(',')[5][:-4])
                                    port = num1 * 256 + num2 # Acquire the high-bit port number in PASV FTP.
                                    files.update({filename: port})
        print files # Contains all the detected files.
        results = {}
        for name in files: # For each file in the "files", we should recombine it.
            result = ''
            file_id = {}
            for i in self.raw_pkts:
                if self.raw_pkts[i].getlayer(TCP) != None and self.raw_pkts[i].getlayer(TCP).sport == files[name]:
                    id_seq = self.raw_pkts[i].getlayer(TCP).seq
                    file_id.update({str(i): id_seq})
            for id in sorted(file_id, key=file_id.__getitem__):
                try:
                    file_frag = self.raw_pkts[id].getlayer(Raw).load
                    result = result + file_frag # Recombine the file.
                except:
                    result = result + ''
            results.update({name: result})
            print name
        if results == {}:
            QtGui.QMessageBox.critical(self, "Error", "There are no FTP packets.")
        else:
            filecombine = FilesRecombineGUI(results)
            filecombine.exec_()

    def help(self):# Help: please refering to our repository in github...
        webbrowser.open("https://github.com/DaydreamerZhang/NetScope")
		
def main():
    app = QtGui.QApplication(sys.argv)  # A new instance of QApplication
    mainWin = myapp()
    mainWin.show()
    app.exec_() # The execution of out app.

if __name__ == '__main__':
    main()    
