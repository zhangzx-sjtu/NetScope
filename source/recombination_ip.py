#This file implements the function of IP packets recombination.
from PyQt4 import QtCore, QtGui
import sys
import os
from scapy.all import *

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


class RecombinationIPGUI(QtGui.QDialog):
    def __init__(self, result, w_pkts, raw_pkts):
        QtGui.QDialog.__init__(self)

        self.result = result
        self.w_pkts = w_pkts
        self.raw_pkts = raw_pkts
        self.setupUi()
        self.show_recombination_list()

        # for i in self.raw_pkts:
        #     raw = self.raw_pkts[i].getlayer(Raw)
        #     print raw.load
        self.show()

    def setupUi(self):
        self.setObjectName(_fromUtf8("widget"))
        self.resize(773, 592)
        self.setContextMenuPolicy(QtCore.Qt.NoContextMenu)
        self.recombination_list = QtGui.QTableWidget(self)
        self.recombination_list.setGeometry(QtCore.QRect(30, 20, 711, 221))
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(7)
        sizePolicy.setVerticalStretch(6)
        sizePolicy.setHeightForWidth(self.recombination_list.sizePolicy().hasHeightForWidth())
        self.recombination_list.setSizePolicy(sizePolicy)
        self.recombination_list.setMaximumSize(QtCore.QSize(711, 221))
        self.recombination_list.setSizeIncrement(QtCore.QSize(0, 0))
        self.recombination_list.setBaseSize(QtCore.QSize(0, 0))
        font = QtGui.QFont()
        font.setUnderline(False)
        font.setStrikeOut(False)
        self.recombination_list.setFont(font)
        self.recombination_list.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        self.recombination_list.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.recombination_list.setAutoFillBackground(False)
        self.recombination_list.setFrameShape(QtGui.QFrame.StyledPanel)
        self.recombination_list.setLineWidth(0)
        self.recombination_list.setColumnCount(4)
        self.recombination_list.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        font = QtGui.QFont()
        font.setPointSize(11)
        item.setFont(font)
        self.recombination_list.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.recombination_list.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        self.recombination_list.setHorizontalHeaderItem(2, item)
        item = QtGui.QTableWidgetItem()
        self.recombination_list.setHorizontalHeaderItem(3, item)
        self.recombination_list.horizontalHeader().setVisible(True)
        self.recombination_list.horizontalHeader().setCascadingSectionResizes(True)
        self.recombination_list.horizontalHeader().setDefaultSectionSize(175)
        self.recombination_list.horizontalHeader().setHighlightSections(False)
        self.recombination_list.horizontalHeader().setMinimumSectionSize(100)
        self.recombination_list.horizontalHeader().setSortIndicatorShown(False)
        self.recombination_list.horizontalHeader().setStretchLastSection(True)
        self.recombination_list.verticalHeader().setCascadingSectionResizes(False)
        self.recombination_list.verticalHeader().setStretchLastSection(False)
        self.line = QtGui.QFrame(self)
        self.line.setGeometry(QtCore.QRect(0, 240, 1171, 21))
        self.line.setFrameShape(QtGui.QFrame.HLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)
        self.Raw_data = QtGui.QTextEdit(self)
        self.Raw_data.setGeometry(QtCore.QRect(30, 260, 711, 301))
        self.Raw_data.setObjectName(_fromUtf8("Raw_data"))

        self.recombination_list.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.recombination_list.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.recombination_list.setSelectionMode(QtGui.QAbstractItemView.SingleSelection)

        self.retranslateUi()
        QtCore.QObject.connect(self.recombination_list, QtCore.SIGNAL(_fromUtf8("cellClicked(int,int)")), self.show_data)
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self):
        self.setWindowTitle(_translate("widget", "IP Recombination", None))
        item = self.recombination_list.horizontalHeaderItem(0)
        item.setText(_translate("widget", "Packet_id", None))
        item = self.recombination_list.horizontalHeaderItem(1)
        item.setText(_translate("widget", "Source", None))
        item = self.recombination_list.horizontalHeaderItem(2)
        item.setText(_translate("widget", "Destination", None))
        item = self.recombination_list.horizontalHeaderItem(3)
        item.setText(_translate("widget", "Raw_IP_id", None))

    def show_recombination_list(self):  
        for i in self.result:
            self.show_recombination_element(i)

    def show_recombination_element(self, unit): # show the information after recombination 
        # packet_id / src / dst / ip_id
        pkt_id = ''
        for pid in unit:
            if pkt_id == '':
                pkt_id += pid
            else:
                pkt_id += ','+pid

        i = unit[0]
        print self.w_pkts[i].IP
        item1 = QtGui.QTableWidgetItem(pkt_id)
        item2 = QtGui.QTableWidgetItem(self.w_pkts[i].src)
        item3 = QtGui.QTableWidgetItem(self.w_pkts[i].dst)
        item4 = QtGui.QTableWidgetItem(str(self.w_pkts[i].IP['id']))
        row_count = self.recombination_list.rowCount()
        self.recombination_list.insertRow(row_count)
        self.recombination_list.setItem(row_count, 0, item1)
        self.recombination_list.setItem(row_count, 1, item2)
        self.recombination_list.setItem(row_count, 2, item3)
        self.recombination_list.setItem(row_count, 3, item4)

    def show_data(self):  # show the data after recombination
        select_item = self.recombination_list.selectedItems()
        id_list = str(select_item[0].text()).split(',')

        data = ''

        for i in id_list:
            raw = self.raw_pkts[i].getlayer(Raw)
            if raw != None:
                raw_length = len(raw.load)
                single_hex = ''
                for i in range(0, raw_length):
                    single_hex = single_hex + '{:02x}'.format(ord(raw.load[i])) + ' '
                data += single_hex
            else:
                pass

        self.Raw_data.setText(data)


def main():
    app = QtGui.QApplication(sys.argv)  # A new instance of QApplication
    test = RecombinationIPGUI()
    app.exec_()



if __name__ == '__main__':
    main()
