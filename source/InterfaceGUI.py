# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'interface.ui'
#
# Created: Wed Nov 28 20:55:41 2018
#      by: PyQt4 UI code generator 4.10.4
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui
from NetInterface import NetInterface
import sys


class InterfaceGUI(QtGui.QDialog):
    def __init__(self,parent=None):
        QtGui.QDialog.__init__(self, parent)
        self.resize(500, 200)
        self.setWindowTitle('Network Adapter Selection')
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("icon/icon.png"),QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.setWindowIcon(icon)
        self.setupdata()  # data part
        self.setupUi()      # UI part
        # self.show()

    def setupdata(self):
        # use NetInterface() to obtain network adapter information
        self.netinterface = NetInterface()

        # current chosen network adapter
        # it works since it has a loop interface at least
        # and we choose it as a default choice at the very beginning
        self.cur_interface = self.netinterface.get_name_list()[0]


    def setupUi(self):

        self.radio_lists = [] # save the Qradiobutton

        font = QtGui.QFont()
        font.setBold(False)
        font.setUnderline(False)
        font.setWeight(50)
        self.setFont(font)
        self.top_gridLayout = QtGui.QGridLayout(self)
        self.gridLayout = QtGui.QGridLayout()

        # print the main information
        # must have
        self.name = QtGui.QLabel("name")
        self.gridLayout.addWidget(self.name, 0, 0, 1, 1, QtCore.Qt.AlignVCenter)
        self.ip_address = QtGui.QLabel("ip_address")
        self.gridLayout.addWidget(self.ip_address, 0, 1, 1, 1, QtCore.Qt.AlignVCenter)
        self.send = QtGui.QLabel("receive")
        self.gridLayout.addWidget(self.send, 0, 2, 1, 1, QtCore.Qt.AlignVCenter)
        self.receive = QtGui.QLabel("send")
        self.gridLayout.addWidget(self.receive, 0, 3, 1, 1, QtCore.Qt.AlignVCenter)

        # network adapter information
        # we use a for-loop to print the information

        pos = 0

        for name in self.netinterface.ip_address_dict:

            pos += 1
            self.cur_radio = QtGui.QRadioButton(name)
            # we first choose the self.cur_interface automatically
            if name == self.cur_interface:
                self.cur_radio.setChecked(True)

            self.gridLayout.addWidget(self.cur_radio, pos, 0, 1, 1, QtCore.Qt.AlignVCenter)
            self.radio_lists.append(self.cur_radio)
            self.ip_data = QtGui.QLabel(self.netinterface.ip_address_dict[name])
            self.gridLayout.addWidget(self.ip_data, pos, 1, 1, 1, QtCore.Qt.AlignVCenter)
            self.send_data = QtGui.QLabel(str(self.netinterface.data_dict[name][0]) + 'MB')
            self.gridLayout.addWidget(self.send_data, pos, 2, 1, 1, QtCore.Qt.AlignVCenter)
            self.receive_data = QtGui.QLabel(str(self.netinterface.data_dict[name][1]) + 'MB')
            self.gridLayout.addWidget(self.receive_data, pos, 3, 1, 1, QtCore.Qt.AlignVCenter)

        # the top grid layout and the buttonbox
        self.top_gridLayout.addLayout(self.gridLayout, 0, 0, 1, 2)
        spacerItem = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.top_gridLayout.addItem(spacerItem, 1, 1, 1, 1)
        self.buttonBox = QtGui.QDialogButtonBox(self)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.top_gridLayout.addWidget(self.buttonBox, 2, 1, 1, 1)

        # make some stretch
        self.top_gridLayout.setRowStretch(0, 5)
        self.top_gridLayout.setRowStretch(1, 1)
        self.top_gridLayout.setRowStretch(2, 1)

        # connect some action
        # if the user click ok, we update the information and hide the Qdialog
        self.buttonBox.accepted.connect(self.res_ok)
        # if the user click cancel, we do nothing but hide the Qdialog
        self.buttonBox.rejected.connect(self.res_cancel)


        return

    def res_ok(self):
        for radio in self.radio_lists:
            if radio.isChecked():
                self.cur_interface = str(radio.text())

        print self.cur_interface

        self.hide()
        return

    def res_cancel(self):
        # we just do nothing
        print self.cur_interface
        self.hide()

        return


if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    a = InterfaceGUI()
    a.show()
    app.exec_()
