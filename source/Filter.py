import sys
import re
from PyQt4 import QtGui

class MyFilterGUI(QtGui.QDialog):
    def __init__(self, filter_rule='', parent=None):

        QtGui.QDialog.__init__(self, parent=parent)
        self.setWindowTitle('Set_Filter')

        self.filter_rule = filter_rule
        self.vbox = QtGui.QVBoxLayout()  # vertical

        for key in ['Protocol', 'Source', 'Destination', 'Src Port', 'Dst Port']:

            label = key + ' :'
            KeyLabel = QtGui.QLabel(label)
            ValueLineEdit = QtGui.QLineEdit()
            ValueLineEdit.setObjectName(key)  # simply use key as its objectname

            if key == 'Protocol':
                ValueLineEdit.setPlaceholderText('icmp')
            elif key == 'Source' or key == 'Destination':
                ValueLineEdit.setPlaceholderText('0.0.0.0')
            else:
                ValueLineEdit.setPlaceholderText('80')


            hbox = QtGui.QHBoxLayout()
            hbox.addWidget(KeyLabel)
            hbox.addWidget(ValueLineEdit)
            self.vbox.addLayout(hbox)


        self.buttonBox = QtGui.QDialogButtonBox(self)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel | QtGui.QDialogButtonBox.Ok)
        self.buttonBox.accepted.connect(self.res_ok)
        self.buttonBox.rejected.connect(self.res_cancel)
        self.vbox.addWidget(self.buttonBox)
        self.setLayout(self.vbox)

        self.show()

    def res_cancel(self):   # when user click cancel
        print self.filter_rule
        self.hide()
        return

    def res_ok(self):   # when user click ok
        # renew value first
        new_value = {}
        new_rule = ''
        for key in ['Protocol', 'Source', 'Destination', 'Src Port', 'Dst Port']:  # check for all the fields

            ValueLineEdit = self.findChild((QtGui.QLineEdit,), key)
            tmp = str(ValueLineEdit.text())

            if key == 'Protocol':
                if self.checkproto(tmp):
                    new_value[key] = tmp.lower()
                else:
                    new_value[key] = ''
                    if tmp != '':
                        QtGui.QMessageBox.critical(self, "Error", 'Please put in the right protocol!')
                        return

            elif key == 'Source':
                if self.checkip(tmp):
                    new_value[key] = 'src host ' + tmp
                else:
                    new_value[key] = ''
                    if tmp != '':
                        QtGui.QMessageBox.critical(self, "Error", 'Please put in the right source!')
                        return
            elif key == 'Destination':
                if self.checkip(tmp):
                    new_value[key] = 'dst host ' + tmp
                else:
                    new_value[key] = ''
                    if tmp != '':
                        QtGui.QMessageBox.critical(self, "Error", 'Please put in the right destination!')
                        return
            elif key == 'Src Port':
                if not tmp.isdigit():
                    new_value[key] = ''
                    if tmp != '':
                        QtGui.QMessageBox.critical(self, "Error", 'Please put in the right source port!')
                        return
                else:
                    new_value[key] = 'src port ' + tmp
            elif key == 'Dst Port':
                if not tmp.isdigit():
                    new_value[key] = ''
                    if tmp != '':
                        QtGui.QMessageBox.critical(self, "Error", 'Please put in the right destination port!')
                        return
                else:
                    new_value[key] = 'dst port ' + tmp

        for key in new_value:
            if new_rule == '':  # '' add directly . no problem
                new_rule = new_rule + new_value[key]
            elif new_value[key] != '':
                new_rule = new_rule + ' and ' + new_value[key]

        self.filter_rule = new_rule
        self.hide()

    def checkip(self, ip): 
        p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        if p.match(ip):
            return True
        else:
            return False


    def checkproto(self, proto):
        p = re.compile('(T|t)(C|c)(P|p)|(U|u)(D|d)(P|p)|(A|a)(R|r)(P|p)|(I|i)(C|c)(M|m)(P|p)|(D|d)(N|n)(S|s)|(D|d)(H|h)(C|c)(P|p)')
        if p.match(proto):
            return True
        else:
            return False


# ~ #-------------------------------------------------
def main():
    app = QtGui.QApplication(sys.argv)  # A new instance of QApplication
    test = MyFilterGUI('xixixi')
    print test.filter_rule
    app.exec_()


if __name__ == '__main__':
    main()

