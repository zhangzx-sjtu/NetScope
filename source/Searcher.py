import sys
import re
from PyQt4 import QtGui

class MySearcherGUI(QtGui.QDialog):
    def __init__(self, searcher_rule={}, parent=None):

        QtGui.QDialog.__init__(self, parent=parent)
        self.setWindowTitle('Set_Searcher')

        self.searcher_rule = searcher_rule
        if len(self.searcher_rule) == 0:
            self.searcher_rule = {'Protocol': '', 'Source': '',
                                      'Destination': '', 'Begin_id': '',
                                      'End_id': ''}

        self.vbox = QtGui.QVBoxLayout()  # vertical

        for key in ['Protocol', 'Source', 'Destination', 'Begin_id', 'End_id']:

            label = key + ' :'
            KeyLabel = QtGui.QLabel(label)
            ValueLineEdit = QtGui.QLineEdit()
            ValueLineEdit.setObjectName(key)  # simply use key as its objectname

            if key == 'Protocol':
                ValueLineEdit.setPlaceholderText('icmp')
            elif key == 'Source' or key == 'Destination':
                ValueLineEdit.setPlaceholderText('0.0.0.0')
            elif key == 'Begin_id':
                ValueLineEdit.setPlaceholderText('1')
            else:
                ValueLineEdit.setPlaceholderText('2')


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

    def res_cancel(self): # when user click cancel
        print self.searcher_rule
        self.hide()
        return

    def res_ok(self):  # when user click ok
        # renew value first
        new_value = {}
        for key in ['Protocol', 'Source', 'Destination', 'Begin_id', 'End_id']:

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
                    new_value[key] = tmp
                else:
                    new_value[key] = ''
                    if tmp != '':
                        QtGui.QMessageBox.critical(self, "Error", 'Please put in the right source!')
                        return
            elif key == 'Destination':
                if self.checkip(tmp):
                    new_value[key] = tmp
                else:
                    new_value[key] = ''
                    if tmp != '':
                        QtGui.QMessageBox.critical(self, "Error", 'Please put in the right destination!')
                        return
            elif key == 'Begin_id':
                if not tmp.isdigit():
                    new_value[key] = ''
                    if tmp != '':
                        QtGui.QMessageBox.critical(self, "Error", 'Please put in the right Begin_id!')
                        return
                else:
                    new_value[key] = tmp
            elif key == 'End_id':
                if not tmp.isdigit():
                    new_value[key] = ''
                    if tmp != '':
                        QtGui.QMessageBox.critical(self, "Error", 'Please put in the right End_id!')
                        return
                else:
                    new_value[key] =  tmp

        # Maybe we have to make a window to print the error information
        if new_value['Begin_id'] != '' and new_value['End_id'] != '' and int(new_value['Begin_id']) > int(new_value['End_id']):
            new_value['Begin_id'] = ''
            new_value['End_id'] = ''
            QtGui.QMessageBox.critical(self, "Error", 'Your id range is wrong!')
            return
        self.searcher_rule = new_value
        print self.searcher_rule
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
    test = MySearcherGUI()
    print test.searcher_rule
    app.exec_()


if __name__ == '__main__':
    main()

