#This file implements the function of detecting and reconstructing files from PASV FTP.
import sys
import re
from PyQt4 import QtCore,QtGui

#The main GUI class for files recombine. It contains the detected-file list and the file-saving dialog.
class FilesRecombineGUI(QtGui.QDialog):
	def __init__(self,resultss,parent=None):
		QtGui.QDialog.__init__(self, parent=parent)
		self.result = resultss
		self.setWindowTitle('Save Discovered File in FTP')
		self.buttonBox = QtGui.QDialogButtonBox(self)
		self.buttonBox.setGeometry(QtCore.QRect(60, 270, 341, 32))
		self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
		self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
		self.buttonBox.setObjectName("buttonBox")
		self.label = QtGui.QLabel(self)
		self.label.setGeometry(QtCore.QRect(20, 10, 371, 21))
		self.label.setObjectName("label")
		self.DiscoveredFiles = QtGui.QTableWidget(self)
		self.DiscoveredFiles.setGeometry(QtCore.QRect(20, 40, 371, 221))
		self.DiscoveredFiles.setObjectName("DiscoveredFiles")
		self.DiscoveredFiles.setColumnCount(0)
		self.DiscoveredFiles.setRowCount(0)
		self.DiscoveredFiles.horizontalHeader().setVisible(False)
		self.DiscoveredFiles.insertColumn(0)
		self.DiscoveredFiles.horizontalHeader().setStretchLastSection(True)
		self.label.setText("Select and save one of the following discovered files:")
		self.DiscoveredFiles.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
		self.DiscoveredFiles.setSelectionMode(QtGui.QAbstractItemView.SingleSelection)
		self.row_to_name = []
		if resultss != {}:
			for name in resultss:
				item = QtGui.QTableWidgetItem(str(name))
				row_count = self.DiscoveredFiles.rowCount()
				self.DiscoveredFiles.insertRow(row_count) 
				self.DiscoveredFiles.setItem(row_count,0,item)
				self.row_to_name.append(name)
		
		self.buttonBox.accepted.connect(self.accept)
		self.buttonBox.rejected.connect(self.cancel)
		self.show()

	def accept(self):# when you click "yes", save the selected files
		if self.DiscoveredFiles.selectedItems() == []:
			QtGui.QMessageBox.critical(self, "Info", "Please select the packets you want to save.")
		else:
			row = self.DiscoveredFiles.currentRow()
			file_name = self.row_to_name[row]
			print file_name
			save_name = QtGui.QFileDialog.getSaveFileName(self, "Save file", "../", "")
			if save_name:
				try:
					save_name = str(save_name)
					print save_name
                	# ask again
					ans = QtGui.QMessageBox.question(self, '',"Are you sure to save?", QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
					if ans == QtGui.QMessageBox.No:
						return
					#save_name  self.result[file_name]
					fh = open(save_name, 'w')
					fh.write(self.result[file_name])
					fh.close()
					QtGui.QMessageBox.information(self, "Success", "Save %s successfully!" % save_name)
				except:
					print "Unexpected error:", sys.exc_info()[0]
				
	def cancel(self):# when you click "no", do nothing and exit.
		self.hide()
