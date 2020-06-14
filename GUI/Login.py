# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\StorePasswordSafe_Login.ui'
#
# Created by: PyQt5 UI code generator 5.14.2
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(449, 600)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.mainWindowLoginID = QtWidgets.QLineEdit(self.centralwidget)
        self.mainWindowLoginID.setGeometry(QtCore.QRect(80, 120, 301, 51))
        font = QtGui.QFont()
        font.setFamily("Verdana")
        font.setPointSize(12)
        self.mainWindowLoginID.setFont(font)
        self.mainWindowLoginID.setObjectName("mainWindowLoginID")
        self.mainWindowLoginPWD = QtWidgets.QLineEdit(self.centralwidget)
        self.mainWindowLoginPWD.setGeometry(QtCore.QRect(80, 200, 301, 51))
        font = QtGui.QFont()
        font.setFamily("Verdana")
        font.setPointSize(12)
        self.mainWindowLoginPWD.setFont(font)
        self.mainWindowLoginPWD.setObjectName("mainWindowLoginPWD")
        self.mainWindowLoginNewUser = QtWidgets.QLabel(self.centralwidget)
        self.mainWindowLoginNewUser.setGeometry(QtCore.QRect(190, 320, 91, 20))
        font = QtGui.QFont()
        font.setFamily("Verdana")
        font.setPointSize(12)
        font.setUnderline(True)
        self.mainWindowLoginNewUser.setFont(font)
        self.mainWindowLoginNewUser.setObjectName("mainWindowLoginNewUser")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(130, 370, 201, 51))
        font = QtGui.QFont()
        font.setFamily("Verdana")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 449, 21))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.mainWindowLoginID.setPlaceholderText(_translate("MainWindow", "ID"))
        self.mainWindowLoginPWD.setPlaceholderText(_translate("MainWindow", "Password"))
        self.mainWindowLoginNewUser.setText(_translate("MainWindow", "New Here?"))
        self.pushButton.setText(_translate("MainWindow", "GO"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
