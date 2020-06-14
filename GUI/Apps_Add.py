# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\StorePasswordSafe_AppsAdd.ui'
#
# Created by: PyQt5 UI code generator 5.14.2
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(447, 600)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.AppAddWindowAppName = QtWidgets.QLineEdit(self.centralwidget)
        self.AppAddWindowAppName.setGeometry(QtCore.QRect(80, 70, 301, 51))
        font = QtGui.QFont()
        font.setFamily("Verdana")
        font.setPointSize(12)
        self.AppAddWindowAppName.setFont(font)
        self.AppAddWindowAppName.setObjectName("AppAddWindowAppName")
        self.AppAddWindowID = QtWidgets.QLineEdit(self.centralwidget)
        self.AppAddWindowID.setGeometry(QtCore.QRect(80, 150, 301, 51))
        font = QtGui.QFont()
        font.setFamily("Verdana")
        font.setPointSize(12)
        self.AppAddWindowID.setFont(font)
        self.AppAddWindowID.setObjectName("AppAddWindowID")
        self.AppAddWindowPWD = QtWidgets.QLineEdit(self.centralwidget)
        self.AppAddWindowPWD.setGeometry(QtCore.QRect(80, 230, 301, 51))
        font = QtGui.QFont()
        font.setFamily("Verdana")
        font.setPointSize(12)
        self.AppAddWindowPWD.setFont(font)
        self.AppAddWindowPWD.setObjectName("AppAddWindowPWD")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(130, 360, 201, 51))
        font = QtGui.QFont()
        font.setFamily("Verdana")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 447, 21))
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
        self.AppAddWindowAppName.setPlaceholderText(_translate("MainWindow", "App Name"))
        self.AppAddWindowID.setPlaceholderText(_translate("MainWindow", "ID"))
        self.AppAddWindowPWD.setPlaceholderText(_translate("MainWindow", "Password"))
        self.pushButton.setText(_translate("MainWindow", "GO"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
