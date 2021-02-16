"""
Description: 编写一个远程监控与控制小工具，能够实现抓包、远程控制、断网等功能.
Author: ZXY
Date: 2020-12-22 16:11:31
LastEditors: ZXY
LastEditTime: 2020-12-30 15:13:34
"""

import socket
import struct
import sys
import threading
import time

import numpy as np
from cv2 import cv2
from PyQt5 import QtCore, QtGui, QtWidgets
from rsa import PublicKey, encrypt
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

ip_current = ''
port = 8099
port1 = 8111
ip_gate = '192.168.227.2'
bufsize = 1024
soc = None
soc1 = None

img = None  # 当前被监控机图像

event_stop_capture = threading.Event()  # 用来终止抓包线程的事件
event_cutoff = threading.Event()  # 进行arp攻击的事件
event_monitor = threading.Event()  # 监控主机的事件
thread_monitor = None
thread_capture = None
thread_info = None
thread_time = None
lock = threading.Lock()

filters = ''  # 抓包过滤语句
iface_ipt = 'VMware Network Adapter VMnet8'  # 网络接口
packet_list = []  # 已抓到的数据包
flag_pause = False  # 暂停抓包标志位
flag_save = False  # 保存文件标志位
flag_stop = False  # 停止抓包标志位

public_key = None  # 加密公钥
left_button = b'a(7\x1f\xeb\xdd-\x85\xf3\xe6\xc5\xc1\x9a\x9b\x1f\x82'
right_button = b'0\xc7\x9c\xca\xd9\xa2\xb9Q8\xf4\x06\xfe\x05\xd5\x86Q'


def timestamp2time(timestamp):
    """
    将数据包中的时间转换为字符串.
    """
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return mytime


def set_socket(ip, port):
    """
    设置Socket连接.
    """
    global soc
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.connect((ip, port))


def encryp(data):
    """
    使用RSA对byte类型的数据进行加密
    """
    global public_key
    if public_key is None:
        with open("source/keys/pubkey.pem", "rb") as x:
            public_key = x.read()
            public_key = PublicKey.load_pkcs1(public_key)  # 取公钥

    data = bytes(str(data), encoding='utf8')
    return encrypt(data, public_key)  # 返回加密结果


class MyQLabel(QtWidgets.QLabel):
    """
    重写QLabel的鼠标事件.
    """
    # signal_clicked = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super(MyQLabel, self).__init__(parent)
        self.x = 0
        self.y = 0

    def EventDo(self, data):
        """
        将鼠标键盘事件发送到被监控机.
        """
        global soc
        # print(data)
        if soc is not None:
            try:
                soc.sendall(data)
            except:
                print("连接中断！")

    def mousePressEvent(self, QMouseEvent):
        """
        重写鼠标按下事件.
        """
        global left_button, right_button
        press = QMouseEvent.button()
        self.x = int(QMouseEvent.x()/0.6)
        self.y = int(QMouseEvent.y()/0.6)
        if press == 1:  # 按下的是左键
            return self.EventDo(left_button + struct.pack('>BHH', 100, self.x, self.y))
        elif press == 2:  # 按下的是右键
            return self.EventDo(right_button + struct.pack('>BHH', 100, self.x, self.y))
        elif press == 4:  # 按下的是滚轮
            # TODO: 添加滚轮事件
            pass
        else:  # 其他，暂时不做处理
            pass

    def mouseReleaseEvent(self, QMouseEvent):
        """
        重写鼠标释放事件.
        """
        global right_button, left_button
        release = QMouseEvent.button()
        self.x = int(QMouseEvent.x()/0.6)
        self.y = int(QMouseEvent.y()/0.6)
        if release == 1:  # 释放鼠标左键
            return self.EventDo(left_button + struct.pack('>BHH', 117, self.x, self.y))
        if release == 2:  # 释放鼠标右键
            return self.EventDo(right_button + struct.pack('>BHH', 117, self.x, self.y))
        else:
            pass

    def keyPressEvent(self, QKeyEvent):
        """
        重写键盘按键按下事件.
        """
        keycode = QKeyEvent.key()
        data = encryp(keycode)
        try:
            return self.EventDo(data + struct.pack('>BHH', 100, self.x, self.y))
            # print(str(QKeyEvent.key()))
        except:
            # return self.EventDo(struct.pack('>BBHH', QKeyEvent.key()-0x01000000, 100, self.x, self.y))
            print("当前尚不支持该按键按下！")

    def keyReleaseEvent(self, QKeyEvent):
        """
        重写键盘按键释放事件.
        """
        try:
            keycode = QKeyEvent.key()
            data = encryp(keycode)
            # print(str(QKeyEvent.key()))
            return self.EventDo(data + struct.pack('>BHH', 117, self.x, self.y))
        except:
            print("当前尚不支持该按键释放！")
            # return self.EventDo(struct.pack('>BBHH', QKeyEvent.key()-0x01000000, 100, self.x, self.y))


class Ui_filter(QtWidgets.QWidget):
    def setupUi(self, filter):
        self.filter = filter
        filter.setObjectName("filter")
        filter.resize(321, 291)
        filter.setWindowIcon(QtGui.QIcon('source/images/setting.jpg'))
        self.confirm = QtWidgets.QPushButton(filter)
        self.confirm.setGeometry(QtCore.QRect(120, 250, 81, 31))
        font = QtGui.QFont()
        font.setFamily("黑体")
        font.setPointSize(12)
        self.confirm.setFont(font)
        self.confirm.setObjectName("confirm")
        self.layoutWidget = QtWidgets.QWidget(filter)
        self.layoutWidget.setGeometry(QtCore.QRect(90, 40, 191, 201))
        self.layoutWidget.setObjectName("layoutWidget")
        self.layout_ipt = QtWidgets.QVBoxLayout(self.layoutWidget)
        self.layout_ipt.setContentsMargins(0, 0, 0, 0)
        self.layout_ipt.setObjectName("layout_ipt")
        self.ipt_iface = QtWidgets.QLineEdit(self.layoutWidget)
        self.ipt_iface.setObjectName("ipt_iface")
        self.layout_ipt.addWidget(self.ipt_iface)
        self.select_proto = QtWidgets.QComboBox(self.layoutWidget)
        self.select_proto.setObjectName("select_proto")
        self.select_proto.addItem("")
        self.select_proto.addItem("")
        self.select_proto.addItem("")
        self.select_proto.addItem("")
        self.select_proto.addItem("")
        self.select_proto.addItem("")
        self.select_proto.addItem("")
        self.layout_ipt.addWidget(self.select_proto)
        self.ipt_host = QtWidgets.QLineEdit(self.layoutWidget)
        self.ipt_host.setText("")
        self.ipt_host.setObjectName("ipt_host")
        self.layout_ipt.addWidget(self.ipt_host)
        self.ipt_src = QtWidgets.QLineEdit(self.layoutWidget)
        self.ipt_src.setText("")
        self.ipt_src.setObjectName("ipt_src")
        self.layout_ipt.addWidget(self.ipt_src)
        self.ipt_dst = QtWidgets.QLineEdit(self.layoutWidget)
        self.ipt_dst.setText("")
        self.ipt_dst.setObjectName("ipt_dst")
        self.layout_ipt.addWidget(self.ipt_dst)
        self.layoutWidget1 = QtWidgets.QWidget(filter)
        self.layoutWidget1.setGeometry(QtCore.QRect(-10, 40, 90, 191))
        self.layoutWidget1.setObjectName("layoutWidget1")
        self.layout_label = QtWidgets.QVBoxLayout(self.layoutWidget1)
        self.layout_label.setContentsMargins(0, 0, 0, 0)
        self.layout_label.setObjectName("layout_label")
        self.label_iface = QtWidgets.QLabel(self.layoutWidget1)
        self.label_iface.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.label_iface.setAlignment(
            QtCore.Qt.AlignRight | QtCore.Qt.AlignTrailing | QtCore.Qt.AlignVCenter)
        self.label_iface.setObjectName("label_iface")
        self.layout_label.addWidget(self.label_iface)
        self.label_proto = QtWidgets.QLabel(self.layoutWidget1)
        self.label_proto.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.label_proto.setAlignment(
            QtCore.Qt.AlignRight | QtCore.Qt.AlignTrailing | QtCore.Qt.AlignVCenter)
        self.label_proto.setObjectName("label_proto")
        self.layout_label.addWidget(self.label_proto)
        self.label_host = QtWidgets.QLabel(self.layoutWidget1)
        self.label_host.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.label_host.setAlignment(
            QtCore.Qt.AlignRight | QtCore.Qt.AlignTrailing | QtCore.Qt.AlignVCenter)
        self.label_host.setObjectName("label_host")
        self.layout_label.addWidget(self.label_host)
        self.label_src = QtWidgets.QLabel(self.layoutWidget1)
        self.label_src.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.label_src.setAlignment(
            QtCore.Qt.AlignRight | QtCore.Qt.AlignTrailing | QtCore.Qt.AlignVCenter)
        self.label_src.setObjectName("label_src")
        self.layout_label.addWidget(self.label_src)
        self.label_dst = QtWidgets.QLabel(self.layoutWidget1)
        self.label_dst.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.label_dst.setAlignment(
            QtCore.Qt.AlignRight | QtCore.Qt.AlignTrailing | QtCore.Qt.AlignVCenter)
        self.label_dst.setObjectName("label_dst")
        self.layout_label.addWidget(self.label_dst)

        self.retranslateUi(filter)
        self.confirm.clicked.connect(self.on_confirm_clicked)
        # self.confirm.clicked.connect(filter.close)
        QtCore.QMetaObject.connectSlotsByName(filter)

    def retranslateUi(self, filter):
        global iface_ipt, ip_current
        _translate = QtCore.QCoreApplication.translate
        filter.setWindowTitle(_translate("filter", "设置"))
        self.confirm.setText(_translate("filter", "确定"))
        self.ipt_iface.setText(_translate(
            "filter", iface_ipt))
        self.ipt_host.setText(_translate(
            "filter", ip_current))
        self.select_proto.setItemText(0, _translate("filter", "Any"))
        self.select_proto.setItemText(1, _translate("filter", "IP"))
        self.select_proto.setItemText(2, _translate("filter", "TCP"))
        self.select_proto.setItemText(3, _translate("filter", "UDP"))
        self.select_proto.setItemText(4, _translate("filter", "Http"))
        self.select_proto.setItemText(5, _translate("filter", "Https"))
        self.select_proto.setItemText(6, _translate("filter", "SMTP"))
        self.label_iface.setText(_translate("filter", "网络接口"))
        self.label_proto.setText(_translate("filter", "协议类型"))
        self.label_host.setText(_translate("filter", "主机"))
        self.label_src.setText(_translate("filter", "源主机"))
        self.label_dst.setText(_translate("filter", "目的主机"))

    def on_confirm_clicked(self):
        """
        构造BRF过滤语句，设置抓包相关选项.
        """
        global iface_ipt
        global filters
        proto = self.select_proto.currentText()
        iface_ipt = self.ipt_iface.text()
        host = self.ipt_host.text()
        src = self.ipt_src.text()
        dst = self.ipt_dst.text()

        filters = ''
        flag = True  # 记录filters是否为空
        flag_t = False  # 记录构造过程是否有错

        # 构造抓包过滤语句
        if proto != 'Any':
            flag = False
            if proto == 'TCP':
                filters += 'tcp'
            elif proto == 'UDP':
                filters += 'udp'
            elif proto == 'IP':
                filters += 'ip'
            elif proto == 'Http':
                filters += 'tcp port 80'
            elif proto == 'Https':
                filters += 'tcp port 443'
            elif proto == 'SMTP':
                filters += 'tcp port 25'
            # TODO: 添加其他协议

        if iface_ipt == '' or iface_ipt is None:
            flag_t = True
            text_warn = '网络接口不能为空!'
            warn = QtWidgets.QDialog()
            ui = Ui_warning()
            ui.setupUi(warn, text_warn)
            warn.show()
            warn.exec_()

        if host != '' and host != None:
            if flag is True:
                flag = False
                filters += 'host ' + host
            else:
                filters += ' and host ' + host

        if src != '' and src != None:
            if flag is True:
                flag = False
                filters += 'src host ' + src
            else:
                filters += ' and src host ' + src

        if dst != '' and dst != None:
            if flag is True:
                flag = False
                filters += 'dst host ' + dst
            else:
                filters += ' and dst host ' + dst

        if not flag_t:
            self.filter.close()


class Ui_warning(object):
    """
    显示错误信息.
    """
    def setupUi(self, warning, text_warn):
        warning.setObjectName("warning")
        warning.resize(303, 122)
        warning.setWindowIcon(QtGui.QIcon('source/images/error.jpg'))
        self.close = QtWidgets.QPushButton(warning)
        self.close.setGeometry(QtCore.QRect(110, 80, 71, 31))
        self.close.setObjectName("close")
        self.text = QtWidgets.QLabel(warning)
        self.text.setGeometry(QtCore.QRect(20, 30, 261, 31))
        self.text.setText("")
        self.text.setAlignment(QtCore.Qt.AlignCenter)
        self.text.setObjectName("text")

        self.retranslateUi(warning, text_warn)
        self.close.clicked.connect(warning.close)
        QtCore.QMetaObject.connectSlotsByName(warning)

    def retranslateUi(self, warning, text_warn):
        _translate = QtCore.QCoreApplication.translate
        warning.setWindowTitle(_translate("warning", "警告"))
        self.close.setText(_translate("warning", "关闭"))
        self.text.setText(_translate("warning", text_warn))


class Ui_Capture(QtWidgets.QWidget):
    def setupUi(self, Capture):
        Capture.setObjectName("Capture")
        Capture.resize(1446, 987)
        Capture.setFocusPolicy(QtCore.Qt.NoFocus)
        self.table_packets = QtWidgets.QTableWidget(Capture)
        self.table_packets.setGeometry(QtCore.QRect(80, 700, 801, 271))
        self.table_packets.setMinimumSize(QtCore.QSize(771, 0))
        self.table_packets.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table_packets.setObjectName("table_packets")
        self.table_packets.setColumnCount(6)
        self.table_packets.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.table_packets.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_packets.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_packets.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_packets.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_packets.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.table_packets.setHorizontalHeaderItem(5, item)
        self.table_packets.horizontalHeader().setCascadingSectionResizes(True)
        self.info_packet = QtWidgets.QTextBrowser(Capture)
        self.info_packet.setGeometry(QtCore.QRect(940, 700, 291, 271))
        self.info_packet.setMouseTracking(False)
        self.info_packet.setObjectName("info_packet")
        self.layoutWidget = QtWidgets.QWidget(Capture)
        self.layoutWidget.setGeometry(QtCore.QRect(1290, 690, 101, 311))
        self.layoutWidget.setObjectName("layoutWidget")
        self.layout_capture = QtWidgets.QVBoxLayout(self.layoutWidget)
        self.layout_capture.setContentsMargins(0, 0, 0, 0)
        self.layout_capture.setObjectName("layout_capture")
        self.capture_setting = QtWidgets.QPushButton(self.layoutWidget)
        font = QtGui.QFont()
        font.setFamily("黑体")
        font.setPointSize(12)
        self.capture_setting.setFont(font)
        self.capture_setting.setObjectName("capture_setting")
        self.layout_capture.addWidget(self.capture_setting)
        self.capture_start = QtWidgets.QPushButton(self.layoutWidget)
        font = QtGui.QFont()
        font.setFamily("黑体")
        font.setPointSize(12)
        self.capture_start.setFont(font)
        self.capture_start.setObjectName("capture_start")
        self.layout_capture.addWidget(self.capture_start)
        self.capture_pause = QtWidgets.QPushButton(self.layoutWidget)
        self.capture_pause.setEnabled(False)
        font = QtGui.QFont()
        font.setFamily("黑体")
        font.setPointSize(12)
        self.capture_pause.setFont(font)
        self.capture_pause.setObjectName("capture_pause")
        self.layout_capture.addWidget(self.capture_pause)
        self.capture_stop = QtWidgets.QPushButton(self.layoutWidget)
        self.capture_stop.setEnabled(False)
        font = QtGui.QFont()
        font.setFamily("黑体")
        font.setPointSize(12)
        self.capture_stop.setFont(font)
        self.capture_stop.setObjectName("capture_stop")
        self.layout_capture.addWidget(self.capture_stop)
        self.capture_save = QtWidgets.QPushButton(self.layoutWidget)
        self.capture_save.setEnabled(False)
        font = QtGui.QFont()
        font.setFamily("黑体")
        font.setPointSize(12)
        self.capture_save.setFont(font)
        self.capture_save.setObjectName("capture_save")
        self.layout_capture.addWidget(self.capture_save)
        self.exit = QtWidgets.QPushButton(self.layoutWidget)
        font = QtGui.QFont()
        font.setFamily("黑体")
        font.setPointSize(12)
        self.exit.setFont(font)
        self.exit.setObjectName("exit")
        self.layout_capture.addWidget(self.exit)
        self.label_net = QtWidgets.QLabel(Capture)
        self.label_net.setGeometry(QtCore.QRect(20, 690, 51, 291))
        font = QtGui.QFont()
        font.setFamily("黑体")
        font.setPointSize(22)
        self.label_net.setFont(font)
        self.label_net.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_net.setAlignment(QtCore.Qt.AlignCenter)
        self.label_net.setWordWrap(True)
        self.label_net.setObjectName("label_net")
        self.label_host = QtWidgets.QLabel(Capture)
        self.label_host.setGeometry(QtCore.QRect(20, 200, 51, 271))
        font = QtGui.QFont()
        font.setFamily("黑体")
        font.setPointSize(22)
        self.label_host.setFont(font)
        self.label_host.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_host.setAlignment(QtCore.Qt.AlignCenter)
        self.label_host.setWordWrap(True)
        self.label_host.setObjectName("label_host")
        self.monitor = MyQLabel(Capture)
        self.monitor.setGeometry(QtCore.QRect(80, 30, 1152, 648))
        font = QtGui.QFont()
        font.setFamily("Adobe Devanagari")
        font.setPointSize(72)
        self.monitor.setFont(font)
        self.monitor.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.monitor.setMouseTracking(True)
        self.monitor.setTabletTracking(False)
        self.monitor.setFocusPolicy(QtCore.Qt.ClickFocus)
        self.monitor.setAutoFillBackground(False)
        self.monitor.setText("")
        self.monitor.setPixmap(QtGui.QPixmap(
            "source/images/hit2.jpg"))
        self.monitor.setAlignment(QtCore.Qt.AlignCenter)
        self.monitor.setObjectName("monitor")
        self.layoutWidget1 = QtWidgets.QWidget(Capture)
        self.layoutWidget1.setGeometry(QtCore.QRect(1250, 330, 154, 29))
        self.layoutWidget1.setObjectName("layoutWidget1")
        self.layout_ip = QtWidgets.QHBoxLayout(self.layoutWidget1)
        self.layout_ip.setContentsMargins(0, 0, 0, 0)
        self.layout_ip.setObjectName("layout_ip")
        self.label_ip = QtWidgets.QLabel(self.layoutWidget1)
        font = QtGui.QFont()
        font.setFamily("Adobe Devanagari")
        font.setPointSize(12)
        self.label_ip.setFont(font)
        self.label_ip.setAlignment(QtCore.Qt.AlignCenter)
        self.label_ip.setObjectName("label_ip")
        self.layout_ip.addWidget(self.label_ip)
        self.ipt_ip = QtWidgets.QLineEdit(self.layoutWidget1)
        self.ipt_ip.setText("")
        self.ipt_ip.setObjectName("ipt_ip")
        self.layout_ip.addWidget(self.ipt_ip)
        self.instruction = QtWidgets.QTextBrowser(Capture)
        self.instruction.setEnabled(False)
        self.instruction.setGeometry(QtCore.QRect(1240, 30, 171, 161))
        self.instruction.setObjectName("instruction")
        self.layoutWidget2 = QtWidgets.QWidget(Capture)
        self.layoutWidget2.setGeometry(QtCore.QRect(1290, 363, 101, 311))
        self.layoutWidget2.setObjectName("layoutWidget2")
        self.layout_monitor = QtWidgets.QVBoxLayout(self.layoutWidget2)
        self.layout_monitor.setContentsMargins(0, 0, 0, 0)
        self.layout_monitor.setObjectName("layout_monitor")
        self.monitor_start = QtWidgets.QPushButton(self.layoutWidget2)
        font = QtGui.QFont()
        font.setFamily("黑体")
        font.setPointSize(12)
        self.monitor_start.setFont(font)
        self.monitor_start.setObjectName("monitor_start")
        self.layout_monitor.addWidget(self.monitor_start)
        self.monitor_stop = QtWidgets.QPushButton(self.layoutWidget2)
        self.monitor_stop.setEnabled(False)
        font = QtGui.QFont()
        font.setFamily("黑体")
        font.setPointSize(12)
        self.monitor_stop.setFont(font)
        self.monitor_stop.setObjectName("monitor_stop")
        self.layout_monitor.addWidget(self.monitor_stop)
        self.cutoff = QtWidgets.QPushButton(self.layoutWidget2)
        self.cutoff.setEnabled(True)
        font = QtGui.QFont()
        font.setFamily("黑体")
        font.setPointSize(12)
        self.cutoff.setFont(font)
        self.cutoff.setObjectName("cutoff")
        self.layout_monitor.addWidget(self.cutoff)
        self.recover = QtWidgets.QPushButton(self.layoutWidget2)
        self.recover.setEnabled(True)
        font = QtGui.QFont()
        font.setFamily("黑体")
        font.setPointSize(12)
        self.recover.setFont(font)
        self.recover.setObjectName("recover")
        self.layout_monitor.addWidget(self.recover)
        self.cap_img = QtWidgets.QPushButton(self.layoutWidget2)
        self.cap_img.setEnabled(False)
        font = QtGui.QFont()
        font.setFamily("黑体")
        font.setPointSize(12)
        self.cap_img.setFont(font)
        self.cap_img.setObjectName("cap_img")
        self.layout_monitor.addWidget(self.cap_img)
        self.widget = QtWidgets.QWidget(Capture)
        self.widget.setGeometry(QtCore.QRect(1240, 200, 171, 112))
        self.widget.setObjectName("widget")
        self.formLayout = QtWidgets.QFormLayout(self.widget)
        self.formLayout.setContentsMargins(0, 0, 0, 0)
        self.formLayout.setObjectName("formLayout")
        self.label_time = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setFamily("Adobe Devanagari")
        font.setPointSize(10)
        self.label_time.setFont(font)
        self.label_time.setAlignment(QtCore.Qt.AlignCenter)
        self.label_time.setObjectName("label_time")
        self.formLayout.setWidget(
            0, QtWidgets.QFormLayout.LabelRole, self.label_time)
        self.time_display = QtWidgets.QLineEdit(self.widget)
        self.time_display.setEnabled(False)
        self.time_display.setObjectName("time_display")
        self.formLayout.setWidget(
            0, QtWidgets.QFormLayout.FieldRole, self.time_display)
        self.label_cpu = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setFamily("Adobe Devanagari")
        font.setPointSize(10)
        self.label_cpu.setFont(font)
        self.label_cpu.setAlignment(QtCore.Qt.AlignCenter)
        self.label_cpu.setObjectName("label_cpu")
        self.formLayout.setWidget(
            1, QtWidgets.QFormLayout.LabelRole, self.label_cpu)
        self.label_mem = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setFamily("Adobe Devanagari")
        font.setPointSize(10)
        self.label_mem.setFont(font)
        self.label_mem.setAlignment(QtCore.Qt.AlignCenter)
        self.label_mem.setObjectName("label_mem")
        self.formLayout.setWidget(
            2, QtWidgets.QFormLayout.LabelRole, self.label_mem)
        self.lable_mem_total = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setFamily("Adobe Devanagari")
        font.setPointSize(10)
        self.lable_mem_total.setFont(font)
        self.lable_mem_total.setAlignment(QtCore.Qt.AlignCenter)
        self.lable_mem_total.setObjectName("lable_mem_total")
        self.formLayout.setWidget(
            3, QtWidgets.QFormLayout.LabelRole, self.lable_mem_total)
        self.mem_total_display = QtWidgets.QLineEdit(self.widget)
        self.mem_total_display.setEnabled(False)
        self.mem_total_display.setObjectName("mem_total_display")
        self.formLayout.setWidget(
            3, QtWidgets.QFormLayout.FieldRole, self.mem_total_display)
        self.cpu_display = QtWidgets.QLineEdit(self.widget)
        self.cpu_display.setEnabled(False)
        self.cpu_display.setObjectName("cpu_display")
        self.formLayout.setWidget(
            1, QtWidgets.QFormLayout.FieldRole, self.cpu_display)
        self.mem_display = QtWidgets.QLineEdit(self.widget)
        self.mem_display.setEnabled(False)
        self.mem_display.setObjectName("mem_display")
        self.formLayout.setWidget(
            2, QtWidgets.QFormLayout.FieldRole, self.mem_display)

        self.retranslateUi(Capture)
        QtCore.QMetaObject.connectSlotsByName(Capture)

        self.retranslateUi(Capture)
        self.exit.clicked.connect(Capture.close)
        self.capture_setting.clicked.connect(self.on_setting_clicked)
        self.capture_start.clicked.connect(self.on_start_clicked)
        self.capture_pause.clicked.connect(self.on_pause_clicked)
        self.capture_stop.clicked.connect(self.on_stop_clicked)
        self.capture_save.clicked.connect(self.on_save_clicked)
        self.table_packets.clicked.connect(self.on_table_clicked)
        self.cutoff.clicked.connect(self.on_cutoff_clicked)
        self.recover.clicked.connect(self.on_recover_clicked)
        self.monitor_start.clicked.connect(self.on_monitor_start_clicked)
        self.monitor_stop.clicked.connect(self.on_monitor_stop_clicked)
        self.cap_img.clicked.connect(self.on_cap_img_clicked)
        # self.monitor.mousePressEvent()
        QtCore.QMetaObject.connectSlotsByName(Capture)

    def retranslateUi(self, Capture):
        _translate = QtCore.QCoreApplication.translate
        Capture.setWindowTitle(_translate("Capture", "主机监控控制工具"))
        self.table_packets.setSortingEnabled(False)
        item = self.table_packets.horizontalHeaderItem(0)
        item.setText(_translate("Capture", "Time"))
        item = self.table_packets.horizontalHeaderItem(1)
        item.setText(_translate("Capture", "Src"))
        item = self.table_packets.horizontalHeaderItem(2)
        item.setText(_translate("Capture", "Dst"))
        item = self.table_packets.horizontalHeaderItem(3)
        item.setText(_translate("Capture", "Proto"))
        item = self.table_packets.horizontalHeaderItem(4)
        item.setText(_translate("Capture", "Len"))
        item = self.table_packets.horizontalHeaderItem(5)
        item.setText(_translate("Capture", "Info"))
        self.info_packet.setHtml(_translate("Capture", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                            "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
                                            "p, li { white-space: pre-wrap; }\n"
                                            "</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
                                            "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>"))
        self.capture_setting.setText(_translate("Capture", "设置"))
        self.capture_start.setText(_translate("Capture", "开始"))
        self.capture_pause.setText(_translate("Capture", "暂停"))
        self.capture_stop.setText(_translate("Capture", "终止"))
        self.capture_save.setText(_translate("Capture", "保存"))
        self.exit.setText(_translate("Capture", "退出"))
        self.label_net.setText(_translate("Capture", "网络活动监控"))
        self.label_host.setText(_translate("Capture", "远程主机控制"))
        self.label_ip.setText(_translate("Capture", "IP"))
        self.instruction.setHtml(_translate("Capture", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                            "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
                                            "p, li { white-space: pre-wrap; }\n"
                                            "</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
                                            "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-weight:600;\">说明：</span></p>\n"
                                            "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">1.IP框输入要监控的主机IP</p>\n"
                                            "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">2.点击IP框下的开始进行监控</p>\n"
                                            "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">3.点击设置下的开始进行抓包</p>\n"
                                            "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">4.目前一次只能监控一台主机</p></body></html>"))
        self.monitor_start.setText(_translate("Capture", "开始"))
        self.monitor_stop.setText(_translate("Capture", "结束"))
        self.cutoff.setText(_translate("Capture", "断网"))
        self.recover.setText(_translate("Capture", "恢复网络"))
        self.cap_img.setText(_translate("Capture", "截图"))
        self.label_time.setText(_translate("Capture", "时长"))
        self.label_cpu.setText(_translate("Capture", "CPU"))
        self.label_mem.setText(_translate("Capture", "内存"))
        self.lable_mem_total.setText(_translate("Capture", "总内存"))

    def packet_process(self, packet):
        """
        处理抓到的数据包. 该函数作为sniff的参数使用.
        """
        # 如果是暂停状态，仍然会抓包，但不会将对抓到的数据包进行任何处理
        if not flag_pause:
            global packet_list
            packet_list.append(packet)
            packet_time = timestamp2time(packet.time)
            if Ether in packet:
                src = packet[Ether].src
                dst = packet[Ether].dst
                type1 = packet[Ether].type
                types = {
                    0x0800: 'IPv4',
                    0x0806: 'ARP',
                    0x86dd: 'IPv6',
                    0x88cc: 'LLDP',
                    0x891D: 'TTE'
                }
                if type1 in types:
                    proto = types[type1]
                else:
                    proto = 'LOOP'  # TODO: 不明白LOOP是什么意思，参考代码写的“协议”
                # IP
                if proto == 'IPv4':
                    # 建立协议查询字典
                    protos_ip = {
                        1: 'ICMP',
                        2: 'IGMP',
                        4: 'IP',
                        6: 'TCP',
                        8: 'EGP',
                        9: 'IGP',
                        17: 'UDP',
                        41: 'IPv6',
                        50: 'ESP',
                        89: 'OSPF'
                    }
                    src = packet[IP].src
                    dst = packet[IP].dst
                    proto = packet[IP].proto
                    if proto in protos_ip:
                        proto = protos_ip[proto]
                # TCP
                if TCP in packet:
                    protos_tcp = {
                        80: 'Http',
                        443: 'Https',
                        23: 'Telnet',
                        21: 'Ftp',
                        20: 'ftp_data',
                        22: 'SSH',
                        25: 'SMTP'  # 简单邮件传输协议
                    }
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    # 根据端口判断协议
                    if sport in protos_tcp:
                        proto = protos_tcp[sport]
                    elif dport in protos_tcp:
                        proto = protos_tcp[dport]
                # UDP
                elif UDP in packet:
                    protos_udp = {
                        53: 'DNS',
                        137: 'Nbname',  # NetBIOS名称服务
                        138: 'Nbdatagram',  # NetBIOS数据报服务
                        161: 'SNMP'  # 简单网络管理协议
                    }
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    # 根据端口判断协议
                    if sport in protos_udp:
                        proto = protos_udp[sport]
                    elif dport in protos_udp:
                        proto = protos_udp[dport]
            else:
                return
            packet_len = len(packet)  # 数据包长度
            packet_info = packet.summary()  # 数据包大致信息
            # 将该数据包的信息填入表格中
            row_cnt = self.table_packets.rowCount()
            self.table_packets.insertRow(row_cnt)
            self.table_packets.setItem(
                row_cnt, 0, QtWidgets.QTableWidgetItem(str(packet_time)))
            self.table_packets.setItem(
                row_cnt, 1, QtWidgets.QTableWidgetItem(str(src)))
            self.table_packets.setItem(
                row_cnt, 2, QtWidgets.QTableWidgetItem(str(dst)))
            self.table_packets.setItem(
                row_cnt, 3, QtWidgets.QTableWidgetItem(str(proto)))
            self.table_packets.setItem(
                row_cnt, 4, QtWidgets.QTableWidgetItem(str(packet_len)))
            self.table_packets.setItem(
                row_cnt, 5, QtWidgets.QTableWidgetItem(str(packet_info)))

    def packet_capture(self):
        """
        抓包
        """
        global filters, iface_ipt, packet_list
        event_stop_capture.clear()  # 设置停止抓包的flag为false
        packet_list.clear()  # 清空数据包列表
        # print(iface_ipt)
        sniff(iface=iface_ipt, prn=(lambda x: self.packet_process(x)),
              filter=filters, stop_filter=(lambda x: event_stop_capture.is_set()))

    def arp_attack(self, arp_pkg):
        """
        进行arp攻击
        """
        global iface_ipt
        while event_cutoff.is_set():
            sendp(arp_pkg, inter=1, iface=iface_ipt)

    def monitor_run(self):
        """
        接收被监控机发来的数据包，并进行格式转换后显示在界面上.
        :return:
        """
        global bufsize, img, event_monitor, soc, event_monitor
        # cv2.namedWindow("Monitor")
        lenb = soc.recv(5)
        img_tpye, img_len = struct.unpack(">BI", lenb)
        img_b = b''
        try:
            while img_len > bufsize:
                t = soc.recv(bufsize)
                img_b += t
                img_len -= len(t)
            while img_len > 0:
                t = soc.recv(img_len)
                img_b += t
                img_len -= len(t)
        except:
            print("连接中断!")
            self.monitor.setPixmap(QtGui.QPixmap(
                "source/images/monitor.jpg"))
            soc = None
            event_monitor.clear()
        data = np.frombuffer(img_b, dtype=np.uint8)
        img = cv2.imdecode(data, cv2.IMREAD_COLOR)
        while event_monitor.is_set():
            try:
                lock.acquire()
                imgs = cv2.resize(img, None, fx=0.6, fy=0.6)
                x, y = imgs.shape[1], imgs.shape[0]
                temp_imgSrc = QtGui.QImage(
                    imgs, x, y, QtGui.QImage.Format_RGB888)
                pix = QtGui.QPixmap.fromImage(temp_imgSrc).scaled(x, y)
                self.monitor.setPixmap(pix)
                lock.release()
            except:
                print("设置画面失败！")
            try:
                lenb = soc.recv(5)
                img_tpye, img_len = struct.unpack(">BI", lenb)
                img_b = b''
                while img_len > bufsize:
                    t = soc.recv(bufsize)
                    img_b += t
                    img_len -= len(t)
                while img_len > 0:
                    t = soc.recv(img_len)
                    img_b += t
                    img_len -= len(t)
            except:
                print("连接中断!")
                self.monitor.setPixmap(QtGui.QPixmap(
                    "source/images/hit2.jpg"))
                soc = None
                event_monitor.clear()
            data = np.frombuffer(img_b, dtype=np.uint8)
            img_new = cv2.imdecode(data, cv2.IMREAD_COLOR)
            if img_tpye == 0:  # 差异化传输
                img = img + img_new
            else:
                img = img_new
            cv2.waitKey(90)

    def recv_info(self):
        global soc1, event_monitor
        try:
            soc1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc1.connect((ip_current, port1))
        except:
            print("Socket1连接失败！")
        base_len = 12
        while event_monitor.is_set():
            info = b''
            rest = base_len
            while rest > 0:
                try:
                    info += soc1.recv(rest)
                    rest -= len(info)
                except:
                    print("info连接中断！")
                    soc1 = None
            self.mem_total_display.setText(
                str(round(struct.unpack('>f', info[8:12])[0], 2)) + 'G')
            self.cpu_display.setText(
                str(round(struct.unpack('>f', info[:4])[0], 2)) + ' %')
            self.mem_display.setText(
                str(round(struct.unpack('>f', info[4:8])[0], 2)) + ' %')
            time.sleep(2)

    def fill_time(self, t1):
        """
        计算监控时长.
        """
        while True:
            if event_monitor.is_set():
                t2 = time.time()
                t3 = time.strftime("%H:%M:%S", time.gmtime(t2-t1))
                self.time_display.setText(t3)
                time.sleep(1)
            else:
                t1 = time.time()
                time.sleep(1)

    def on_setting_clicked(self):
        """
        进入抓包设置页面.
        """
        filter = QtWidgets.QDialog()
        ui = Ui_filter()
        ui.setupUi(filter)
        filter.show()
        filter.exec_()

    def on_start_clicked(self):
        """
        启动抓包线程.
        """
        global flag_pause, flag_stop, flag_save, thread_capture
        # 设置按键是否可用
        self.capture_pause.setEnabled(True)
        self.capture_stop.setEnabled(True)
        self.capture_save.setEnabled(False)
        self.capture_start.setEnabled(False)

        flag_stop = False
        if not flag_pause:
            self.table_packets.setRowCount(0)

            # 开启新线程抓包
            try:
                thread_capture = threading.Thread(
                    target=self.packet_capture)
                thread_capture.setDaemon(True)
                thread_capture.start()
                flag_save = True
            except scapy.error.Scapy_Exception:
                print("过滤语法有误，请检查！")
                self.capture_pause.setEnabled(False)
                self.capture_save.setEnabled(False)
                self.capture_stop.setEnabled(False)
                self.capture_start.setEnabled(True)
        else:
            flag_pause = False

    def on_pause_clicked(self):
        """
        阻塞抓包线程，暂停抓包.
        """
        global flag_pause
        self.capture_start.setEnabled(True)
        self.capture_pause.setEnabled(False)
        self.capture_save.setEnabled(False)
        flag_pause = True

    def on_stop_clicked(self):
        """
        停止抓包.
        """
        global flag_pause, flag_stop, event_stop_capture
        event_stop_capture.set()
        flag_pause = False
        flag_stop = True
        self.capture_start.setEnabled(True)
        self.capture_save.setEnabled(True)
        self.capture_pause.setEnabled(False)
        self.capture_stop.setEnabled(False)

    def on_save_clicked(self):
        """
        保存抓到的包.
        """
        global flag_save, packet_list
        flag_save = True
        filename, ok = QtWidgets.QFileDialog.getSaveFileName(
            self, "文件保存", "C:/", "Packet Files (*.pcap);;All Files (*)")
        if ok:
            wrpcap(filename, packet_list)
        flag_save = False

    def on_table_clicked(self, index):
        global packet_list
        current_row = index.row()
        self.info_packet.clear()
        packet = packet_list[current_row]
        lines = (packet.show(dump=True)).split('\n')
        for line in lines:
            if line.startswith('#'):  # 新的一项
                line = line.strip('# ')
                self.info_packet.append(line)
            else:
                self.info_packet.append(line)
        self.info_packet.moveCursor(self.info_packet.textCursor().Start)

    def on_cutoff_clicked(self):
        """
        arp攻击实现断网.
        """
        global iface_ipt, ip_gate, ip_current
        if ip_current == '':
            ip_target = self.ipt_ip.text()
        else:
            ip_target = ip_current
        if ip_target == '':
            warntext = '未指定要断网的IP！'
            warn = QtWidgets.QDialog()
            ui = Ui_warning()
            ui.setupUi(warn, warntext)
            warn.show()
            warn.exec_()
            return
        mac_target = None
        while not mac_target:
            mac_target = getmacbyip(ip_target)  # 获取目标主机mac地址
        mac_gate = get_if_hwaddr(iface_ipt)  # 获取网卡mac地址
        arp_packet = Ether(src=mac_gate, dst=mac_target) / ARP(hwsrc=mac_gate,
                                                               psrc=ip_gate, hwdst=mac_target, pdst=ip_target)
        try:
            event_cutoff.set()
            arp = threading.Thread(target=self.arp_attack, args=(arp_packet,))
            arp.setDaemon(True)
            arp.start()
            self.recover.setEnabled(True)
        except:
            print("arp攻击发生错误！")

    def on_recover_clicked(self):
        """
        终止arp攻击，恢复网络
        """
        event_cutoff.clear()

    def on_monitor_start_clicked(self):
        """
        开始监视指定的主机.
        """
        global ip_current, thread_monitor, thread_info, thread_time
        ip_current = self.ipt_ip.text()
        try:
            set_socket(ip_current, port)
        except:
            warntext = '无法连接到目的主机！'
            warn = QtWidgets.QDialog()
            ui = Ui_warning()
            ui.setupUi(warn, warntext)
            warn.show()
            warn.exec_()
            return
        self.monitor_stop.setEnabled(True)
        self.cap_img.setEnabled(True)
        self.monitor_start.setEnabled(False)
        event_monitor.set()

        thread_monitor = threading.Thread(target=self.monitor_run)
        thread_monitor.setDaemon(True)
        thread_monitor.start()

        thread_info = threading.Thread(target=self.recv_info)
        thread_info.setDaemon(True)
        thread_info.start()

        time_start = time.time()
        thread_time = threading.Thread(
            target=self.fill_time, args=(time_start,))
        thread_time.setDaemon(True)
        thread_time.start()

    def on_monitor_stop_clicked(self):
        """
        停止监控主机.
        """
        global soc, soc1, event_monitor, img
        event_monitor.clear()
        if soc is not None:
            soc.close()
        if soc1 is not None:
            soc1.close()
        self.monitor_stop.setEnabled(False)
        self.cap_img.setEnabled(False)
        self.monitor_start.setEnabled(True)
        self.time_display.setText("")
        self.cpu_display.setText("")
        self.mem_total_display.setText("")
        self.mem_display.setText("")
        self.monitor.setPixmap(QtGui.QPixmap(
            "source/images/hit2.jpg"))

    def on_cap_img_clicked(self):
        """
        获取当前监控机的截图并保存.
        """
        global img
        filename, ok = QtWidgets.QFileDialog.getSaveFileName(
            self, "文件保存", "C:/", "Image (*.png);;All Files (*)")
        if ok:
            lock.acquire()
            cv2.imwrite(filename, cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
            lock.release()


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    monitor_tool = QtWidgets.QDialog()
    ui = Ui_Capture()
    ui.setupUi(monitor_tool)
    monitor_tool.setWindowIcon(QtGui.QIcon("source/images/hit1.jpg"))
    monitor_tool.show()
    sys.exit(app.exec_())
