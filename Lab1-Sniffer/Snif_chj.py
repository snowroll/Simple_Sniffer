#-*- coding:utf-8 -*-

from Main import Ui_MainWindow  # 主从窗口的ui界面
from Dialog import Ui_Dialog
from CSniffer import *  # 嗅探程序

from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtChart import *
 
import numpy as np
import sys, time, threading
from urllib.parse import unquote  #解码url编码的用户名和密码


# 继承QThread  网络嗅探
class Runthread(QThread):
    #  通过类成员对象定义信号对象
    _signal = pyqtSignal(list)
    
    def __init__(self, device_name, rule):
        super(Runthread, self).__init__()
        self.CSniffer = CSniffer()
        self.CSniffer.pcap_set(device_name, rule)
        self._isStop = False
 
    def __del__(self):
        self.wait()
 
    def run(self):
        data = []
        index = 1
        start_time = time.time()
        for stamp, pkt in self.CSniffer.pc:
            if not self._isStop:
                data.append(self.CSniffer.format_packet(stamp, pkt))
                if time.time() - start_time >= 1 or index % 20 == 0:
                    start_time = time.time()
                    self._signal.emit(data)
                    data = []
                index += 1
            else:
                break

class MySortFilterModel(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super(MySortFilterModel, self).__init__(parent)
    
    def lessThan(self, left, right):
        leftData = self.sourceModel().data(left)
        rightData = self.sourceModel().data(right)
        if isinstance(leftData, str) and isinstance(rightData, str):
            if left.column() == 0:
                return int(leftData) < int(rightData)
            else:
                return leftData < rightData
        else:
            return True
    
    def filterAcceptsRow(self, sourceRow, sourceParent):
        stamp  = self.sourceModel().index(sourceRow, 1, sourceParent)
        src_ip = self.sourceModel().index(sourceRow, 2, sourceParent)
        dst_ip = self.sourceModel().index(sourceRow, 3, sourceParent)
        pro    = self.sourceModel().index(sourceRow, 4, sourceParent)
        regex = self.filterRegExp()
        return (regex.indexIn(self.sourceModel().data(stamp)) != -1 \
               or regex.indexIn(self.sourceModel().data(src_ip)) != -1
               or regex.indexIn(self.sourceModel().data(dst_ip)) != -1
               or regex.indexIn(self.sourceModel().data(pro)) != -1)

class Dlg(QDialog,Ui_Dialog):        #次界面
    exit_signal = pyqtSignal()
    stop_signal = pyqtSignal()
    def __init__(self,parent=None):
        super(Dlg, self).__init__(parent)
        self.setupUi(self)
        self.setWindowTitle('sniff_chj')
        # self.setWindowIcon(QIcon('img/dog.png'))

        self.row_idx = 0
        self.flag = True
        self.device_name = ''
        self.filter_rule = ''
        self.data = []
        self.pro_color = {'TCP':QColor(135,206,235,50), 'UDP':QColor(0,255,0,50), 'HTTP':QColor(255,215,0,50), \
                          'ICMP':QColor(255,97,0,50), 'IGMP':QColor(156,102,31,50), 'ARP':QColor(160,32,240,50)}
        self.pro_num = {'TCP': 0, 'UDP': 0, 'HTTP':0, 'ICMP':0, 'IGMP':0, 'ARP': 0}
        self.createContextMenu()  #创建右键菜单
        # 数据列表
        self.model = QStandardItemModel(8,6)  # 设置数据层次结构，8行6列
        self.model.setHorizontalHeaderLabels(['序号', '时间戳','源地址','目标地址', '协议类型', '信息'])  # 设置水平方向四个头标签文本内容
        
        self.proxymodel = MySortFilterModel()
        self.proxymodel.setSourceModel(self.model)
        self.tableView.setModel(self.proxymodel)
        self.tableView.verticalHeader().setVisible(False) 
        #水平方向标签拓展剩下的窗口部分，填满表格
        self.tableView.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.tableView.horizontalHeader().setStretchLastSection(True)
        self.tableView.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)  # 水平方向，表格大小拓展到适当的尺寸
        # self.tableView.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        for i in range(5):
            self.tableView.horizontalHeader().setSectionResizeMode(i, QHeaderView.Fixed)
            self.tableView.setColumnWidth(i, 100)
        self.tableView.setSortingEnabled(True)
        self.tableView.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableView.sortByColumn(0, Qt.AscendingOrder)

        self.tableView.clicked.connect(self.show_detail)
        self.begin_btn.clicked.connect(self.start)
        self.stop_btn.clicked.connect(self.stop)
        self.filter_btn.clicked.connect(self.filterRegExpChanged)

    def start(self):
        self.data_clear()
        self.thread = Runthread(self.device_name, self.filter_rule)
        self.thread._signal.connect(self.setdata)
        self.thread.start() 
        self.stop_btn.setEnabled(True)

    def stop(self):
        try:
            self.thread._isStop = True
            self.stop_btn.setEnabled(False)
        except Exception as e:
            pass

    def data_clear(self):
        self.row_idx = 0
        self.data.clear()
        self.model.removeRows(0, self.model.rowCount())
        for i in self.pro_num:
            self.pro_num[i] = 0

    def closeEvent(self, event):  # 重写退出事件
        self.data_clear()
        self.exit_signal.emit()
        event.accept()

    def setdata(self, data):  # data = list of [tmstmp, src_ip, dst_ip, protocol, hex_rep, Frames]
        for info in data:
            bg_color = self.pro_color[info[3]]
            index_item = QStandardItem(str(self.row_idx))
            index_item.setBackground(bg_color)
            self.model.setItem(self.row_idx, 0, index_item)
            self.data.append(info)
            self.pro_num[info[3]] += 1
            for i in range(len(info)-2):
                tmp_item = QStandardItem(info[i])
                tmp_item.setBackground(bg_color)
                self.model.setItem(self.row_idx, i+1, tmp_item)  # QStandardItem(info[i])) 
            self.row_idx += 1     

    def show_detail(self, item):
        self.textBrowser.clear()
        for i in range(self.treeWidget.topLevelItemCount()):
            self.treeWidget.takeTopLevelItem(0)
        
        row = item.row()
        r_idx = int(self.model.index(row, 0).data())
        hex_data = self.data[r_idx][-2]
        self.textBrowser.append(hex_data)  # 包的16进制和ASCII值显示
        frame_data = self.data[r_idx][-1]  # 设置详细帧信息
        for frame in frame_data:
            root_item = QTreeWidgetItem(self.treeWidget)
            root_item.setText(0, frame)
            for i in frame_data[frame]:
                child = QTreeWidgetItem(root_item)
                child.setText(0, i)

    def filterRegExpChanged(self):
        self.textBrowser.clear()
        for i in range(self.treeWidget.topLevelItemCount()):
            self.treeWidget.takeTopLevelItem(0)

        filter_rule = self.lineEdit.text()
        self.proxymodel.setFilterFixedString(filter_rule)  #将字符匹配作为过滤规则
        print("过滤规则为: ", filter_rule)

    def createContextMenu(self):
        # 必须将ContextMenuPolicy设置为Qt.CustomContextMenu
        # 否则无法使用customContextMenuRequested信号
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.showContextMenu)

        # 创建QMenu
        self.contextMenu = QMenu(self)
        self.actionA = self.contextMenu.addAction(u'提取密码')
        self.actionB = self.contextMenu.addAction(u'百分比图表')
        # self.actionB = self.contextMenu.addAction(u'删除')
        # 将动作与处理函数相关联
        # 这里为了简单，将所有action与同一个处理函数相关联，
        # 当然也可以将他们分别与不同函数关联，实现不同的功能
        self.actionA.triggered.connect(self.actionAHandler)
        self.actionB.triggered.connect(self.actionBHandler)
    
    def showContextMenu(self):
        self.contextMenu.move(QCursor().pos())
        self.contextMenu.show()
    
    def actionAHandler(self):
        result = ''
        for i in range(len(self.data)):
            tmp, host = '', ''
            frame = self.data[i][-1]
            for key in frame:
                for info in frame[key]:
                    if 'host:' in info:
                        host= info + '\n'
                    if 'pwd=' in info:
                        pwd_info = ' '.join(unquote(info).split('&')[:2])
                        tmp = tmp + host + pwd_info + '\n'
                result += tmp
        QMessageBox.information(self, '密码提取', result, QMessageBox.Yes)
    
    def actionBHandler(self):
        pie = QPieSeries()
        pie_num = 0
        for pro in self.pro_num:
            if self.pro_num[pro] != 0:
                pie.append(pro, self.pro_num[pro])
                pie_num += 1
        for i in range(pie_num):
            p_slice = pie.slices()[i]
            p_slice.setLabelVisible()
            p_slice.setPen(QPen(Qt.darkGreen, 1))
            p_slice.setBrush(self.pro_color[p_slice.label()])
            p_slice.hovered.connect(self.slice_clicked)
        
        piechart = QChart()
        piechart.addSeries(pie)
        piechart.setTitle("捕获协议包占比")
        # piechart.legend().hide()

        self.piecharview = QChartView(piechart)#定义charView窗口，添加chart元素，设置主窗口为父窗体，既将chartView嵌入到父窗体
        self.piecharview.setGeometry(0,0,600,600)#设置charview在父窗口的大小、位置
        self.piecharview.setRenderHint(QPainter.Antialiasing)#设置抗锯齿
        self.piecharview.show()
           
    @pyqtSlot(bool)
    def slice_clicked(self, state):
        clicked_slice = self.sender()
        label = clicked_slice.label()
        if state:
            precentage = round(clicked_slice.percentage(),2)
            clicked_slice.setLabel(label+': '+ str(self.pro_num[label]) + ', '+ str(precentage))
            clicked_slice.setExploded()
        else:
            clicked_slice.setLabel(label.split(':')[0])
            clicked_slice.setExploded(False)
        
class MainWin(QMainWindow,Ui_MainWindow):     #主界面
    selected_op = pyqtSignal()
    def __init__(self, parent=None):
        super(MainWin, self).__init__(parent)
        self.setupUi(self)
        self.setWindowTitle('sniff_chj')
        # self.setWindowIcon(QIcon('img/dog1.png'))

        self.sdlg = Dlg()
        self.thread = None

        # 初始化相应参数
        self.select_device = ''
        self.filter_rule = ''
        self.options = ['ether', 'ip', 'tcp', 'udp', 'arp', 'dst host 127.0.0.1', 'src host 127.0.0.1', \
                        'dst port 80', 'src port 443', 'tcp src port port', 'less length', 'greater length']

        # 初始化列表模型
        option_list = QStringListModel()
        option_list.setStringList(self.options)
        self.option_listView = QListView(parent=self)
        self.option_listView.SelectionMode = 'Single'
        self.option_listView.setModel(option_list)
        self.option_listView.hide()

        slm = QStringListModel()
        devices = pcap.findalldevs()
        self.qList = [item for item in devices if devices.count(item) == 1]
        
        slm.setStringList(self.qList)   # 设置模型列表视图，加载数据列表 
        self.listView.SelectionMode = "Single"  
        self.listView.setModel(slm)  # 设置列表视图的模型

        self.Option_btn.clicked.connect(self.show_option)
        self.option_listView.clicked.connect(self.click_option)
        self.listView.clicked.connect(self.click_item)
        self.pushButton.clicked.connect(lambda: self.start_filter(self.select_device))
        self.sdlg.exit_signal.connect(self.show)

    def click_item(self, qModelIndex):
        # print(self.qList[qModelIndex.row()])
        self.select_device = self.qList[qModelIndex.row()]

    def show_option(self):
        m = self.listView.geometry()
        self.option_listView.setGeometry(m)
        self.option_listView.show()

    def click_option(self, qModelIndex):
        self.Filter_line.setText(self.options[qModelIndex.row()])
        self.option_listView.hide()

    def start_filter(self, device_name):
        if device_name == '':
            QMessageBox.warning(self,"警告",  
                                   self.tr("请选择网卡"),  
                                   QMessageBox.Yes)  
            return
        tmp_pcap = pcap.pcap(device_name)
        filter_rule = self.Filter_line.text()
        try:
            tmp_pcap.setfilter(filter_rule)
        except Exception as e:
            QMessageBox.critical(self, "错误",
                                   self.tr("过滤规则错误"),
                                   QMessageBox.Yes)
            return

        self.hide()
        self.sdlg.device_name = device_name
        self.sdlg.filter_rule = filter_rule
        self.sdlg.show()
        return self.sdlg.exec()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon('img/dog.png'))
    win = MainWin()  
    win.show()
    sys.exit(app.exec())
