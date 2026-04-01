import sys
import os
import io
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog

# import UI
from gui_ui import Ui_MainWindow

# import backend
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from mitm.main_sniffer import run_pcap


class MainApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.file_path = None

        # connect buttons
        self.ui.pushButton.clicked.connect(self.select_file)
        self.ui.pushButton_2.clicked.connect(self.run_tool)

    def select_file(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select PCAP", "", "PCAP Files (*.pcap *.pcapng)")
        if file:
            self.file_path = file
            self.ui.label.setText(file)

    def log(self, text):
        self.ui.textEdit.append(text)

    def run_tool(self):
        if not self.file_path:
            self.log("No file selected")
            return

        try:
            pkt = self.ui.lineEdit.text()
            tag = self.ui.lineEdit_2.text()
            val = self.ui.lineEdit_3.text()
            occ = self.ui.lineEdit_4.text()
            src_mac = self.ui.lineEdit_5.text()
            dst_mac = self.ui.lineEdit_6.text()
            src_ip = self.ui.lineEdit_7.text()
            dst_ip = self.ui.lineEdit_8.text()
            sv_file = self.ui.lineEdit_9.text()

            pkt = int(pkt) if pkt else None
            tag = int(tag) if tag else None
            val = int(val) if val else None
            occ = int(occ) if occ else None
            
            length = self.ui.checkBox.isChecked()
            mod_only = self.ui.checkBox_2.isChecked()
            save = self.ui.checkBox_3.isChecked()
            prt = self.ui.checkBox_4.isChecked()

            class Args:
                pass
            
            args = Args()
               
            args.pcap = self.file_path
            args.pkt = [pkt] if pkt else None
            args.t = tag
            args.v = val
            args.len = length
            args.mod = mod_only
            args.s = sv_file if save else None
            args.prt = prt
            args.src_mac = src_mac if src_mac else None
            args.dst_mac = dst_mac if dst_mac else None
            args.src_ip = src_ip if src_ip else None
            args.dst_ip = dst_ip if dst_ip else None
            args.occ = occ

            self.log("Running...")

            buffer = io.StringIO()
            sys.stdout = buffer
            
            run_pcap(args.pcap, args)
            
            sys.stdout = sys.__stdout__
            
            output = buffer.getvalue()
            self.ui.textEdit.setPlainText(output)

            self.log("Done...")

        except Exception as e:
            self.log(f"Error: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainApp()
    window.show()
    sys.exit(app.exec())
