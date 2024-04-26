from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QSizePolicy,
    QTabWidget,
    QVBoxLayout,
)
import sys
import commonWidget as cw


class Sm9Widget(QDialog):
    def __init__(self, parent=None):
        super(Sm9Widget, self).__init__(parent)
        self.setWindowFlags(
            self.windowFlags() | Qt.WindowType.WindowMinimizeButtonHint
        )

        self.sizePolicy = QSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred
        )
        self.tabWidget = QTabWidget()
        self.tabWidget.setSizePolicy(self.sizePolicy)

        # 区分不同的系统
        if sys.platform == "win32":
            fontname = "Consolas"
        elif sys.platform == "linux":
            fontname = "Monospace"
        else:
            fontname = "Menlo"

        self.tabWidget.addTab(
            cw.CommonWidget(
                type=cw.SM9WidgetType.SignVerify, fontName=fontname
            ),
            "签名/验签",
        )
        self.tabWidget.addTab(
            cw.CommonWidget(
                type=cw.SM9WidgetType.EncryptDecrypt, fontName=fontname
            ),
            "加解密",
        )
        self.tabWidget.addTab(
            cw.CommonWidget(
                type=cw.SM9WidgetType.KeyEncapDecap, fontName=fontname
            ),
            "密钥封装",
        )
        self.tabWidget.addTab(
            cw.CommonWidget(
                type=cw.SM9WidgetType.KeyExchange, fontName=fontname
            ),
            "密钥交换",
        )
        mainLayout = QVBoxLayout()
        mainLayout.addWidget(self.tabWidget)

        self.setLayout(mainLayout)
        self.setWindowTitle("SM9 算法验证工具")
        self.resize(800, 400)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    sm9Widget = Sm9Widget()
    sm9Widget.show()
    sys.exit(app.exec())
