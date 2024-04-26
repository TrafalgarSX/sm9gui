from PyQt6.QtWidgets import (
    QTabWidget,
    QApplication,
    QDialog,
    QGridLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QTextEdit,
    QWidget,
    QMessageBox,
)
from PyQt6.QtGui import QFont
import sys
import SM9
import numpy as np
import binascii
from enum import Enum

SM3_HMAC_SIZE = 32


class SM9WidgetType(Enum):
    SignVerify = 1
    EncryptDecrypt = 2
    KeyEncapDecap = 3
    KeyExchange = 4


def insertNewlines(string, every=64):
    return "\n".join(
        string[i : i + every] for i in range(0, len(string), every)
    )


def deleteNewlines(string):
    return string.replace("\n", "")


class CommonWidget(QDialog):
    def __init__(
        self,
        parent=None,
        type=SM9WidgetType.SignVerify,
        fontName="CaskaydiaCove NF",
    ):
        super(CommonWidget, self).__init__(parent)

        self.sizePolicy = QSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred
        )
        self.type = type
        self.singleLineHeight = QTextEdit().fontMetrics().lineSpacing()
        self.singleLineHeight = self.singleLineHeight + 6
        self.fontUse = QFont(fontName)
        self.fontUse.setFixedPitch(True)
        self.lineWrapWidth = 64

        if self.type == SM9WidgetType.SignVerify:
            self.createSignVerifyWidget()
        elif self.type == SM9WidgetType.EncryptDecrypt:
            self.createEncDecWidget()
        elif self.type == SM9WidgetType.KeyEncapDecap:
            self.createEnCapDecapWidget()

    def createSignVerifyWidget(self):
        signVerifyTabLayout = QGridLayout()

        signVerifyTabLayout.addWidget(self.keyInfoGroup(), 0, 0)
        signVerifyTabLayout.addWidget(self.calcInfoGroup(), 1, 0)
        signVerifyTabLayout.addWidget(self.featureButtonGroup(), 2, 0)

        self.setLayout(signVerifyTabLayout)

    def createEncDecWidget(self):
        encDecTabLayout = QGridLayout()

        encDecTabLayout.addWidget(self.keyInfoGroup(), 0, 0)
        encDecTabLayout.addWidget(self.calcInfoGroup(), 1, 0)
        encDecTabLayout.addWidget(self.featureButtonGroup(), 2, 0)

        self.setLayout(encDecTabLayout)

    def createEnCapDecapWidget(self):
        enCapDecapTabLayout = QGridLayout()

        enCapDecapTabLayout.addWidget(self.keyInfoGroup(), 0, 0)
        enCapDecapTabLayout.addWidget(self.keyEnCapInfoGroup(), 1, 0)
        enCapDecapTabLayout.addWidget(self.featureButtonGroup(), 2, 0)

        self.setLayout(enCapDecapTabLayout)

    def keyInfoGroup(self):
        currentIdentify = ""
        userPriKeyLabelName = ""
        userId = ""
        masterPublicKeyTextHeight = 2
        userPrivateKeyTextHeight = 2
        if self.type == SM9WidgetType.SignVerify:
            userPriKeyLabelName = "签名私钥"
            currentIdentify = "01"
            userId = "Alice"
            masterPublicKeyTextHeight = 4
            userPrivateKeyTextHeight = 2

        elif (
            self.type == SM9WidgetType.EncryptDecrypt
            or self.type == SM9WidgetType.KeyEncapDecap
        ):
            userPriKeyLabelName = "加密私钥"
            currentIdentify = "03"
            userId = "Bob"
            masterPublicKeyTextHeight = 2
            userPrivateKeyTextHeight = 4
        else:
            currentIdentify = "02"
            userId = "Charlie"
            masterPublicKeyTextHeight = 2

        masterPrivateKeyLabel = QLabel("主私钥")
        masterPublicKeyLabel = QLabel("主公钥")
        userPrivateKeyLabel = QLabel(userPriKeyLabelName)
        identifyLabel = QLabel("识别码")
        userIdLabel = QLabel("ID")

        self.masterPrivateKeyLineEdit = QLineEdit()
        self.masterPublicKeyTextEdit = QTextEdit()
        self.userPrivateKeyTextEdit = QTextEdit()

        self.masterPrivateKeyLineEdit.setFont(self.fontUse)
        self.masterPublicKeyTextEdit.setFont(self.fontUse)
        self.userPrivateKeyTextEdit.setFont(self.fontUse)
        self.masterPublicKeyTextEdit.setFixedHeight(
            self.singleLineHeight * masterPublicKeyTextHeight
        )
        self.userPrivateKeyTextEdit.setFixedHeight(
            self.singleLineHeight * userPrivateKeyTextHeight
        )

        if userPriKeyLabelName != "":
            userPrivateKeyLabel.setText(userPriKeyLabelName)

        self.userIdLineEdit = QLineEdit()
        self.userIdLineEdit.setText(userId)
        self.userIdLineEdit.setFont(self.fontUse)

        self.identifyLineEdit = QLineEdit()
        self.identifyLineEdit.setText(currentIdentify)
        self.identifyLineEdit.setDisabled(True)
        self.identifyLineEdit.setFont(self.fontUse)

        keyInfoLayout = QGridLayout()
        keyInfoLayout.addWidget(masterPrivateKeyLabel, 0, 0, 1, 1)
        keyInfoLayout.addWidget(self.masterPrivateKeyLineEdit, 0, 1, 1, 3)
        keyInfoLayout.addWidget(identifyLabel, 1, 0, 1, 1)
        keyInfoLayout.addWidget(self.identifyLineEdit, 1, 1, 1, 1)
        keyInfoLayout.addWidget(userIdLabel, 1, 2, 1, 1)
        keyInfoLayout.addWidget(self.userIdLineEdit, 1, 3, 1, 1)
        keyInfoLayout.addWidget(masterPublicKeyLabel, 2, 0, 1, 1)
        keyInfoLayout.addWidget(self.masterPublicKeyTextEdit, 2, 1, 1, 3)
        if userPriKeyLabelName != "":
            keyInfoLayout.addWidget(userPrivateKeyLabel, 3, 0, 1, 1)
            keyInfoLayout.addWidget(self.userPrivateKeyTextEdit, 3, 1, 1, 3)

        keyInfoWidget = QWidget()
        keyInfoWidget.setObjectName("keyInfoWidget")
        keyInfoWidget.setLayout(keyInfoLayout)
        keyInfoWidget.setStyleSheet("#keyInfoWidget {border: 1px solid gray;}")
        return keyInfoWidget

    def calcInfoGroup(self):
        calcInfoLayout = QGridLayout()
        calcInfoLayout.setColumnStretch(0, 1)
        calcInfoLayout.setColumnStretch(1, 3)
        plainTextLabelName = ""
        calcFirstLabelName = ""
        calcSecondLabelName = ""
        calcFirstTextHeight = 2
        calcSecondTextHeight = 2
        if self.type == SM9WidgetType.SignVerify:
            plainTextLabelName = "签名原文"
            calcFirstLabelName = "h"
            calcSecondLabelName = "S"
            calcFirstTextHeight = 1
            calcSecondTextHeight = 2
        elif self.type == SM9WidgetType.EncryptDecrypt:
            plainTextLabelName = "加密原文"
            calcFirstLabelName = "密文"
            calcSecondLabelName = "解密原文"
            calcFirstTextHeight = 4
            calcSecondTextHeight = 1

        plainTextLabel = QLabel(plainTextLabelName)
        calcFirstLabel = QLabel(calcFirstLabelName)
        calcSecondLabel = QLabel(calcSecondLabelName)
        plainTextLabel.setSizePolicy(
            QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred
        )

        self.plainTextLineEdit = QLineEdit()
        self.plainTextLineEdit.textChanged.connect(self.plainHexTextShow)
        self.plainTextLineEdit.setFont(self.fontUse)
        # TODO 这里 setPlaceholder 设置中文加载会慢， 不知道为什么, setText 不会。
        self.plainTextLineEdit.setPlaceholderText("utf-8 string[optional]")
        self.plainHexTextLineEdit = QLineEdit()
        self.plainHexTextLineEdit.setFont(self.fontUse)
        # TODO 这里 setPlaceholder 设置中文加载会慢， 不知道为什么, setText 不会。
        self.plainHexTextLineEdit.setPlaceholderText("Hex string[required]")

        self.calcFirstTextEdit = QTextEdit()
        self.calcSecondTextEdit = QTextEdit()
        self.calcFirstTextEdit.setFont(self.fontUse)
        self.calcSecondTextEdit.setFont(self.fontUse)

        calcInfoLayout.addWidget(plainTextLabel, 0, 0, 1, 1)
        calcInfoLayout.addWidget(self.plainTextLineEdit, 0, 1, 1, 2)
        calcInfoLayout.addWidget(self.plainHexTextLineEdit, 1, 1, 1, 2)

        self.calcFirstTextEdit.setFixedHeight(
            self.singleLineHeight * calcFirstTextHeight
        )
        self.calcSecondTextEdit.setFixedHeight(
            self.singleLineHeight * calcSecondTextHeight
        )
        calcInfoLayout.addWidget(calcFirstLabel, 3, 0, 1, 1)
        calcInfoLayout.addWidget(self.calcFirstTextEdit, 3, 1, 1, 2)
        calcInfoLayout.addWidget(calcSecondLabel, 4, 0, 1, 1)
        calcInfoLayout.addWidget(self.calcSecondTextEdit, 4, 1, 1, 2)

        calcInfoWidget = QWidget()
        calcInfoWidget.setObjectName("calcInfoWidget")
        calcInfoWidget.setLayout(calcInfoLayout)
        calcInfoWidget.setStyleSheet(
            "#calcInfoWidget {border: 1px solid gray;}"
        )
        return calcInfoWidget

    def keyEnCapInfoGroup(self):
        keyEnCapInfoLayout = QGridLayout()

        keyLengthLabel = QLabel("KEY长度")
        keyOriginLabel = QLabel("KEY原文")
        CLabel = QLabel("C")
        MLabel = QLabel("M")

        self.keyLengthLineEdit = QLineEdit()
        self.keyLengthLineEdit.setFont(self.fontUse)
        self.keyLengthLineEdit.setText("32")

        self.keyOriginTextEdit = QTextEdit()
        self.keyOriginTextEdit.setFont(self.fontUse)

        self.CTextEdit = QTextEdit()
        self.CTextEdit.setFont(self.fontUse)
        self.MLineEdit = QLineEdit()
        self.MLineEdit.setFont(self.fontUse)

        self.keyOriginTextEdit.setFixedHeight(self.singleLineHeight * 1)
        self.CTextEdit.setFixedHeight(self.singleLineHeight * 2)

        keyEnCapInfoLayout.addWidget(keyLengthLabel, 0, 0, 1, 1)
        keyEnCapInfoLayout.addWidget(self.keyLengthLineEdit, 0, 1, 1, 1)
        keyEnCapInfoLayout.addWidget(keyOriginLabel, 1, 0, 1, 1)
        keyEnCapInfoLayout.addWidget(self.keyOriginTextEdit, 1, 1, 1, 1)
        keyEnCapInfoLayout.addWidget(CLabel, 3, 0, 1, 1)
        keyEnCapInfoLayout.addWidget(self.CTextEdit, 3, 1, 1, 1)
        keyEnCapInfoLayout.addWidget(MLabel, 4, 0, 1, 1)
        keyEnCapInfoLayout.addWidget(self.MLineEdit, 4, 1, 1, 1)

        keyEnCapInfoWidget = QWidget()
        keyEnCapInfoWidget.setObjectName("keyEnCapInfoWidget")
        keyEnCapInfoWidget.setLayout(keyEnCapInfoLayout)
        keyEnCapInfoWidget.setStyleSheet(
            "#keyEnCapInfoWidget {border: 1px solid gray;}"
        )
        return keyEnCapInfoWidget

    def keyExchangeInfoGroup(self, currentIndex=0):
        keyExchangeInfoLayout = QGridLayout()

        keyExchangeInfoWidget = QWidget()
        keyExchangeInfoWidget.setObjectName("keyExchangeInfoWidget")
        keyExchangeInfoWidget.setLayout(keyExchangeInfoLayout)
        keyExchangeInfoWidget.setStyleSheet(
            "#keyExchangeInfoWidget {border: 1px solid gray;}"
        )

        return keyExchangeInfoWidget

    def featureButtonGroup(self):
        featureButtonLayout = QGridLayout()
        randomPriKeyButton = QPushButton("随机生成私钥")
        generateMasterKeyButton = QPushButton("生成主密钥")
        featureButtonLayout.addWidget(generateMasterKeyButton, 0, 0, 1, 1)
        featureButtonLayout.addWidget(randomPriKeyButton, 0, 1, 1, 1)

        if self.type == SM9WidgetType.SignVerify:
            signButton = QPushButton("签名")
            verifyButton = QPushButton("验签")

            randomPriKeyButton.clicked.connect(self.userSignPriKey)
            generateMasterKeyButton.clicked.connect(self.generateSignMasterKey)
            signButton.clicked.connect(self.sign)
            verifyButton.clicked.connect(self.verify)

            featureButtonLayout.addWidget(signButton, 0, 2, 1, 1)
            featureButtonLayout.addWidget(verifyButton, 0, 3, 1, 1)
        elif self.type == SM9WidgetType.EncryptDecrypt:
            encButton = QPushButton("加密")
            decButton = QPushButton("解密")

            randomPriKeyButton.clicked.connect(self.userEncPriKey)
            generateMasterKeyButton.clicked.connect(self.generateEncMasterKey)
            encButton.clicked.connect(self.encrypt)
            decButton.clicked.connect(self.decrypt)

            featureButtonLayout.addWidget(encButton, 0, 2, 1, 1)
            featureButtonLayout.addWidget(decButton, 0, 3, 1, 1)
        elif self.type == SM9WidgetType.KeyEncapDecap:
            enCapButton = QPushButton("封装")
            deCapButton = QPushButton("解封")

            randomPriKeyButton.clicked.connect(self.userEncPriKey)
            generateMasterKeyButton.clicked.connect(self.generateEncMasterKey)
            enCapButton.clicked.connect(self.encap)
            deCapButton.clicked.connect(self.decap)

            featureButtonLayout.addWidget(enCapButton, 0, 2, 1, 1)
            featureButtonLayout.addWidget(deCapButton, 0, 3, 1, 1)
        else:
            keyExchangeButton = QPushButton("密钥交换")

            # keyExchangeButton.clicked.connect(self.keyExchange)
            featureButtonLayout.addWidget(keyExchangeButton, 0, 2, 1, 1)

        featureButtonWidget = QWidget()
        featureButtonWidget.setObjectName("featureButtonWidget")
        featureButtonWidget.setLayout(featureButtonLayout)
        featureButtonWidget.setStyleSheet(
            "#featureButtonWidget {border: 1px solid gray;}"
        )
        return featureButtonWidget

    def userSignPriKey(self):
        try:
            ksStrHex = self.masterPrivateKeyLineEdit.text()

            if ksStrHex == "":
                pu8Ks = np.zeros(32, dtype=np.uint8)
            elif len(ksStrHex) == 64:
                pu8Ks = np.frombuffer(
                    binascii.a2b_hex(ksStrHex), dtype=np.uint8
                )
            elif len(ksStrHex) != 64:
                self.showMessageBox("主私钥长度错误，应为 32 字节")
                return

            userId = self.userIdLineEdit.text()
            ida = np.frombuffer(userId.encode("utf-8"), dtype=np.uint8)
            pu8dsA = np.zeros(64, dtype=np.uint8)
            ret = SM9.SM9_GenerateSignKeyWrap(pu8Ks, ida, pu8dsA)
            if ret != 0:
                self.showMessageBox("生成签名私钥失败")
                return

            dsAStrHex = binascii.hexlify(pu8dsA.tobytes()).decode("utf-8")
            self.userPrivateKeyTextEdit.setText(insertNewlines(dsAStrHex, 64))
        except binascii.Error as e:
            errStr = e.args[0] + "\n主私钥转换 Hex 字符串失败!"
            self.showMessageBox(errStr)
            return
        except UnicodeEncodeError as e:
            errStr = e.args[0] + "\nuserId 输入的字符不支持!"
            self.showMessageBox(errStr)
            return

    def userEncPriKey(self):
        try:
            keStrHex = self.masterPrivateKeyLineEdit.text()
            if keStrHex == "":
                pu8Ke = np.zeros(32, dtype=np.uint8)
            elif len(keStrHex) == 64:
                pu8Ke = np.frombuffer(
                    binascii.a2b_hex(keStrHex), dtype=np.uint8
                )
            elif len(keStrHex) != 64:
                self.showMessageBox("主私钥长度错误，应为 32 字节")
                return

            userId = self.userIdLineEdit.text()
            idb = np.frombuffer(userId.encode("utf-8"), dtype=np.uint8)
            pu8deB = np.zeros(128, dtype=np.uint8)
            ret = SM9.SM9_GenerateEncKeyWrap(pu8Ke, idb, pu8deB)
            if ret != 0:
                self.showMessageBox("生成加密私钥失败")
                return

            deBStrHex = binascii.hexlify(pu8deB.tobytes()).decode("utf-8")
            self.userPrivateKeyTextEdit.setText(insertNewlines(deBStrHex, 64))
        except binascii.Error as e:
            errStr = e.args[0] + "\n主私钥转换 Hex 字符串失败!"
            self.showMessageBox(errStr)
            return
        except UnicodeEncodeError as e:
            errStr = e.args[0] + "\nuserId 输入的字符不支持!"
            self.showMessageBox(errStr)
            return

    def generateSignMasterKey(self):
        try:
            ksStrHex = self.masterPrivateKeyLineEdit.text()

            if ksStrHex == "":
                pu8Ks = np.zeros(32, dtype=np.uint8)
            elif len(ksStrHex) == 64:
                pu8Ks = np.frombuffer(
                    binascii.a2b_hex(ksStrHex), dtype=np.uint8
                )
            elif len(ksStrHex) != 64:
                self.showMessageBox("主私钥长度错误，应为 32 字节")
                return

            pu8Ppubs = np.zeros(128, dtype=np.uint8)
            ret = SM9.SM9_GenMasterSignKeyWrap(pu8Ks, pu8Ppubs)
            if ret != 0:
                self.showMessageBox("生成签名主密钥对失败")
                return

            ksStrHex = binascii.hexlify(pu8Ks.tobytes()).decode("utf-8")
            ppubsStrHex = binascii.hexlify(pu8Ppubs.tobytes()).decode("utf-8")
            self.masterPrivateKeyLineEdit.setText(ksStrHex)
            self.masterPublicKeyTextEdit.setText(
                insertNewlines(ppubsStrHex, 64)
            )
        except binascii.Error as e:
            errStr = e.args[0] + "\n主私钥转换 Hex 字符串失败!"
            self.showMessageBox(errStr)
            return

    def generateEncMasterKey(self):
        try:
            keStrHex = self.masterPrivateKeyLineEdit.text()
            if keStrHex == "":
                pu8Ke = np.zeros(32, dtype=np.uint8)
            elif len(keStrHex) == 64:
                pu8Ke = np.frombuffer(
                    binascii.a2b_hex(keStrHex), dtype=np.uint8
                )
            elif len(keStrHex) != 64:
                self.showMessageBox("主私钥长度错误，应为 32 字节")
                return

            pu8Ppube = np.zeros(64, dtype=np.uint8)
            ret = SM9.SM9_GenMasterEncKeyWrap(pu8Ke, pu8Ppube)
            if ret != 0:
                self.showMessageBox("生成加密主密钥对失败")
                return

            keStrHex = binascii.hexlify(pu8Ke.tobytes()).decode("utf-8")
            ppubeStrHex = binascii.hexlify(pu8Ppube.tobytes()).decode("utf-8")
            self.masterPrivateKeyLineEdit.setText(keStrHex)
            self.masterPublicKeyTextEdit.setText(
                insertNewlines(ppubeStrHex, 64)
            )
        except binascii.Error as e:
            errStr = e.args[0] + "\n主私钥转换 Hex 字符串失败!"
            self.showMessageBox(errStr)
            return

    def sign(self):
        try:
            ppubsStrHex = deleteNewlines(
                self.masterPublicKeyTextEdit.toPlainText()
            )
            if ppubsStrHex != "" and len(ppubsStrHex) == 256:
                pu8Ppubs = np.frombuffer(
                    binascii.a2b_hex(ppubsStrHex), dtype=np.uint8
                )
            else:
                self.showMessageBox("主公钥输入错误")
                return

            dsAStrHex = deleteNewlines(
                self.userPrivateKeyTextEdit.toPlainText()
            )
            if dsAStrHex != "" and len(dsAStrHex) == 128:
                pu8dsA = np.frombuffer(
                    binascii.a2b_hex(dsAStrHex), dtype=np.uint8
                )
            else:
                self.showMessageBox("签名私钥输入错误")
                return

            plainTextHex = self.plainHexTextLineEdit.text()
            if plainTextHex == "":
                self.showMessageBox("签名原文不能为空")
                return
            plainText = binascii.a2b_hex(plainTextHex)
            pu8Msg = np.frombuffer(plainText, dtype=np.uint8)

            pu8H = np.zeros(32, dtype=np.uint8)
            pu8S = np.zeros(64, dtype=np.uint8)
            ret = SM9.SM9_SignWrap(pu8Ppubs, pu8dsA, pu8Msg, pu8H, pu8S)
            if ret != 0:
                self.showMessageBox("SM9_SignWrap failed")
                return

            HHex = binascii.hexlify(pu8H.tobytes()).decode("utf-8")
            SHex = binascii.hexlify(pu8S.tobytes()).decode("utf-8")
            self.calcFirstTextEdit.setText(HHex)
            self.calcSecondTextEdit.setText(insertNewlines(SHex, 64))
        except binascii.Error as e:
            errStr = e.args[0] + "\n主公钥或签名私钥或签名原文转换 Hex 字符串失败!"
            self.showMessageBox(errStr)
            return
        except UnicodeEncodeError as e:
            errStr = e.args[0] + "\n签名原文输入的字符不支持!"
            self.showMessageBox(errStr)
            return

    def verify(self):
        try:
            ppubsStrHex = deleteNewlines(
                self.masterPublicKeyTextEdit.toPlainText()
            )
            if ppubsStrHex != "" and len(ppubsStrHex) == 256:
                pu8Ppubs = np.frombuffer(
                    binascii.a2b_hex(ppubsStrHex), dtype=np.uint8
                )
            else:
                self.showMessageBox("主公钥输入错误")
                return

            idaStr = self.userIdLineEdit.text()
            if idaStr == "":
                self.showMessageBox("ID不能为空")
                return
            ida = np.frombuffer(idaStr.encode("utf-8"), dtype=np.uint8)

            plainTextHex = self.plainHexTextLineEdit.text()
            if plainTextHex == "":
                self.showMessageBox("签名原文不能为空")
                return
            plainText = binascii.a2b_hex(plainTextHex)
            pu8Msg = np.frombuffer(plainText, dtype=np.uint8)

            HStr = self.calcFirstTextEdit.toPlainText()
            if HStr == "":
                self.showMessageBox("H 不能为空")
                return
            elif len(HStr) != 64:
                self.showMessageBox("H 长度错误，应为 32 字节")
                return
            pu8H = np.frombuffer(binascii.a2b_hex(HStr), dtype=np.uint8)

            SStr = deleteNewlines(self.calcSecondTextEdit.toPlainText())
            if SStr == "":
                self.showMessageBox("S 不能为空")
                return
            elif len(SStr) != 128:
                self.showMessageBox("S 长度错误，应为 64 字节")
                return
            pu8S = np.frombuffer(binascii.a2b_hex(SStr), dtype=np.uint8)

            ret = SM9.SM9_VerifyWrap(pu8Ppubs, ida, pu8Msg, pu8H, pu8S)
            if ret != 0:
                self.showMessageBox("验签失败！")
                return
            else:
                self.showMessageBox("验签成功！")
                return
        except binascii.Error as e:
            errStr = e.args[0] + "\n主公钥或签名原文或 H 或 S 转换 Hex 字符串失败!"
            self.showMessageBox(errStr)
            return
        except UnicodeEncodeError as e:
            errStr = e.args[0] + "\nuserId 或者签名原文输入的字符不支持!"
            self.showMessageBox(errStr)
            return

    def encrypt(self):
        try:
            ppubeStrHex = deleteNewlines(
                self.masterPublicKeyTextEdit.toPlainText()
            )
            if ppubeStrHex != "" and len(ppubeStrHex) == 128:
                pu8Ppube = np.frombuffer(
                    binascii.a2b_hex(ppubeStrHex), dtype=np.uint8
                )
            else:
                self.showMessageBox("主公钥输入错误")
                return

            idbStr = self.userIdLineEdit.text()
            if idbStr == "":
                self.showMessageBox("ID不能为空")
                return
            idb = np.frombuffer(idbStr.encode("utf-8"), dtype=np.uint8)

            plainTextHex = self.plainHexTextLineEdit.text()
            if plainTextHex == "":
                self.showMessageBox("加密原文不能为空")
                return
            plainText = binascii.a2b_hex(plainTextHex)
            pu8Msg = np.frombuffer(plainText, dtype=np.uint8)

            cipherLen = 64 + SM3_HMAC_SIZE + pu8Msg.size
            pu8Cipher = np.zeros(cipherLen, dtype=np.uint8)
            ret = SM9.SM9_EncryptWrap(pu8Ppube, idb, pu8Msg, pu8Cipher)
            if ret != 0:
                self.showMessageBox("加密失败!")
                return

            self.calcFirstTextEdit.setText(
                binascii.hexlify(pu8Cipher.tobytes()).decode("utf-8")
            )
        except binascii.Error as e:
            errStr = e.args[0] + "\n主公钥或加密原文转换 Hex 字符串失败!"
            self.showMessageBox(errStr)
            return
        except UnicodeEncodeError as e:
            errStr = e.args[0] + "\nuserId 或者加密原文输入的字符不支持!"
            self.showMessageBox(errStr)
            return

    def decrypt(self):
        try:
            deBStrHex = deleteNewlines(
                self.userPrivateKeyTextEdit.toPlainText()
            )
            if deBStrHex != "" and len(deBStrHex) == 256:
                pu8deB = np.frombuffer(
                    binascii.a2b_hex(deBStrHex), dtype=np.uint8
                )
            else:
                self.showMessageBox("加密私钥输入错误")
                return
            pass

            cipherTextHex = self.calcFirstTextEdit.toPlainText()
            if cipherTextHex == "":
                self.showMessageBox("密文不能为空")
                return
            cipherText = binascii.a2b_hex(cipherTextHex)
            pu8Cipher = np.frombuffer(cipherText, dtype=np.uint8)

            idbStr = self.userIdLineEdit.text()
            if idbStr == "":
                self.showMessageBox("ID不能为空")
                return
            idb = np.frombuffer(idbStr.encode("utf-8"), dtype=np.uint8)

            deMsgLen = len(cipherText) - 64 - SM3_HMAC_SIZE
            if deMsgLen <= 0:
                self.showMessageBox("密文长度错误, 密文长度应大于 96 字节")
                return
            pu8DeMsg = np.zeros(deMsgLen, dtype=np.uint8)
            ret = SM9.SM9_DecryptWrap(pu8deB, idb, pu8Cipher, pu8DeMsg)
            DeMsgStrHex = binascii.hexlify(pu8DeMsg.tobytes()).decode("utf-8")
            if ret != 0:
                self.showMessageBox("解密失败!")
                print(
                    "error code is {}\nDeMsgStr:{}\n".format(ret, DeMsgStrHex)
                )
                return
            else:
                self.calcSecondTextEdit.setText(DeMsgStrHex)
                self.showMessageBox("解密成功!")
                return
        except binascii.Error as e:
            errStr = e.args[0] + "\n加密私钥或密文转换 Hex 字符串失败!"
            self.showMessageBox(errStr)
            return
        except UnicodeEncodeError as e:
            errStr = e.args[0] + "\nuserId 输入的字符不支持!"
            self.showMessageBox(errStr)
            return
        except ValueError as e:
            errStr = e.args[0] + "\n密文长度错误!"
            self.showMessageBox(errStr)
            return

    def encap(self):
        try:
            ppubeStrHex = deleteNewlines(
                self.masterPublicKeyTextEdit.toPlainText()
            )
            if ppubeStrHex != "" and len(ppubeStrHex) == 128:
                pu8Ppube = np.frombuffer(
                    binascii.a2b_hex(ppubeStrHex), dtype=np.uint8
                )
            else:
                self.showMessageBox("主公钥输入错误")
                return

            idbStr = self.userIdLineEdit.text()
            if idbStr == "":
                self.showMessageBox("ID不能为空")
                return
            idb = np.frombuffer(idbStr.encode("utf-8"), dtype=np.uint8)

            keyLen = self.keyLengthLineEdit.text()
            if keyLen == "":
                self.showMessageBox("KEY长度不能为空")
                return
            elif keyLen.isdigit() is False:
                self.showMessageBox("KEY长度必须为数字")
                return
            keyLen = int(keyLen)

            pu8C = np.zeros(64, dtype=np.uint8)
            pu8K = np.zeros(keyLen, dtype=np.uint8)
            ret = SM9.SM9_Key_encapWrap(pu8Ppube, idb, pu8C, pu8K)
            if ret != 0:
                self.showMessageBox("密钥封装失败!")
                return

            CHex = binascii.hexlify(pu8C.tobytes()).decode("utf-8")
            KHex = binascii.hexlify(pu8K.tobytes()).decode("utf-8")
            self.CTextEdit.setText(insertNewlines(CHex, 64))
            self.keyOriginTextEdit.setText(KHex)
        except binascii.Error as e:
            errStr = e.args[0] + "\n主公钥转换 Hex 字符串失败!"
            self.showMessageBox(errStr)
            return
        except UnicodeEncodeError as e:
            errStr = e.args[0] + "\nuserId 输入的字符不支持!"
            self.showMessageBox(errStr)
            return

    def decap(self):
        try:
            deBStrHex = deleteNewlines(
                self.userPrivateKeyTextEdit.toPlainText()
            )
            if deBStrHex != "" and len(deBStrHex) == 256:
                pu8deB = np.frombuffer(
                    binascii.a2b_hex(deBStrHex), dtype=np.uint8
                )
            else:
                self.showMessageBox("加密私钥输入错误")
                return

            idbStr = self.userIdLineEdit.text()
            if idbStr == "":
                self.showMessageBox("ID不能为空")
                return
            idb = np.frombuffer(idbStr.encode("utf-8"), dtype=np.uint8)

            CHex = deleteNewlines(self.CTextEdit.toPlainText())
            if CHex == "":
                self.showMessageBox("C不能为空")
                return
            elif len(CHex) != 128:
                self.showMessageBox("C长度错误，应为 64 字节")
                return
            pu8C = np.frombuffer(binascii.a2b_hex(CHex), dtype=np.uint8)

            keyLen = self.keyLengthLineEdit.text()
            if keyLen == "":
                self.showMessageBox("KEY长度不能为空")
                return
            elif keyLen.isdigit() is False:
                self.showMessageBox("KEY长度必须为数字")
                return
            keyLen = int(keyLen)

            pu8KDecap = np.zeros(keyLen, dtype=np.uint8)
            ret = SM9.SM9_Key_decapWrap(idb, pu8deB, pu8C, pu8KDecap)
            MStr = binascii.hexlify(pu8KDecap.tobytes()).decode("utf-8")
            if ret != 0:
                self.showMessageBox("密钥解封失败!")
                print("error code is {} \nMStr: {}\n".format(ret, MStr))
                return
            else:
                self.MLineEdit.setText(MStr)
                self.showMessageBox("密钥解封成功!")
                return
        except binascii.Error as e:
            errStr = e.args[0] + "\n加密私钥或 C 转换 Hex 字符串失败!"
            self.showMessageBox(errStr)
            return
        except UnicodeEncodeError as e:
            errStr = e.args[0] + "\nuserId 输入的字符不支持!"
            self.showMessageBox(errStr)
            return

    def plainHexTextShow(self):
        plainText = self.plainTextLineEdit.text()
        try:
            hexText = binascii.hexlify(plainText.encode("utf-8")).decode(
                "utf-8"
            )
            self.plainHexTextLineEdit.setText(hexText)
        except binascii.Error:
            return
        except UnicodeEncodeError as e:
            errStr = e.args[0] + "\n原文输入的字符不支持!"
            self.showMessageBox(errStr)

    def showMessageBox(self, message):
        msgBox = QMessageBox()
        msgBox.setWindowTitle("提示")
        msgBox.setText(message)
        msgBox.setIcon(QMessageBox.Icon.Warning)
        msgBox.setStandardButtons(QMessageBox.StandardButton.Ok)
        msgBox.exec()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    tabWidget = QTabWidget()
    tabWidget.setSizePolicy(
        QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred
    )
    tabWidget.addTab(CommonWidget(type=SM9WidgetType.SignVerify), "签名/验签")
    tabWidget.addTab(CommonWidget(type=SM9WidgetType.EncryptDecrypt), "加解密")
    tabWidget.addTab(CommonWidget(type=SM9WidgetType.KeyEncapDecap), "密钥封装")
    tabWidget.resize(800, 400)
    tabWidget.show()
    tabWidget.setWindowTitle("SM9 算法验证工具")
    sys.exit(app.exec())
