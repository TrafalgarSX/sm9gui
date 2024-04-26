import SM9
import numpy as np
import binascii

SM3_HMAC_SIZE = 32


def test_sm9GenMasterSignKey():
    pu8Ks = np.zeros(32, dtype=np.uint8)
    pu8Ppubs = np.zeros(128, dtype=np.uint8)
    ret = SM9.SM9_GenMasterSignKeyWrap(pu8Ks, pu8Ppubs)
    print("result is {}".format(ret))
    print("size is {}, pu8Ks is {}".format(pu8Ks.size, pu8Ks))
    print("size is {}, pu8Ppubs is {}".format(pu8Ppubs.size, pu8Ppubs))
    print("\n")

    print("pu8Ks hex is {}".format(binascii.hexlify(pu8Ks.tobytes()).decode()))
    print(
        "pu8Ppubs hex is {}".format(
            binascii.hexlify(pu8Ppubs.tobytes()).decode()
        )
    )

    pu8dsA = np.zeros(64, dtype=np.uint8)
    ida = np.frombuffer("Alice".encode("utf-8"), dtype=np.uint8)
    ret = SM9.SM9_GenerateSignKeyWrap(pu8Ks, ida, pu8dsA)
    print("result is {}".format(ret))
    print("size is {}, pu8dsA is {}".format(pu8dsA.size, pu8dsA))


def test_sm9GenMasterSignKeyStd():
    pu8KsBytes = binascii.a2b_hex(
        "44e7d2e602c93640e31a9586e522dd7c811221a8c41a37c72016681aee0d7548"
    )
    pu8PpubsBytes = binascii.a2b_hex(
        "aa2796b161ebcc55486698913a64ca0fbbb88e4726ed8eb262c02447620402345c51c04b3ed2b72a50ce27f1d2253917991386c9854b72f9bb3f76eb4aa316d032fd98cdd1d707bca8cf5e24e3de90df3da278d6386fc31216d06fd32872e16b54fd215c6969cec1709b23babc6d15a8edfcbde5814a75a8a92ce705a415bdf7"
    )
    pu8Ks = np.frombuffer(pu8KsBytes, dtype=np.uint8)
    pu8Ppubs = np.zeros(128, dtype=np.uint8)
    ret = SM9.SM9_GenMasterSignKeyWrap(pu8Ks, pu8Ppubs)
    print("result is {}".format(ret))
    compareResult = pu8PpubsBytes == pu8Ppubs.tobytes()
    print("compareResult is {}".format(compareResult))


def test_sm9GenMasterEncKey():
    pu8Ke = np.zeros(32, dtype=np.uint8)
    pu8Ppube = np.zeros(64, dtype=np.uint8)
    ret = SM9.SM9_GenMasterEncKeyWrap(pu8Ke, pu8Ppube)
    print("result is {}".format(ret))
    print("size is {}, pu8Ke is {}".format(pu8Ke.size, pu8Ke))
    print("size is {}, pu8Ppube is {}".format(pu8Ppube.size, pu8Ppube))
    print("pu8Ks hex is {}".format(binascii.hexlify(pu8Ke.tobytes()).decode()))
    print(
        "pu8Ppubs hex is {}".format(
            binascii.hexlify(pu8Ppube.tobytes()).decode()
        )
    )

    pu8deB = np.zeros(128, dtype=np.uint8)
    idb = np.frombuffer("Bob".encode("utf-8"), dtype=np.uint8)
    ret = SM9.SM9_GenerateEncKeyWrap(pu8Ke, idb, pu8deB)
    print("result is {}".format(ret))
    print("size is {}, pu8dsB is {}".format(pu8deB.size, pu8deB))


def test_sm9GenMasterEncKeyStd():
    pu8KeBytes = binascii.a2b_hex(
        "713aa5b9dbbdae195c2614ffd9a965ef15800062d5a3c2821e3afbd4ee4ad19c"
    )
    pu8PpubeBytes = binascii.a2b_hex(
        "45bba57f8efce283303a486f4263e15c5347db0d2c55ff86f0191c116ae1baa40b373c8218c5b8ded7a2284ab2caaa6dff74c1a71e0c432193440f0a5a508226"
    )
    pu8Ke = np.frombuffer(pu8KeBytes, dtype=np.uint8)
    pu8Ppube = np.zeros(64, dtype=np.uint8)
    ret = SM9.SM9_GenMasterEncKeyWrap(pu8Ke, pu8Ppube)
    print("result is {}".format(ret))
    compareResult = pu8PpubeBytes == pu8Ppube.tobytes()
    print("compareResult is {}".format(compareResult))


def test_sign_verify():
    pu8Ks = np.zeros(32, dtype=np.uint8)
    pu8Ppubs = np.zeros(128, dtype=np.uint8)
    ret = SM9.SM9_GenMasterSignKeyWrap(pu8Ks, pu8Ppubs)
    print("result is {}".format(ret))
    print("\n")
    print("pu8Ks hex is {}".format(binascii.hexlify(pu8Ks.tobytes()).decode()))
    print(
        "pu8Ppubs hex is {}".format(
            binascii.hexlify(pu8Ppubs.tobytes()).decode()
        )
    )

    pu8dsA = np.zeros(64, dtype=np.uint8)
    ida = np.frombuffer("Alice".encode("utf-8"), dtype=np.uint8)
    ret = SM9.SM9_GenerateSignKeyWrap(pu8Ks, ida, pu8dsA)
    print("result is {}".format(ret))

    pu8Msg = np.frombuffer("hello world".encode("utf-8"), dtype=np.uint8)
    pu8H = np.zeros(32, dtype=np.uint8)
    pu8S = np.zeros(64, dtype=np.uint8)
    ret = SM9.SM9_SignWrap(pu8Ppubs, pu8dsA, pu8Msg, pu8H, pu8S)
    print("result is {}".format(ret))
    ret = SM9.SM9_VerifyWrap(pu8Ppubs, ida, pu8Msg, pu8H, pu8S)
    print("result is {}".format(ret))


def test_enc_dec():
    pu8Ke = np.zeros(32, dtype=np.uint8)
    pu8Ppube = np.zeros(64, dtype=np.uint8)
    ret = SM9.SM9_GenMasterEncKeyWrap(pu8Ke, pu8Ppube)
    print("result is {}".format(ret))
    print("pu8Ks hex is {}".format(binascii.hexlify(pu8Ke.tobytes()).decode()))
    print(
        "pu8Ppubs hex is {}".format(
            binascii.hexlify(pu8Ppube.tobytes()).decode()
        )
    )

    pu8deB = np.zeros(128, dtype=np.uint8)
    idb = np.frombuffer("Bob".encode("utf-8"), dtype=np.uint8)
    ret = SM9.SM9_GenerateEncKeyWrap(pu8Ke, idb, pu8deB)
    print("result is {}".format(ret))

    stdtext = "Chinese IBE standard"
    pu8Msg = np.frombuffer(stdtext.encode("utf-8"), dtype=np.uint8)

    cipherLen = 64 + SM3_HMAC_SIZE + len(stdtext)
    pu8Cipher = np.zeros(cipherLen, dtype=np.uint8)
    ret = SM9.SM9_EncryptWrap(pu8Ppube, idb, pu8Msg, pu8Cipher)
    print("result is {}".format(ret))
    pu8DeMsg = np.zeros(len(stdtext), dtype=np.uint8)
    ret = SM9.SM9_DecryptWrap(pu8deB, idb, pu8Cipher, pu8DeMsg)
    print("result is {}".format(ret))
    deMsgStr = pu8DeMsg.tobytes().decode("utf-8")
    print("pu8M is :{}".format(deMsgStr))

    compareResult = np.equal(pu8Msg, pu8DeMsg)
    print("compareResult is {}".format(compareResult))


def test_encap_decap():
    pu8Ke = np.zeros(32, dtype=np.uint8)
    pu8Ppube = np.zeros(64, dtype=np.uint8)
    ret = SM9.SM9_GenMasterEncKeyWrap(pu8Ke, pu8Ppube)
    print("result is {}".format(ret))
    print("pu8Ks hex is {}".format(binascii.hexlify(pu8Ke.tobytes()).decode()))
    print(
        "pu8Ppubs hex is {}".format(
            binascii.hexlify(pu8Ppube.tobytes()).decode()
        )
    )

    pu8deB = np.zeros(128, dtype=np.uint8)
    idb = np.frombuffer("Bob".encode("utf-8"), dtype=np.uint8)
    ret = SM9.SM9_GenerateEncKeyWrap(pu8Ke, idb, pu8deB)
    print("result is {}".format(ret))

    KLen = 32
    pu8C = np.zeros(64, dtype=np.uint8)
    pu8K = np.zeros(KLen, dtype=np.uint8)
    ret = SM9.SM9_Key_encapWrap(pu8Ppube, idb, pu8C, pu8K)
    print("result is {}".format(ret))
    pu8KDecap = np.zeros(KLen, dtype=np.uint8)
    ret = SM9.SM9_Key_decapWrap(idb, pu8deB, pu8C, pu8KDecap)
    print("result is {}".format(ret))

    # compareResult = np.equal(pu8K, pu8KDecap)
    # print("compareResult is {}".format(compareResult))
    compareResult = pu8K == pu8KDecap
    print("compareResult is {}".format(compareResult))


def testCPPParm():
    s = "test"
    (first, s) = SM9.testStringRef(s)
    print("first is {}, second is {}".format(first, s))

    print("s is {}".format(s))


def testCPPVectorParam():
    vector = SM9.IntVector(10)
    for i in range(10):
        vector[i] = i

    ret = SM9.testVectorRef(vector)
    print("ret is {}".format(ret))
    print("vector size is {}".format(vector.size()))

    for i in range(vector.size()):
        print("vector[{}] is {}".format(i, vector[i]))


if __name__ == "__main__":
    # test_sm9GenMasterSignKey()
    # test_sm9GenMasterEncKey()
    # test_sign_verify()
    # test_enc_dec()
    # test_encap_decap()
    # test_sm9GenMasterSignKeyStd()
    # test_sm9GenMasterEncKeyStd()

    # testCPPParm()
    testCPPVectorParam()
