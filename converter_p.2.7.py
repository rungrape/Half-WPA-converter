from pcapParser import load_savefile
import binascii


essid_cache = {}


def from_bytes(data, big_endian = False):
    if isinstance(data, str):
        data = bytearray(data)
    if big_endian:
        data = reversed(data)
    num = 0
    for offset, byte in enumerate(data):
        num += byte << (offset * 8)
    return num


def find_essid(bssid, pack):
    '''
    :param bssid: bssid of AP, which essid we wanna find
    :param pack: packet dump, which we've catched
    :return: if essid corresponding to bssid were not found yet, but has already been found now / 0, if there is no essid corresponding to bssid / 1 if essid corresponding to to bssid has already been found
    '''
    i = 0
    try:
        found = essid_cache[from_bytes(bssid, big_endian=True)]
        return 1
    except KeyError:
        t = 0
    while t == 0:
        try:
            if binascii.unhexlify(pack[i][1].packet)[0:2] == b'\x80\x00':
                if binascii.unhexlify(pack[i][1].packet)[10:16] == bssid:
                    essid_len = ord(binascii.unhexlify(pack[i][1].packet)[37])
                    essid = binascii.unhexlify(pack[i][1].packet)[38:38 + essid_len]
                    essid_cache.update({from_bytes(bssid, big_endian=True): essid})
                    return essid
            i += 1
        except IndexError:
            break

    return 0


def find_bssid(essid, pack):
    '''

    :param essid: essid of AP, which bssid we wanna find
    :param pack: packet dump, which we've catched
    :return: essid
    '''
    i = 0
    while True:
        try:
            if binascii.unhexlify(pack[i][1].packet)[0:2] == b'\x80\x00':
                essid_len = binascii.unhexlify(pack[i][1].packet)[37]
                if binascii.unhexlify(pack[i][1].packet)[38:38 + from_bytes(essid_len, big_endian=True)] == essid:
                    bssid = binascii.unhexlify(pack[i][1].packet)[10:16]
                    return bssid
            i += 1
        except IndexError:
            break

    return 0


def write_cap_hccap(essid, pack, ff):
    bssid = pack[0][10:16]
    cmac = (pack[0])[4:10]
    snonce = (pack[1])[51:83]
    anonce = (pack[0])[51:83]
    a1 = pack[1][34]
    a2 = pack[1][35]
    a3 = (pack[1])[36:38]
    a4 = pack[1][38]
    a5 = (pack[1])[39:41]
    a6 = (pack[1])[41:43]
    a8 = (pack[1])[43:51]
    a9 = (pack[1])[51:83]
    a10 = (pack[1])[83:99]
    a11 = (pack[1])[99:107]
    a12 = (pack[1])[107:115]
    a13 = (pack[1])[131:133]
    a14 = (pack[1])[133:133 + int(a13.encode('hex'), 16) + 1]
    eapol = a1 + a2 + a3 + a4 + a5 + a6 + a8 + a9 + a10 + a11 + a12 + (b'\x00' * 16) + a13 + a14
    mic = (pack[1])[115:131]
    # ----------------------------------------------
    if type(essid) is str:
        hccap = bytearray(essid.encode('ascii'))
    elif type(essid) is bytes:
        hccap = bytearray(essid)
    elif type(essid) is bytearray:
        hccap = essid
    hccap.extend(b'\x00' * (36 - len(essid)))
    hccap.extend(bssid)
    hccap.extend(cmac)
    hccap.extend(snonce)
    hccap.extend(anonce)
    hccap.extend(eapol)
    hccap.extend(b'\x00' * (256 - len(eapol)))
    import struct
    hccap.extend(struct.pack('<I', len(eapol)))
    hccap.extend(b'\x02\x00\x00\x00')
    hccap.extend(mic)
    # --------------------------
    ff.write(hccap)
    print("file " + ff.name + " has been created")


def write_cap_hccapx(essid, pack, ff):
    signature = b'\x48\x43\x50\x58'
    version = b'\x04\x00\x00\x00'
    message_pair = b'\x00'
    import struct
    essid_len = struct.pack('>I', len(essid))
    i = 0
    while True:
        if essid_len[i] != b'\x00':
            essid_len = essid_len[i:]
            break
        i += 1
    keyver = b'\x02'  # !!!!!!!!!!!!
    mic = (pack[1])[115:131]
    bssid = (pack[0])[10:16]
    cmac = (pack[0])[4:10]
    snonce = (pack[1])[51:83]
    anonce = (pack[0])[51:83]

    a1 = pack[1][34]#struct.pack('>I', (pack[1])[34])
    a2 = pack[1][35]#struct.pack('>I', (pack[1])[35])
    a3 = (pack[1])[36:38]
    a4 = pack[1][38]#struct.pack('>I', (pack[1])[38])
    a5 = (pack[1])[39:41]
    a6 = (pack[1])[41:43]
    a8 = (pack[1])[43:51]
    a9 = (pack[1])[51:83]
    a10 = (pack[1])[83:99]
    a11 = (pack[1])[99:107]
    a12 = (pack[1])[107:115]
    a13 = (pack[1])[131:133]
    a14 = (pack[1])[133:133 + from_bytes(a13, big_endian=True) + 1]
    eapol = a1 + a2 + a3 + a4 + a5 + a6 + a8 + a9 + a10 + a11 + a12 + (b'\x00' * 16) + a13 + a14
    # ----------------------------------------------
    hccapx = bytearray(signature)
    hccapx.extend(version)
    hccapx.extend(message_pair)
    hccapx.extend(essid_len)
    if type(essid) is str:
        hccapx.extend(essid.encode('ascii'))
    elif type(essid) is bytes:
        hccapx.extend(bytearray(essid))
    elif type(essid) is bytes or type(essid) is bytearray:
        hccapx.extend(essid)
    hccapx.extend(b'\x00' * (32 - len(essid)))
    hccapx.extend(keyver)
    hccapx.extend(mic)
    hccapx.extend(bssid)
    hccapx.extend(anonce)
    hccapx.extend(cmac)
    hccapx.extend(snonce)
    eapol_len = struct.pack('<I', len(eapol))[0:2]
    hccapx.extend(eapol_len)
    hccapx.extend(eapol)
    hccapx.extend(b'\x00' * (256 - len(eapol)))
    hccapx_ = hccapx
    hccapx.extend(hccapx_)
    # --------------------------
    ff.write(hccapx)
    print("file " + ff.name + " has been created")


def hccap_hccapx(f):
    pack = f.read()
    essid = bytes(pack[0:32])
    signature = b'\x48\x43\x50\x58'
    version = b'\x04\x00\x00\x00'
    message_pair = b'\x00'
    essid_len = 0
    while essid[essid_len] != b'\x00':
        essid_len += 1
    import struct
    essid_len = struct.pack('>I', essid_len)
    i = 0
    while True:
        if essid_len[i] != b'\x00':
            essid_len = essid_len[i:]
            break
        i += 1
    #essid_len = int.to_bytes(essid_len, 1, byteorder='big')
    bssid = pack[36:42]
    cmac = pack[42:48]
    snonce = pack[48:80]
    anonce = pack[80:112]
    eapol = pack[112:368]
    eapol_len = pack[368:370]
    keyver = pack[372]
    #keyver = int.to_bytes(pack[372], 1, byteorder='big')
    mic = pack[376:]
    # ----------------------------------------------
    hccapx = bytearray(signature)
    hccapx.extend(version)
    hccapx.extend(message_pair)
    hccapx.extend(essid_len)
    hccapx.extend(essid)
    hccapx.extend(keyver)
    hccapx.extend(mic)
    hccapx.extend(bssid)
    hccapx.extend(anonce)
    hccapx.extend(cmac)
    hccapx.extend(snonce)
    hccapx.extend(eapol_len)
    hccapx.extend(eapol)
    hccapx_ = hccapx
    hccapx.extend(hccapx_)
    # --------------------------
    from time import time
    f_out = "handshake_" + essid[0:from_bytes(essid_len, big_endian=True)].decode('ascii') + "_" + str(time()) + ".hccapx"
    fff = open(f_out, 'wb')
    fff.write(hccapx)
    print("file " + fff.name + " has been created")
    fff.close()


def cap_hccap(essid, f):
    caps, header = load_savefile(f)

    packets = caps.packets
    if type(essid) is str:
        essid = bytearray(essid.encode('ascii'))
        bssid = find_bssid(essid, packets)
        i = 0
        while True:
            try:
                if binascii.unhexlify(packets[i][1].packet)[32:34] == b'\x88\x8e' and binascii.unhexlify(packets[i][1].packet)[39:41] == b'\x00\x8a':
                    if binascii.unhexlify(packets[i][1].packet)[10:16] == bssid:
                        break
                i += 1
            except IndexError:
                break
        j = i + 1
        while binascii.unhexlify(packets[j][1].packet)[32:34] != b'\x88\x8e':
            j += 1
        from time import time
        f_out = "handshake_" + essid.decode('ascii') + "_" + str(time()) + ".hccap"
        fff = open(f_out, 'wb')
        write_cap_hccap(essid, [binascii.unhexlify(packets[i][1].packet), binascii.unhexlify(packets[j][1].packet)], fff)
        fff.close()


    elif type(essid) is int:
        i = 0
        while True:
            try:
                if binascii.unhexlify(packets[i][1].packet)[32:34] == b'\x88\x8e' and binascii.unhexlify(packets[i][1].packet)[39:41] == b'\x00\x8a':
                    bssid = bytearray(binascii.unhexlify(packets[i][1].packet)[10:16])
                    essid = find_essid(bssid, packets)
                    if essid != 0 and essid != 1:
                        j = i + 1
                        while binascii.unhexlify(packets[j][1].packet)[32:34] != b'\x88\x8e':
                            j += 1
                        from time import time
                        f_out = "handshake_" + essid.decode('ascii') + "_" + str(time()) + ".hccap"
                        fff = open(f_out, 'wb')
                        write_cap_hccap(essid, [binascii.unhexlify(packets[i][1].packet), binascii.unhexlify(packets[j][1].packet)], fff)
                        fff.close()
                    elif essid == 0:
                        print("essid for bssid " + str(bssid) + " not found\n")
                i += 1
            except IndexError:
                break


def cap_hccapx(essid, f):
    caps, header = load_savefile(f)
    packets = caps.packets
    if type(essid) is str:
        essid = bytearray(essid.encode('ascii'))
        bssid = find_bssid(essid, packets)
        i = 0
        while True:
            try:
                if binascii.unhexlify(packets[i][1].packet)[32:34] == b'\x88\x8e' and binascii.unhexlify(packets[i][1].packet)[39:41] == b'\x00\x8a':
                    if binascii.unhexlify(packets[i][1].packet)[10:16] == bssid:
                        break
                i += 1
            except IndexError:
                break
        j = i + 1
        while binascii.unhexlify(packets[j][1].packet)[32:34] != b'\x88\x8e':
            j += 1
        from time import time
        f_out = "handshake_" + essid.decode('ascii') + "_" + str(time()) + ".hccapx"
        fff = open(f_out, 'wb')
        write_cap_hccapx(essid, [binascii.unhexlify(packets[i][1].packet), binascii.unhexlify(packets[j][1].packet)], fff)
        fff.close()

    elif type(essid) is int:
        i = 0
        while True:
            try:
                if binascii.unhexlify(packets[i][1].packet)[32:34] == b'\x88\x8e' and binascii.unhexlify(packets[i][1].packet)[39:41] == b'\x00\x8a':
                    bssid = bytearray(binascii.unhexlify(packets[i][1].packet)[10:16])
                    essid = find_essid(bssid, packets)
                    if essid != 0 and essid != 1:
                        j = i + 1
                        while binascii.unhexlify(packets[j][1].packet)[32:34] != b'\x88\x8e':
                            j += 1
                        from time import time
                        f_out = "handshake_" + essid.decode('ascii') + "_" + str(time()) + ".hccapx"
                        fff = open(f_out, 'wb')
                        write_cap_hccapx(essid, [binascii.unhexlify(packets[i][1].packet), binascii.unhexlify(packets[j][1].packet)], fff)
                        fff.close()
                    elif essid == 0:
                        print("essid for bssid " + str(bssid) + " not found\n")
                i += 1
            except IndexError:
                break


def analyze_args(a1, a2):
    '''

    :param a1: the first command line arg
    :param a2: the second command line arg
    :return: return the behavior code: which convert function we are to launch
    '''
    if not(type(a1) is str and type(a2) is str):
        return -1

    from re import split
    a1_split = split(r'\.', a1)

    if (a1_split[-1] == a2) or (a1_split[1] == 'hccapx' and a2 == 'hccap') or (a1_split[-1] == 'hccapx' and a2 == 'cap') or (a1_split[-1] == 'hccap' and a2 == 'cap'):
        return -1
    elif a1_split[-1] == 'cap' and a2 == 'hccap':
        return 1
    elif a1_split[-1] == 'cap' and a2 == 'hccapx':
        return 2
    elif a1_split[-1] == 'hccap' and a2 == 'hccapx':
        return 3


'''essid = 0
f_in = "test-01.cap"
f = open(f_in, 'rb')
cap_hccapx(essid, f)
'''
if __name__ == "__main__":
    from sys import argv, exit
    temp = argv[1:]
    if not(len(argv) == 2 or len(argv) == 3 or len(argv) == 4):
        print("bad args. the correct format is:\nconverter.py inputfile outputformat\nor:\nconverter.py inputfile outputformat essid\nexamples:\nconverter.py dump.cap hccapx\nconverter.py dump.cap hccap ESSID\nconverter.py dump.hccap hccapx")
        exit(-1)
    import getopt

    try:
        opts, args = getopt.getopt(argv, "h:")
        for opt in args:
            if opt == '-h':
                print("the correct format is:\n----------------------------------------\n\tconverter.py inputfile outputformat\n----------------------------------------\nor:\n----------------------------------------\n\tconverter.py inputfile outputformat essid\n\nexamples:\n----------------------------------------\n\tconverter.py dump.cap hccapx\n\tconverter.py dump.cap hccap ESSID\n\tconverter.py dump.hccap hccapx\n----------------------------------------\n")
                exit(-1)

    except getopt.GetoptError:
        t = 1

    if not(len(argv) == 3 or len(argv) == 4):
        print("the correct format is:\n----------------------------------------\n\tconverter.py inputfile outputformat\n----------------------------------------\nor:\n----------------------------------------\n\tconverter.py inputfile outputformat essid\n\nexamples:\n----------------------------------------\n\tconverter.py dump.cap hccapx\n\tconverter.py dump.cap hccap ESSID\n\tconverter.py dump.hccap hccapx\n----------------------------------------\n")
        exit(-1)

    ans = analyze_args(argv[1], argv[2])

    if ans == -1:
        print("the correct format is:\n----------------------------------------\n\tconverter.py inputfile outputformat\n----------------------------------------\nor:\n----------------------------------------\n\tconverter.py inputfile outputformat essid\n\nexamples:\n----------------------------------------\n\tconverter.py dump.cap hccapx\n\tconverter.py dump.cap hccap ESSID\n\tconverter.py dump.hccap hccapx\n----------------------------------------\n")
        exit(-1)
    else:

        if ans == 1:
            f_in = argv[1]
            f = open(f_in, 'rb')
            try:
                essid = argv[3]
                cap_hccap(essid, f)
            except IndexError:
                cap_hccap(0, f)

            f.close()

        elif ans == 2:
            f_in = argv[1]
            f = open(f_in, 'rb')
            try:
                essid = argv[3]
                cap_hccapx(essid, f)
            except IndexError:
                cap_hccapx(0, f)

            f.close()

        elif ans == 3:
            f_in = argv[1]
            f = open(f_in, 'rb')
            hccap_hccapx(f)
            f.close()
