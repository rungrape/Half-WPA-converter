from binascii import a2b_hex, b2a_hex

def payloadParser(r):
    tup = []
    i = 0
    while i < len(r):
        t = int.from_bytes(r[i: i + 2], byteorder='big')
        x = r[i + 2: i + 2 + t]
        print(len(x))
        print(x)
        tup.append(x)
        i += t + 2
    return tup


def payloadConstructor(tup):
    r = b''
    for i in tup:
        print(type(i))
        print(i)
        print(type(r))
        r += int.to_bytes(len(i), 2, byteorder='big') + i
    return r

class etherInstance:
    """Instance for connection establishment"""


    def enumWLIntefaces(self):
        """Enumerate all acceptable wireless interfaces"""
        command = "iwconfig"
        from subprocess import Popen, PIPE
        pipe = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
        while True:
            line = pipe.stdout.readline()
            line = line.decode('utf-8')
            if line:
                from re import split
                if '802.11' in line:
                    interface = split(r'\s+IEEE\s+802\.11', line)[0]
                    print(interface)
                    break
            else:
                break


    def sendeth(self, src, dst, eth_type, payload):
        """Send raw Ethernet packet on interface."""
        assert(len(src) == len(dst) == 6)
        assert(len(eth_type) == 2)
        # --
        from socket import socket, AF_PACKET, SOCK_RAW
        s = socket(AF_PACKET, SOCK_RAW)
        s.bind((self.interface, 0))
        # --
        print('!!!!!!!!!!!')
        print(len(payload))
        if len(payload) > 1500:
            i = 0
            while i*1500 < len(payload):
                s.send(src + dst + eth_type + payload[i*1500: (i+1)*1500])
                i += 1
        else:
            print(len(src + dst + eth_type + payload))
            s.send(src + dst + eth_type + payload)

    def recveth(self):
        """Recieve Ethernet packet on interface"""
        import socket
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(3))
        s.bind((self.interface, 0))
        while True:
            buffsize = 30000
            pkt = s.recvfrom(buffsize)
            fr = pkt[0]
            frame = frameInst(fr)
            break
        print(len(frame.payload))
        return frame.payload

        """
        from socket import socket, AF_NETLINK, SOCK_DGRAM
        s = socket(AF_NETLINK, SOCK_DGRAM)
        s.bind((self.interface, 0))
        # --
        buffsize = 34  # mac src + mac dst + ethtype + len + payload + crc32
        print(self.interface)
        buff = s.recv(buffsize)
        frame = frameInst(buff)
        return frame.payload"""


    def __init__(self, i):
        self.interface = i

class frameInst:

    def checkCrc(self, payload, crc):
        from binascii import crc32
        checksum = crc32(payload).to_bytes(4, byteorder='big')
        if crc != checksum:
            return 0, checksum
        else:
            return 1, checksum

    def parse(self, input):
        print(len(input))
        print(input)
        padding = 6
        s = input[0:6]
        d = input[6:12]
        e = input[12:14]
        p = input[14:]
        return s, d, e, p

    def __init__(self, input):
        self.src,\
        self.dst,\
        self.ethver,\
        self.payload = self.parse(input)


def parse(input):
        """s = input[0:6]
        d = input[6:12]
        e = input[12:14]"""
        p = input[14:]
        return p

from binascii import a2b_hex, b2a_hex

class mainProto:
    """
    Client class instance
    """
    def MakeAB(self, aNonce, sNonce, apMac, cliMac):
        A = b"Pairwise key expansion"
        B = min(apMac, cliMac) + max(apMac, cliMac) + min(aNonce, sNonce) + max(aNonce, sNonce)
        return (A, B)

    def PRF(self, key, A, B):
        # Number of bytes in the PTK
        nByte = 64
        i = 0
        R = b''
        # Each iteration produces 160-bit value and 512 bits are required
        while (i <= ((nByte * 8 + 159) / 160)):
            """hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
            R = R + hmacsha1.digest()
            i += 1"""
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes, hmac
            h = hmac.HMAC(key, hashes.SHA1(), backend=default_backend())
            h.update(A + chr(0x00).encode() + B + chr(i).encode())
            # --------------
            R = R + h.finalize()
            i += 1
        return R[0:nByte]

    def KDF(self, a, b, c, d):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.backends import default_backend
        backend = default_backend()
        info = b"hkdf-example"
        hkdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=d,
            salt=b,
            iterations=c,
            backend=default_backend()
        )
        hkdf = hkdf.derive(a)
        return hkdf

    def MakeMIC(self, A, B, data, wpa=False):
        pmk = self.KDF(self.password.encode('ascii'), self.ssid.encode('ascii'), 4096, 32)
        ptk = self.PRF(pmk, A, B)
        print('ETERXEG ' + str((pmk, ptk)))
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, hmac
        h = hmac.HMAC(ptk[0:16], hashes.SHA1(), backend=default_backend())
        h.update(data)
        mic = h.finalize()
        return (mic, ptk, pmk)

    def __init__(self, p):
        self.password = p
        self.ssid = "Harkonen"
        self.apMac = a2b_hex("00146c7e4080")
        self.cliMac = a2b_hex("001346fe320c")

    def step1(self):
        aNonce = b'\x22\x58\x54\xb0\x44\x4d\xe3\xaf\x06\xd1\x49\x2b\x85\x29\x84\xf0\x4c\xf6\x27\x4c\x0e\x32\x18\xb8\x68\x17\x56\x86\x4d\xb7\xa0\x55'
        payload = payloadConstructor((aNonce,))
        return payload
    
    def step2(self):
        aNonce = b'\x22\x58\x54\xb0\x44\x4d\xe3\xaf\x06\xd1\x49\x2b\x85\x29\x84\xf0\x4c\xf6\x27\x4c\x0e\x32\x18\xb8\x68\x17\x56\x86\x4d\xb7\xa0\x55'
        e = etherInstance('enp0s3')
        fr = e.recveth()
        pay = payloadParser(fr)
        print(pay)
        sNonce = pay[1]
        mic1 = pay[2]
        data1 = pay[0]
        A, B = self.MakeAB(aNonce, sNonce, self.apMac, self.cliMac)
        mic, ptk, pmk = self.MakeMIC(A, B, data1)
        mic = mic[:-4]
        print('MIC: ' + str(mic))
        if mic == mic1:
            return (True, aNonce, sNonce)
        else:
            return (False,)

    def step3(self, aNonce, sNonce):
        data2 = a2b_hex(
            "010300970213ca00100000000000000002225854b0444de3af06d1492b852984f04cf6274c0e3218b8681756864db7a055192eeef7fd968ec80aee3dfb875e8222370000000000000000000000000000000000000000000000000000000000000000383ca9185462eca4ab7ff51cd3a3e6179a8391f5ad824c9e09763794c680902ad3bf0703452fbb7c1f5f1ee9f5bbd388ae559e78d27e6b121f")
        A, B = self.MakeAB(aNonce, sNonce, self.apMac, self.cliMac)
        mic2 = self.MakeMIC(A, B, data2)[0][:-4]
        print('mic2: ' + str(mic2))
        payload = payloadConstructor((data2, mic2))
        return payload


    def mainCycle(self):
        """
        Main cycle of auth proto
        :return:
        """
        payload = self.step1()

        src_addr = b"\x0a\x00\x27\x00\x00\x00"
        dst_addr = b"\x08\x00\x27\x30\x30\x54"
        ethertype = b"\x08\x01"
        e = etherInstance('enp0s3')
        e.sendeth(src_addr, dst_addr, ethertype, payload)
        # ----------------------
        r = self.step2()
        if r[0] == False:
            print('Message integrity code is not correct!')
            return
        payload = self.step3(r[1], r[2])
        e.sendeth(src_addr, dst_addr, ethertype, payload)
        # ----------------------
        r = self.step2()
        if r[0] == False:
            print('Message integrity code is not correct!')
            return


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from random import randint


def test1():
    src_addr = b"\x01\x02\x03\x04\x05\x06"
    dst_addr = b"\x08\x00\x27\x30\x30\x54"
    payload = ("[" * 1500).encode('utf-8')
    ethertype = b"\x08\x01"

    e = etherInstance('enp0s3')
    e.sendeth(src_addr, dst_addr, ethertype, payload)

def test2():
    mp = mainProto("12345678")
    mp.mainCycle()



if __name__ == "__main__":
    import time
    s = time.time()
    test2()
    e = time.time()
    print(e - s)
