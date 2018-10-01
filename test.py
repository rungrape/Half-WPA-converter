
class FMT:

    def __init__(self, N, t, k):
        self.i = 0
        self.plc,\
        self.sk = self.init(N, t, k)
        print(self.plc)

    def op_pars(self):
        return (self.retNodeTuple(), self.i)

    def Hash(self, value):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        digest = hashes.Hash(
            hashes.SHA1(),
            backend=default_backend())
        digest.update(value)
        return digest.finalize()

    def LKG(self, X, i, j, k):
        return ((i + 1) * X + (j+1)) % (1 << k)

    def genSK(self, k):
        from random import randint
        SK = randint(1, 2 ** k)
        return SK

    def gensk(self, SK, k, i, t):
        sk = [self.LKG(int.from_bytes(SK, byteorder='big'), i, 0, k).to_bytes(int(k/8), byteorder='big')]
        for j in range(0, t):
            sk.append(self.Hash(self.LKG(int.from_bytes(sk[j-1], byteorder='big'), i, j, k).to_bytes(int(k/8), byteorder='big')))
        return sk

    def genpk(self, sk):
        pk = []
        for i in range(0, len(sk)):
            pk.append(self.Hash(sk[i]))
        return pk


    def genFMT(self, plc):
        plc_next = []
        for i in range(0,int(len(plc)/2)):
            c = bytearray(plc[i*2])
            c.extend(plc[i*2+1])
            plc_next.append(self.Hash(bytes(c)))
        if not(len(plc_next) == 1):
            ret = self.genFMT(plc_next)
            return (plc, ret)
        else:
            return (plc, plc_next)

    def init(self, N, t, k):
        plc = []
        sk = []
        SK = self.genSK(k).to_bytes(int(k/8)+1, byteorder='big')
        for i in range(0, N):
            pkk = 0
            sk.append(self.gensk(SK, k, i, t))
            pk = (self.genpk(sk[i]))
            for j in range(0, t):
                if j != 0:
                    pkk.extend(pk[j])
                else:
                    pkk = bytearray(pk[0])
            plc.append(self.Hash(bytes(pkk)))
        root = self.genFMT(plc)
        return root, sk

    def retN0(self, k):
        n = 0
        for i in range(1, 160):
            c = int(k / (1 << i)) % 2
            if not c:
                n += 1
        return n

    def sign(self, md):
        sk = self.sk[self.i]
        m_ = bytearray(md)
        m_.append(self.retN0(int.from_bytes(md, byteorder='big')))
        plc = sk[0:160-self.retN0(int.from_bytes(m_, byteorder='big'))]
        plc.extend(self.genpk(sk[160-self.retN0(int.from_bytes(m_, byteorder='big')):160]))
        signature = bytearray(plc[0])
        for i in range(1, 160):
            signature.extend(plc[i])
        return signature

    def verify(self, signature, md):
        m_ = bytearray(md)
        m_.append(self.retN0(int.from_bytes(md, byteorder='big')))
        sk = []
        for i in range(0, 160 - self.retN0(int.from_bytes(m_, byteorder='big'))):
            sk.append(bytes(signature[i * 20: i * 20 + 20]))
        pk = self.genpk(sk)
        plc_ = bytearray(pk[0])
        for i in range(1, 160 - self.retN0(int.from_bytes(m_, byteorder='big'))):
            plc_.extend(pk[i])
        plc_.extend(signature[20 * (160 - self.retN0(int.from_bytes(m_, byteorder='big'))): len(signature)])
        res = self.checkFMT(self.plc, self.i, self.Hash(bytes(plc_)), 0)
        self.i += 1
        return res

    def retNodeTuple(self):
        r = b''
        I = self.plc
        b = 1
        while b:
            for i in I:
                if str(type(i)) != "<class 'tuple'>":
                    for j in i:
                        r += j
                    if len(i) == 1:
                        b = 0
                else:
                    I = i
                    break
        return r



    def checkFMT(self, tree, i, value, j):
        if len(tree) == 1:
            if tree[0] == value:
                return 1
            else:
                return 0
        if i % 2 == 0:
            node = bytearray(value)
            node.extend(tree[0][i+1])
        else:
            node = bytearray(tree[0][i-1])
            node.extend(value)
        k = int(i/2)
        i += 1
        node = self.Hash(bytes(node))
        r = self.checkFMT(tree[1], k, node, i)
        return r

def payloadConstructor(tup):
    r = b''
    for i in tup:
        if str(type(i)) == "<class 'bytearray'>":
            i = bytes(i)
        if str(type(i)) == "<class 'int'>":
            i = int.to_bytes(i, 2, byteorder='big')
        r += int.to_bytes(len(i), 2, byteorder='big') + i
    return r

def payloadParser(r):
    print(bytes(r))
    tup = []
    i = 0
    while i < len(r):
        t = int.from_bytes(r[i: i + 2], byteorder='big')
        tup.append(r[i + 2: i + 2 + t])
        print(tup)
        print(len(tup[-1]))
        i += t + 2
    return tup


class grs:

    def __init__(self, a, x0, T):
        self.a = a
        self.T = T
        self.x0 = x0

    def gen(self):
        a = bin(self.a)[2:]
        x0 = bin(self.x0)[2:]
        if len(a) > len(x0):
            x0 = x0 + '0'*(len(a) - len(x0))
        i = 0
        while i != self.T:
            t = x0[i: i+len(a)]
            r = int(a, 2) & int(t, 2)
            from collections import Counter
            c = Counter(str(bin(r)[2:]))
            x0 = int(x0, 2) << 1
            i += 1
            if c['1'] % 2:
                x0 += 1
            x0 = bin(x0)[2:]
        res = x0[len(bin(self.a)[2:]):]
        return res

    def check(self, x):
        r = int(self.gen(), 2).to_bytes(14, byteorder='big')
        res = 1 if x == r else 0
        return res


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


class mainProto:
    """
    Access point class instance
    """

    def __init__(self, p):
        self.password = p

    def mainCycle(self):
        """
        Main cycle of auth proto
        :return:
        """
        b, m = self.step1()
        if b:
            self.step2(m)

    def KDF(self, s_dt):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.backends import default_backend
        backend = default_backend()
        info = b"hkdf-example"
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=s_dt,
            info=info,
            backend=backend
        )
        hkdf = hkdf.derive(self.password.encode('utf-8'))
        return hkdf

    def decrypt(self, m, k):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        backend = default_backend()
        print('--------------------')
        print(k)
        print(type(k))
        cipher = Cipher(algorithms.AES(k), modes.ECB(), backend=backend)
        decryptor = cipher.decryptor()
        ct = decryptor.update(m) + decryptor.finalize()
        return ct

    def step1(self):
        """
        First step of auth proto
        :return:
        """
        e = etherInstance('enp0s3')
        fr = e.recveth()
        pay = payloadParser(fr)
        print(pay)
        m = pay[0]
        s_dt = pay[1]
        k = self.KDF(s_dt)
        ct = self.decrypt(m, k)
        print(ct)
        a = ct[-1]
        print(type(a))
        o = ct[-2]
        x = ct[:-2]
        T = a
        g = grs(a, o, 8 * len(x))
        result = g.check(x)
        return result, k

    def step2(self, m):
        """
        Second step of auth proto
        :return:
        """
        inito = FMT(16, 160, 160)
        signature = inito.sign(m)
        # result = inito.verify(signature, m)
        # print('res is:' + str(result))
        dst_addr = b"\x08\x00\x27\x30\x30\x54"
        src_addr = b"\x0a\x00\x27\x00\x00\x00"
        t1 = inito.op_pars()
        t2 = (m, signature)
        t3 = t1 + t2
        print('----------------------------------')
        print(m)
        print('----------------------------------')
        print(signature)
        print('----------------------------------')
        print(t1[0])
        print('----------------------------------')
        print(t1[1])

        payload = payloadConstructor(inito.op_pars() + (m, signature))

        ethertype = b"\x08\x01"

        e = etherInstance('enp0s3')
        e.sendeth(src_addr, dst_addr, ethertype, payload)



def test1():
  e = etherInstance('enp0s3')
  fr = e.recveth()
  pay = payloadParser(fr)


def test2():
    mp = mainProto("password")
    mp.mainCycle()

def test3():
    inito = FMT(16, 160, 160)
    inito.retNodeTuple()

def test4():
    dst_addr = b"\x08\x00\x27\x30\x30\x54"
    src_addr = b"\x0a\x00\x27\x00\x00\x00"
    payload = ("[" * 1500).encode('utf-8')
    ethertype = b"\x08\x01"
    e = etherInstance('enp0s3')
    e.sendeth(src_addr, dst_addr, ethertype, payload)

if __name__ == "__main__":
    test2()
