import sys, os, math, json, time, random
import M2Crypto

global id
id = 0

class CoffeePacket(object):
    id = 0
    time = 0
    success = False
    action = ""
    data = {}
    
    def __init__(self):
        self.time = time.time()
        return

    def __repr__(self):
        return "<CoffeePacket(id:'%s', time:'%s', success:'%s', action:'%s')>" %(self.id, self.time, self.success, self.action)

    def build(self):
        global id
        id += 1
        self.id = id
        f = {'id':self.id, 'time':self.time, 'rand':random.randint(1000, 9999), 'success':self.success, 'action':self.action, 'data':self.data}
        return f

class CoffeeRequest(CoffeePacket):
    mifareid = 0
    cardid = 0

    def __init__(self, mifareid = 0, cardid = 0):
        CoffeePacket.__init__(self)
        self.mifareid = mifareid
        self.cardid = cardid
        return

    def __repr__(self):
        return CoffeePacket.__repr__(self) + "\n  ^- " + "<CoffeeRequest(mifareid:'%s', cardid:'%s')>" % (self.mifareid, self.cardid)

    def build(self):
        s = CoffeePacket.build(self)
        o = {'mifareid':self.mifareid, 'cardid':self.cardid}
        return dict(s.items() + o.items())

    def compile(self, privateKeyFile):
        crypto = M2Crypto.RSA.load_key(privateKeyFile)

        if crypto == None:
            raise Exception("No private crypto")

        packet = json.dumps(self.build())
        msgDigest = M2Crypto.EVP.MessageDigest ('sha1')
        msgDigest.update(packet)
        hash = msgDigest.digest()
        
        signature = crypto.sign_rsassa_pss(hash).encode('base64')
        return {"packet":packet, "signature":signature}

class CoffeeResponse(CoffeePacket):
    def __init__(self):
        CoffeePacket.__init__(self)
        return

    def __repr__(self):
        return CoffeePacket.__repr__(self) + "\n  ^- " + "<CoffeeResponse()>"

    def build(self):
        s = CoffeePacket.build(self)
        o = {}
        return dict(s.items() + o.items())

    def compile(self):
        return json.dumps(self.build())

class CoffeeProtocol(object):
    def __init__(self):
        return

    def buildRequest(self, mifareid, cardid):
        return CoffeeRequest(mifareid, cardid)

    def buildResponse(self):
        return CoffeeResponse()

    def parseRequest(self, req, publicKeyFile):
        VerifyRSA = M2Crypto.RSA.load_pub_key (publicKeyFile)
        msgDigest = M2Crypto.EVP.MessageDigest ('sha1')
        msgDigest.update(req['packet'])
        hash = msgDigest.digest()
        if VerifyRSA.verify_rsassa_pss (hash, req['signature'].decode("base64")) != 1:
            return None
        
        r = None
        try:
            packet = json.loads(req['packet'])
            r = CoffeeRequest()
            for key in packet:
                setattr(r, key, packet[key])
        except:
            return None

        return r

    def parseResponse(self, resp):
        r = None
        try:
            packet = resp
            r = CoffeeResponse()
            
            for key in packet:
                setattr(r, key, packet[key])
        except:
            return None

        return r

def test():
    p = CoffeeProtocol()

    r1 = p.buildRequest(1, 61)
    r2 = p.buildRequest(2, 62)
    r3 = p.buildRequest(3, 63)

    r3c = r3.compile('private.pem')
    r3n = p.parseRequest(r3c, 'public.pem')
    print r3
    print r3c
    print r3n
