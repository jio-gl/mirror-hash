'''
Created on Apr 26, 2018

@author: Jose I. Orlicki 

MIT License

Class Interface based on Pure Python SHA256 by Tom Dixon (https://github.com/thomdixon/pysha2)
'''

import random, sys, struct
import binascii

def new(m=None):
    return mirror256(m)

# IEEE 754 representation in hex, without heading byte.
def prime_to_cubic_root_hex(p):
    h = hex(long(str(int(p)**(1./3) - int(int(p)**(1./3) ))[2:]))
    while len(h) < 13:
        h = '0x' + '0' + h[2:]
    ret = [0]*8
    h = h[4:]
    for i in range(8):
        ret[i] = int(h[i],16)
    return ret

# IEEE 754 representation in hex, without heading byte.
def cubic_root_array(cr):
    h = hex(cr)
    if h[-1] != 'L':
        h += 'L'
    while len(h) < 13:
        h = '0x' + '0' + h[2:]
    ret = [0]*8
    h = h[4:]
    for i in range(8):
        ret[i] = int(h[i],16)
    return ret


class mirror256(object):
    '''
    Mirror256 Hash Function, Provable Reversible (Biyective) for Hashes.
    '''

    DEFAULT_DEPTH = 128 #1 #16
    DEFAULT_SIZE  = 256 #8 # 256
    GATES = [0, 1]#['Toffoli','Fredkin']

    lastHashes = []
    
    firstPrimesCubicRootDecRep = [
            0xa54ddd35b5,    0xd48ef058b4,    0x342640f4c9,    0x51cd2de3e9,    0x8503094982,    0x9b9fd7c452,    0xc47a643e0c,    0xa8602fe35a,
            0x20eaf18d67,    0x4d59f727fe,    0x685bd4533f,    0x7534dcd163,    0x8dc0dcbb8b,    0xb01624cb6d,    0xcfeabbf181,    0xda0b94f97e,
            0x8f4d86d1a9,    0x20c96455af,    0x29c172f7dd,    0x43b770ba12,    0x544d18005f,    0x6c34f761a1,    0x8a76ef782f,    0x98f8d17ddc,
            0xa0151027c6,    0xae080d4b7b,    0xb4e03c992b,    0xc251542f88,    0x3dc28be52f,    0xb75c7e128f,    0x241edeb8f4,    0x04317d07b2,
            0x46305e3a3d,    0x4bafebecef,    0x09308a3b6b,    0x6bb275e451,    0x76044f4b33,    0x85311d5237,    0x94051aaeb0,    0x98e38ef4df,
            0xb0b5da348c,    0xb55fd044a0,    0xbe9b372069,    0xc32ceea80e,    0xddf799a193,    0x0eee44484b,    0x17529bf549,    0x1b7b53489d,
            0x23ba4d74a0,    0x2febef5a50,    0x33f0db9016,    0x47b5d89777,    0x5352304156,    0x5ec09f1622,    0x6a02e0a83b,    0x0af9027c88,
            0x78c3f873a6,    0x8009496a17,    0x83a5537ad2,    0x95715f4210,    0xadb0de7719,    0xb47bab87d1,    0xb7db7bc375,    0xbe90221e69,
            0xd599166861,    0xdf457a1ae2,    0x3f1c4f10f8,    0x5e7beeb45f,    0x0faff58d42,    0x18f53d76f5,    0x2528d4cd81,    0x2e31dbfd82,
            0x372236c49f,    0x3d0a65aa42,    0x45d30e2165,    0x516594b949,    0x571fef6fc3,    0x6277a55af4,    0x70708531b1,    0x73350c1f03,
            0x80ea6cfcaa,    0x83a1c53701,    0x8bbb0acdff,    0x9116bfdc91,    0x9910e9b48f,    0xa397b0d72f,    0xa8cf4c2583,    0xab68347813,
            0xb0944c2d01,    0xbfebc31b97,    0xca01c32639,    0xcf022b04f8,    0xd8ee4454de,    0xddda24f5e1,    0xe52f7f4ce3,    0x6c818c6507,
            0x8472d1b3d3,    0x2285f71052,    0x2982d70320,    0x350b7321b5,    0x3be615f828,    0x42b44ca815,    0x44f6508617,    0x4bb44d615e,
            0x56d68d1d1a,    0x5d7531014e,    0x64087059f4,    0x663705c553,    0x6cbb5fa88a,    0x7334c44133,    0x777fb210c9,    0x79a3612cf1,
            0x8660f49e64,    0x90df7d6e60,    0x92f570231e,    0x971e058f2c,    0x9d52b376f9,    0x10595e2a63,    0x108dc9904f,    0xb1bd0befac,
            0xb5c5d93981,    0xbbcb73733b,    0xc3c4f0aabb,    0xcda6c368f9,    0xd57d5a7e75,    0x16520c34cf,    0xe6e99f4c26,    0x264192d75e,
            0x0989bc2dbf,    0x854a9cfefb,    0xd0b522f906,    0x1a7dec746c,    0x1e390b5485,    0x25a54a9675,    0x295679bf9b,    0x36292b3477,
            0x3f3a2ff04a,    0x4a01ec61b3,    0x4bcb38937b,    0x54ae80966c,    0x567356a419,    0x59fad0877c,    0x5bbd75dfd9,    0x647fe2621c,
            0x0b43c0fed1,    0x7417c16475,    0x75cfd5a597,    0x793df2a072,    0x852a251c4d,    0x888c3a9c35,    0x8a3c49c1d7,    0x8d9a740155,
            0x9e4ad6fa74,    0xa199c2f506,    0xa830325a9d,    0xb05e889d91,    0xb6df352e6e,    0xba1bfe44ed,    0xbef2c774d8,    0xc3c457f223,
            0xceeea9021f,    0xd21a4009ac,    0xd6d77766f3,    0xdb8fb9c68d,    0xe1d31d3112,    0x024e147bb9,    0x45a4041059,    0x64758e789a,
            0x9289050518,    0xa1da8c8b5d,    0x17d09378c9,    0x1955aee1bf,    0x1de1ffd3b5,    0x03be0f8051,    0x26ed40ba60,    0x2e69348875,
            0x2fe6f31384,    0x345d51384a,    0x41a6fa9d42,    0x06dbc790ea,    0x460c840ae7,    0x48f8964fb7,    0x4d574ac9d0,    0x51b1f28f29,
            0x5779eb0acf,    0x5bcb43e3ef,    0x099c117651,    0x6fbe24810d,    0x0b50c60b1c,    0x78317578e7,    0x7dcb6a4081,    0x84c2b49cc0,
            0x88ebda33b6,    0x8d116a7403,    0x92934fbcac,    0x9aca7688f4,    0x9d846e148d,    0xa19884c4e2,    0xa5a932ae5e,    0xa70356989f,
            0xab0f83d1a6,    0xb31ddc0413,    0xb9ca6990bf,    0xc5b725f629,    0xc70890fc30,    0xc9aa5942eb,    0xcd9a66bed0,    0xcee9b9403a,
            0xd2d59e0287,    0xd5712927f2,    0xd6be6b65d1,    0xd957ea5633,    0x1682d445b9,    0xe266839b86,    0xe6432f6b31,    0xbefe814019,
            0xe4daf84b08,    0x1aa91c8b09,    0x1fad4b5ea5,    0x2ae4ae18c5,    0x311543795e,    0x39b322532e,    0x3c26b944eb,    0x0623353793,
            0x3fd1e9b51c,    0x06bf72cb7c,    0x485734706d,    0x0779fc0a08,    0x4bf9bce29f,    0x4f99b6704c,    0x56d20ebfb1,    0x5cceae69c5,
            0x5e0060a5bc,    0x09a37ea0f6,    0x09c1fb669e,    0x63f4c00913,    0x67841bdf2d,    0x6e9b8e7208,    0x75a96ad747,    0x7a580f92e2,
            0x815638c600,    0x84d1d2bb80,    0x8722f21b88,    0x0ddc45b53b,    0x0e5249fa19,    0x9183779dc3,    0x9619a1c10c,    0x98633a3308,
            0xa05d13a173,    0xa2a244e832,    0xa6083edd92,    0xa729c1a4ba,    0xa96c0f26ed,    0xaccdb931ed,    0xadedcd8549,    0xb14c9f2e14,
            0xb6e5f3a401,    0xc20731b710,    0xc5597e3e50,    0xc78f393564,    0xc8a9bfd2e9,    0xd5d696d008,    0xd8059fd29c,    0xd91cd0017a,
            0xde8d7a1929,    0xe50d858cc9,    0x17036935a4,    0x1aec0ae713,    0x45e3ca4534,    0x660781d922,    0x86186845e1,    0xa61698fe32,
            0x1a29cbf7ec,    0x1d556fe9a3,    0x1f71850a35,    0x207f423e17,    0x26cd7c6f71,    0x2c0934f621,    0x324a60b5fa,    0x3671ecd976,
            0x3eb7c32011,    0x06fde2cc3f,    0x48fdedbf9b,    0x4b09b48cbb,    0x4c0f504b01,    0x4e19f8e3b3,    0x4f1f05e96c,    0x543581a053,
            0x5a4a6ecb10,    0x5d52709977,    0x6058d22656,    0x69624ae937,    0x6a6274cc37,    0x725d6e8b91,    0x735c04408f,    0x7e4108faa8,
            0x8136134ae4,    0x852515fe57,    0x88169247f5,    0x8a0c0e2855,    0x8b068bd109,    0x8cfb06eeda,    0x90e1fe58d2,    0x017a5ff39d,
            0x98a801a35a,    0x99a0055314,    0x0195a8132a,    0xa5338fb1e6,    0xa9ff8dcbd6,    0xacde7217b2,    0x11dbff6f0b,    0xb38baf623a,
            0x1225102d5c,    0xb665df3dca,    0xbb23bfe0ab,    0xc0cf52f722,    0xc1c0b7cc65,    0xc946683c84,    0xca36706d10,    0xcd05a29fc3,
            0xcee45a0bae,    0xcfd37c85a4,    0xd47ceeeda1,    0xd83508683f,    0xe08ab2aaa6,    0x1b87647d28,    0x2dda8c56df,    0x494caa6138,
            0x6dd118371b,    0xb696d24ebb,    0x132a8748ad,    0xd1ca109288,    0x18991c243f,    0x1fcf8d4fbe,    0x20b5bee829,    0x03735f6de3,
            0x26181342db,    0x28c76d7f23,    0x2b75943d65,    0x2d3e593c24,    0x32957bc0ac,    0x3378e0de19,    0x3d359bacf5,    0x3fdab8cfce,
            0x40bc2b4f35,    0x435fbdd0af,    0x45217bcbb2,    0x47c32428ac,    0x4de2934638,    0x508071b007,    0x523e65b3ed,    0x531d2fc459,
            0x55b8ceb8aa,    0x5775446fe3,    0x5a0f0783ae,    0x5f3f3b06f8,    0x61d5add070,    0x646b082d20,    0x6a6df44b67,    0x6c24903d20,
            0x6eb59463a6,    0x73d465a770,    0x773be86b4b,    0x79c84e2a0d,    0x7b7aa6a329,    0x0d7241927c,    0x0e33c9bf1f,    0x9235147a66,
            0x958c0279de,    0x0f1f1482af,    0x0f5f03d7db,    0x9a8b0b2052,    0x9d090e7cb7,    0xa623ef6a66,    0xab15bd8361,    0xabe853dd2c,
            0xb27923f3b4,    0xb5bef88516,    0xb7613eea45,    0xbc4585df81,    0xc1f5b69e0e,    0xc602b56a25,    0xc6d1cb9c0c,    0xc86fa84d57,
            0xcbaa23d3dd,    0xce14eb6297,    0xd07ec66ccb,    0xd21a2ad247,    0xd2e7b5d3fb,    0x15403fc313,    0xd6e9e63d10,    0xda1d06f27b,
            0xdbb5fc65c8,    0xdc82508207,    0xdee6b2c233,    0xe2e156cb42,    0xe3acc4b9a2,    0xe7a46db595,    0xc5dd77cea1,    0x23993428ed,
            0x5ad1e7218a,    0x822660524d,    0xb138b07a6f,    0xb90db66620,    0x0215d4958f,    0xe0287c9248,    0xe7f7c7f5a3,    0x1d6e6678ad,
            0x22ddf91d8b,    0x03a445b593,    0x26bd2634f2,    0x29d46b0213,    0x2c24e6115f,    0x2daf6cd5e9,    0x349a42059d,    0x37aaed0245,
            0x3b7db9947b,    0x3dc7ec72bd,    0x401150af07,    0x431c9620f6,    0x46e8acac4d,    0x4b7443145f,    0x50bdc8dd4d,    0x523fb8293b,
            0x5481f82f11,    0x56c3708024,    0x5783c1ad36,    0x61ff2de4b7,    0x62be364c7e,    0x66781af577,    0x6971b3493b,    0x6aedfe4ec7,
            0x0b363d0311,    0x71992c5698,    0x748dc1f8da,    0x0c19040500,    0x7b2f3f404c,    0x7f9738554a,    0x810e8f4692,    0x01500275b5,
            0x8a8e636ca2,    0x8e3218c29e,    0x8eec330714,    0x94ba2a6b76,    0x9e1e1f2dfb,    0x9f8eca6514,    0xa047023427,    0xa496b1302a,
            0xa6bd7e4503,    0xa82c4f5d6d,    0xac76eca6d9,    0xae9b33edd7,    0xb1752dbd79,    0xb2e1b67b93,    0xb5b9e07146,    0xbd86255ed6,
            0x1305eaf449,    0xbfa504ee55,    0xc059d42fbf,    0x13a8837ac6,    0xce6a96d830,    0xcf1ddc8595,    0xd1373e6d63,    0xd34ffa08ea,
            0xd5680fd896,    0xd6cd17db96,    0xd8e41a7335,    0xd9964c12f8,    0xddc1f7139e,    0xdf25495fb8,    0xe34d8e2da9,    0x16ccab2fb3,
            0xe7734adce1,    0xe82400e6f0,    0x303963efab,    0x371a3d8fe0,    0x6e082d995d,    0x82960dc05e,    0xc6ed3a4969,    0x1957402b09,
            0x1c0eff5a25,    0x1d6a77e9dd,    0x1e181a7e96,    0x1f732c56da,    0x20209ba2d1,    0x2790016836,    0x2a422ac9ee,    0x2e4b709dee,
            0x304f318deb,    0x33a97b2627,    0x3454f19d58,    0x35abacd166,    0x37ad4989ae,    0x38585cc02f,    0x3a5933869c,    0x3daea6332c,
            0x3e592594a7,    0x4256cb12f0,    0x45a86b1961,    0x070837213d,    0x49a1e217ee,    0x4e4210f6f1,    0x503ca2a6e6,    0x518e095e0c,
            0x5387ac1ebc,    0x5628fc56f2,    0x5821526d06,    0x5a191a9805,    0x5f55d2d75f,    0x09ece14bdf,    0x63e7c03a2e,    0x6535783b8f,
                        ]
    
    def __init__(self, m=None, depth=None, size=None, useStandardState=True):
        '''
        Constructor
        '''
        self._buffer = ''
        self._counter = 0
                
        if not depth:
            self.depth = self.DEFAULT_DEPTH
        if not size:
            self.size = self.DEFAULT_SIZE
        if len(self.lastHashes) < self.depth:
            if useStandardState:
                self.initStandardState()
            else:
                self.initLastHashes()
            
        if m is not None:
            if type(m) is not str:
                raise TypeError('%s() argument 1 must be string, not %s' % (self.__class__.__name__, type(m).__name__))
            self.update(m)
        
        
    def unpack(self, m):
        ret = [0]*64
        l = struct.unpack('!32b', m.encode())
        i = 0
        for b in l:
            # high nibble
            ret[i] = b >> 4
            i += 1
            # low nibble
            ret[i] = b & 0x0F
            i += 1
        return ret


    def pack(self, hm):
        hb = [0] * (self.size // 8)
        for i in range(self.size // 8):
            if i * 2 < len(hm):
                b = hm[i * 2] << 4
                if i * 2 + 1 < len(hm):
                    b = b | hm[i * 2 + 1]
                hb[i] = b
        return struct.pack(f'!{self.size // 8}B', *hb)
    
    def digest(self):
        return self.pack(self._hashed)
    
    def hexdigest(self):
        return '0x' + binascii.hexlify(self.digest()).decode('ascii')    
        
    def update(self, m):
        if not m:
            return
        if type(m) is not str:
            raise TypeError('%s() argument 1 must be string, not %s' % (sys._getframe().f_code.co_name, type(m).__name__))
        
        self._buffer += m
        self._counter += len(m)
        
        while len(self._buffer) >= 32:
            hm = self._mirror256_process(self._buffer[:32])
            self.lastHashes = [hm] + self.lastHashes[:self.depth]
            self._buffer = self._buffer[32:]
        if 0 < len(self._buffer) < 32  or m == '':
            hm = self._mirror256_process(self._buffer + 'A'*(32-len(self._buffer)))
            self._buffer = self._buffer[32:]
        self._hashed = hm

    # hex(long(str(5**(1./3) - int(5**(1./3) ))[2:]))
    def initStandardState(self):
        while len(self.lastHashes) < self.depth:
            i = len(self.lastHashes)
            layer = []
            for j in range(8*i,8*(i+1)):
                jprimerep = self.firstPrimesCubicRootDecRep[i]
                layer += cubic_root_array(jprimerep)
            self.lastHashes.append( layer )
        
            
    def initLastHashes(self):
        # TODO replace with fixed initial internal state, for example based on cubic roots of primes.
        random.seed(777)
        while len(self.lastHashes) < self.depth:
            oneRandomHash = self.randomHash()
            self.lastHashes.append(oneRandomHash)
        
        
    def randomHash(self):
        ret = [0]*(self.size/4)
        for i in range(self.size/4):
            newhex = random.randint(0,15) #hex(random.randint(0,15))[2]
            ret[i] = newhex
        return ret #'0x' + ret

    
    def _mirror256_process(self, m):
        m = self.unpack(m)
        for layer in range(self.depth):
            hm = self.hashLayerPass(layer, m)
        return hm

    
    def hashLayerPass(self, layer, block, startLeft=None):        
        #     Layer1 (a zigzag)
        # 1    ### @@@
        # 2    ###
        # 3    ### @@@
        # 4        @@@
        # 5    ### @@@
        # 6    ###
        # 7    ### @@@
        # 8        @@@        
        # Size must divisible by 8
        # Each 3-wire gate can be Toffoli or Fredkin, mirrored or not., 4 choices.
        
        # First a XOR with layer encoding to avoid 0 to 0 hashes.
        layerHash = self.lastHashes[layer]
        for gateIndex in range(int(self.size/4)):
            block[gateIndex] = block[gateIndex] ^ layerHash[gateIndex]
        
        for gateIndex in range(int(self.size/4)):
            gateType = layerHash[gateIndex] & 0x3 #int(layerHash[2:][gateIndex],16) & 0x3

            if gateType % 2 ==0: # Toffoli
                gateName = 0 #'Toffoli'
            else:
                gateName = 1 #'Fredkin'

            if gateType >> 1 == 0: # Toffoli
                gateSymmetry = 0 #'Regular'
            else:
                gateSymmetry = 1 #'Mirrored'
            
            ## do gate
            block = self.applyGate(gateIndex,gateName,gateSymmetry, block, firstSublayer=True, layer=layer)
            
        for gateIndex in range(int(self.size/4)):
            gateType = gateType = layerHash[gateIndex] & 0xc #int(layerHash[2:][gateIndex],16) & 0xc

            if ((gateType>>2) % 2) ==0: # Toffoli
                gateName = 0 #'Toffoli'
            else:
                gateName = 1 #'Fredkin'

            if ((gateType>>2) >> 1) == 0: # Toffoli
                gateSymmetry = 0 #'Regular'
            else:
                gateSymmetry = 1 #'Mirrored'
            
            ## do gate
            block = self.applyGate(gateIndex,gateName,gateSymmetry, block, firstSublayer=False, layer=layer)

        return block
    
    
    def getWire(self, gateIndex, firstSublayer, offset=0):
        return (gateIndex * 4 + offset + (not firstSublayer and 2 or 0 )) % self.size 

    def getBit(self, block, wire):
        return block[int(wire/4)] >> wire%4 & 1 

    def setBit(self, block, wire, bit):
        oldNib = block[int(wire/4)] #int(block[2:][wire/4],16)
        ret = (oldNib & (15^(1 << wire%4)))
        ret = ret | (int(bit) << wire%4)  
        #ret = hex(ret)[2:]
        #block = block[:2 + wire/4] + ret +  block[2 + wire/4 + 1:] 
        block[wire//4] = ret  
        return block
    
    def applyGate(self, gateIndex,gateName,gateSymmetry, block, firstSublayer=None, layer=None):
        #     Layer1 (a zigzag)
        # 1    ### @@@
        # 2    ###
        # 3    ### @@@
        # 4        @@@
        # 5    ### @@@
        # 6    ###
        # 7    ### @@@
        # 8        @@@        
        # Size must divisible by 8
        # Each 3-wire gate can be Toffoli or Fredkin, mirrored or not., 4 choices.
        initialOffset = layer%2
        wire1 = self.getWire(gateIndex, firstSublayer, offset=initialOffset+0)
        wire2 = self.getWire(gateIndex, firstSublayer, offset=initialOffset+1)
        wire3 = self.getWire(gateIndex, firstSublayer, offset=initialOffset+2)
        val1 = self.getBit(block, wire1)
        oval1 = val1
        val2 = self.getBit(block, wire2)
        oval2 = val2
        val3 = self.getBit(block, wire3)
        oval3 = val3
        
        # Toffoli and Regular
        if gateName == 0 and gateSymmetry == 0 and (val1 and val2):
            val3 = val3 ^ (val1 and val2)
        # Toffoli and Mirrored
        elif gateName == 0 and gateSymmetry == 1 and (val2 and val3):
            val1 = val1 ^ (val2 and val3)
        # Fredkin and Regular
        elif gateName == 1 and gateSymmetry == 0 and val1 and val2!=val3:
            #if val1:
            val2,val3 = val3,val2
        # Fredkin and Mirrored
        elif gateName == 1 and gateSymmetry == 1 and val3 and val1!=val2:
            #if val3:
            val1,val2 = val2,val1
                
        if val1 != oval1:
            block = self.setBit(block, wire1, val1)
        if val2 != oval2:
            block = self.setBit(block, wire2, val2)
        if val3 != oval3:
            block = self.setBit(block, wire3, val3)

        return block
    
    
def randomAlfanumericString(N):
    import string
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))
    
    
if __name__ == "__main__":
    random.seed(777)
    m='This is the canary.'
    print ('Message=',m)
    h = mirror256(m=m)
    import time
    t = time.time()
    c = 0
    for i in range(1024):
        digest = h.digest()
        print( i, h.hexdigest())
        randStr = randomAlfanumericString(N=32)
        #print len(randStr), randStr
        msg = 'This is the canary #%d. asdfasdfasdfasdfasdfqwerqwerqwerdfnnjkdfnjldljknsvv' % i
        h = mirror256( msg )
        c += 1
        if time.time() > t + 1:
            print ('%d hashes per seconds!' % c)
            print ('Example message = ', msg)
            print ('Example digest = ', h.hexdigest())
            print ('Example message =',randStr)
            print ('Example digest = ', mirror256(randStr).hexdigest())
            c = 0
            t = time.time()
