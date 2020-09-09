'''
Created on Apr 26, 2018

@author: Jose I. Orlicki 

MIT License

Class Interface based on Pure Python SHA256 by Tom Dixon (https://github.com/thomdixon/pysha2)
'''

import random, sys, struct

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

    DEFAULT_DEPTH = 64 #1 #16
    DEFAULT_SIZE  = 256 #8 # 256
    GATES = [0, 1]#['Toffoli','Fredkin']

    lastHashes = []
    
    firstPrimesCubicRootDecRep = [
            0xa54ddd35b5L,    0xd48ef058b4L,    0x342640f4c9L,    0x51cd2de3e9L,    0x8503094982L,    0x9b9fd7c452L,    0xc47a643e0cL,    0xa8602fe35aL,
            0x20eaf18d67L,    0x4d59f727feL,    0x685bd4533fL,    0x7534dcd163L,    0x8dc0dcbb8bL,    0xb01624cb6dL,    0xcfeabbf181L,    0xda0b94f97eL,
            0x8f4d86d1a9L,    0x20c96455afL,    0x29c172f7ddL,    0x43b770ba12L,    0x544d18005fL,    0x6c34f761a1L,    0x8a76ef782fL,    0x98f8d17ddcL,
            0xa0151027c6L,    0xae080d4b7bL,    0xb4e03c992bL,    0xc251542f88L,    0x3dc28be52fL,    0xb75c7e128fL,    0x241edeb8f4L,    0x04317d07b2L,
            0x46305e3a3dL,    0x4bafebecefL,    0x09308a3b6bL,    0x6bb275e451L,    0x76044f4b33L,    0x85311d5237L,    0x94051aaeb0L,    0x98e38ef4dfL,
            0xb0b5da348cL,    0xb55fd044a0L,    0xbe9b372069L,    0xc32ceea80eL,    0xddf799a193L,    0x0eee44484bL,    0x17529bf549L,    0x1b7b53489dL,
            0x23ba4d74a0L,    0x2febef5a50L,    0x33f0db9016L,    0x47b5d89777L,    0x5352304156L,    0x5ec09f1622L,    0x6a02e0a83bL,    0x0af9027c88L,
            0x78c3f873a6L,    0x8009496a17L,    0x83a5537ad2L,    0x95715f4210L,    0xadb0de7719L,    0xb47bab87d1L,    0xb7db7bc375L,    0xbe90221e69L,
            0xd599166861L,    0xdf457a1ae2L,    0x3f1c4f10f8L,    0x5e7beeb45fL,    0x0faff58d42L,    0x18f53d76f5L,    0x2528d4cd81L,    0x2e31dbfd82L,
            0x372236c49fL,    0x3d0a65aa42L,    0x45d30e2165L,    0x516594b949L,    0x571fef6fc3L,    0x6277a55af4L,    0x70708531b1L,    0x73350c1f03L,
            0x80ea6cfcaaL,    0x83a1c53701L,    0x8bbb0acdffL,    0x9116bfdc91L,    0x9910e9b48fL,    0xa397b0d72fL,    0xa8cf4c2583L,    0xab68347813L,
            0xb0944c2d01L,    0xbfebc31b97L,    0xca01c32639L,    0xcf022b04f8L,    0xd8ee4454deL,    0xddda24f5e1L,    0xe52f7f4ce3L,    0x6c818c6507L,
            0x8472d1b3d3L,    0x2285f71052L,    0x2982d70320L,    0x350b7321b5L,    0x3be615f828L,    0x42b44ca815L,    0x44f6508617L,    0x4bb44d615eL,
            0x56d68d1d1aL,    0x5d7531014eL,    0x64087059f4L,    0x663705c553L,    0x6cbb5fa88aL,    0x7334c44133L,    0x777fb210c9L,    0x79a3612cf1L,
            0x8660f49e64L,    0x90df7d6e60L,    0x92f570231eL,    0x971e058f2cL,    0x9d52b376f9L,    0x10595e2a63L,    0x108dc9904fL,    0xb1bd0befacL,
            0xb5c5d93981L,    0xbbcb73733bL,    0xc3c4f0aabbL,    0xcda6c368f9L,    0xd57d5a7e75L,    0x16520c34cfL,    0xe6e99f4c26L,    0x264192d75eL,
            0x0989bc2dbfL,    0x854a9cfefbL,    0xd0b522f906L,    0x1a7dec746cL,    0x1e390b5485L,    0x25a54a9675L,    0x295679bf9bL,    0x36292b3477L,
            0x3f3a2ff04aL,    0x4a01ec61b3L,    0x4bcb38937bL,    0x54ae80966cL,    0x567356a419L,    0x59fad0877cL,    0x5bbd75dfd9L,    0x647fe2621cL,
            0x0b43c0fed1L,    0x7417c16475L,    0x75cfd5a597L,    0x793df2a072L,    0x852a251c4dL,    0x888c3a9c35L,    0x8a3c49c1d7L,    0x8d9a740155L,
            0x9e4ad6fa74L,    0xa199c2f506L,    0xa830325a9dL,    0xb05e889d91L,    0xb6df352e6eL,    0xba1bfe44edL,    0xbef2c774d8L,    0xc3c457f223L,
            0xceeea9021fL,    0xd21a4009acL,    0xd6d77766f3L,    0xdb8fb9c68dL,    0xe1d31d3112L,    0x024e147bb9L,    0x45a4041059L,    0x64758e789aL,
            0x9289050518L,    0xa1da8c8b5dL,    0x17d09378c9L,    0x1955aee1bfL,    0x1de1ffd3b5L,    0x03be0f8051L,    0x26ed40ba60L,    0x2e69348875L,
            0x2fe6f31384L,    0x345d51384aL,    0x41a6fa9d42L,    0x06dbc790eaL,    0x460c840ae7L,    0x48f8964fb7L,    0x4d574ac9d0L,    0x51b1f28f29L,
            0x5779eb0acfL,    0x5bcb43e3efL,    0x099c117651L,    0x6fbe24810dL,    0x0b50c60b1cL,    0x78317578e7L,    0x7dcb6a4081L,    0x84c2b49cc0L,
            0x88ebda33b6L,    0x8d116a7403L,    0x92934fbcacL,    0x9aca7688f4L,    0x9d846e148dL,    0xa19884c4e2L,    0xa5a932ae5eL,    0xa70356989fL,
            0xab0f83d1a6L,    0xb31ddc0413L,    0xb9ca6990bfL,    0xc5b725f629L,    0xc70890fc30L,    0xc9aa5942ebL,    0xcd9a66bed0L,    0xcee9b9403aL,
            0xd2d59e0287L,    0xd5712927f2L,    0xd6be6b65d1L,    0xd957ea5633L,    0x1682d445b9L,    0xe266839b86L,    0xe6432f6b31L,    0xbefe814019L,
            0xe4daf84b08L,    0x1aa91c8b09L,    0x1fad4b5ea5L,    0x2ae4ae18c5L,    0x311543795eL,    0x39b322532eL,    0x3c26b944ebL,    0x0623353793L,
            0x3fd1e9b51cL,    0x06bf72cb7cL,    0x485734706dL,    0x0779fc0a08L,    0x4bf9bce29fL,    0x4f99b6704cL,    0x56d20ebfb1L,    0x5cceae69c5L,
            0x5e0060a5bcL,    0x09a37ea0f6L,    0x09c1fb669eL,    0x63f4c00913L,    0x67841bdf2dL,    0x6e9b8e7208L,    0x75a96ad747L,    0x7a580f92e2L,
            0x815638c600L,    0x84d1d2bb80L,    0x8722f21b88L,    0x0ddc45b53bL,    0x0e5249fa19L,    0x9183779dc3L,    0x9619a1c10cL,    0x98633a3308L,
            0xa05d13a173L,    0xa2a244e832L,    0xa6083edd92L,    0xa729c1a4baL,    0xa96c0f26edL,    0xaccdb931edL,    0xadedcd8549L,    0xb14c9f2e14L,
            0xb6e5f3a401L,    0xc20731b710L,    0xc5597e3e50L,    0xc78f393564L,    0xc8a9bfd2e9L,    0xd5d696d008L,    0xd8059fd29cL,    0xd91cd0017aL,
            0xde8d7a1929L,    0xe50d858cc9L,    0x17036935a4L,    0x1aec0ae713L,    0x45e3ca4534L,    0x660781d922L,    0x86186845e1L,    0xa61698fe32L,
            0x1a29cbf7ecL,    0x1d556fe9a3L,    0x1f71850a35L,    0x207f423e17L,    0x26cd7c6f71L,    0x2c0934f621L,    0x324a60b5faL,    0x3671ecd976L,
            0x3eb7c32011L,    0x06fde2cc3fL,    0x48fdedbf9bL,    0x4b09b48cbbL,    0x4c0f504b01L,    0x4e19f8e3b3L,    0x4f1f05e96cL,    0x543581a053L,
            0x5a4a6ecb10L,    0x5d52709977L,    0x6058d22656L,    0x69624ae937L,    0x6a6274cc37L,    0x725d6e8b91L,    0x735c04408fL,    0x7e4108faa8L,
            0x8136134ae4L,    0x852515fe57L,    0x88169247f5L,    0x8a0c0e2855L,    0x8b068bd109L,    0x8cfb06eedaL,    0x90e1fe58d2L,    0x017a5ff39dL,
            0x98a801a35aL,    0x99a0055314L,    0x0195a8132aL,    0xa5338fb1e6L,    0xa9ff8dcbd6L,    0xacde7217b2L,    0x11dbff6f0bL,    0xb38baf623aL,
            0x1225102d5cL,    0xb665df3dcaL,    0xbb23bfe0abL,    0xc0cf52f722L,    0xc1c0b7cc65L,    0xc946683c84L,    0xca36706d10L,    0xcd05a29fc3L,
            0xcee45a0baeL,    0xcfd37c85a4L,    0xd47ceeeda1L,    0xd83508683fL,    0xe08ab2aaa6L,    0x1b87647d28L,    0x2dda8c56dfL,    0x494caa6138L,
            0x6dd118371bL,    0xb696d24ebbL,    0x132a8748adL,    0xd1ca109288L,    0x18991c243fL,    0x1fcf8d4fbeL,    0x20b5bee829L,    0x03735f6de3L,
            0x26181342dbL,    0x28c76d7f23L,    0x2b75943d65L,    0x2d3e593c24L,    0x32957bc0acL,    0x3378e0de19L,    0x3d359bacf5L,    0x3fdab8cfceL,
            0x40bc2b4f35L,    0x435fbdd0afL,    0x45217bcbb2L,    0x47c32428acL,    0x4de2934638L,    0x508071b007L,    0x523e65b3edL,    0x531d2fc459L,
            0x55b8ceb8aaL,    0x5775446fe3L,    0x5a0f0783aeL,    0x5f3f3b06f8L,    0x61d5add070L,    0x646b082d20L,    0x6a6df44b67L,    0x6c24903d20L,
            0x6eb59463a6L,    0x73d465a770L,    0x773be86b4bL,    0x79c84e2a0dL,    0x7b7aa6a329L,    0x0d7241927cL,    0x0e33c9bf1fL,    0x9235147a66L,
            0x958c0279deL,    0x0f1f1482afL,    0x0f5f03d7dbL,    0x9a8b0b2052L,    0x9d090e7cb7L,    0xa623ef6a66L,    0xab15bd8361L,    0xabe853dd2cL,
            0xb27923f3b4L,    0xb5bef88516L,    0xb7613eea45L,    0xbc4585df81L,    0xc1f5b69e0eL,    0xc602b56a25L,    0xc6d1cb9c0cL,    0xc86fa84d57L,
            0xcbaa23d3ddL,    0xce14eb6297L,    0xd07ec66ccbL,    0xd21a2ad247L,    0xd2e7b5d3fbL,    0x15403fc313L,    0xd6e9e63d10L,    0xda1d06f27bL,
            0xdbb5fc65c8L,    0xdc82508207L,    0xdee6b2c233L,    0xe2e156cb42L,    0xe3acc4b9a2L,    0xe7a46db595L,    0xc5dd77cea1L,    0x23993428edL,
            0x5ad1e7218aL,    0x822660524dL,    0xb138b07a6fL,    0xb90db66620L,    0x0215d4958fL,    0xe0287c9248L,    0xe7f7c7f5a3L,    0x1d6e6678adL,
            0x22ddf91d8bL,    0x03a445b593L,    0x26bd2634f2L,    0x29d46b0213L,    0x2c24e6115fL,    0x2daf6cd5e9L,    0x349a42059dL,    0x37aaed0245L,
            0x3b7db9947bL,    0x3dc7ec72bdL,    0x401150af07L,    0x431c9620f6L,    0x46e8acac4dL,    0x4b7443145fL,    0x50bdc8dd4dL,    0x523fb8293bL,
            0x5481f82f11L,    0x56c3708024L,    0x5783c1ad36L,    0x61ff2de4b7L,    0x62be364c7eL,    0x66781af577L,    0x6971b3493bL,    0x6aedfe4ec7L,
            0x0b363d0311L,    0x71992c5698L,    0x748dc1f8daL,    0x0c19040500L,    0x7b2f3f404cL,    0x7f9738554aL,    0x810e8f4692L,    0x01500275b5L,
            0x8a8e636ca2L,    0x8e3218c29eL,    0x8eec330714L,    0x94ba2a6b76L,    0x9e1e1f2dfbL,    0x9f8eca6514L,    0xa047023427L,    0xa496b1302aL,
            0xa6bd7e4503L,    0xa82c4f5d6dL,    0xac76eca6d9L,    0xae9b33edd7L,    0xb1752dbd79L,    0xb2e1b67b93L,    0xb5b9e07146L,    0xbd86255ed6L,
            0x1305eaf449L,    0xbfa504ee55L,    0xc059d42fbfL,    0x13a8837ac6L,    0xce6a96d830L,    0xcf1ddc8595L,    0xd1373e6d63L,    0xd34ffa08eaL,
            0xd5680fd896L,    0xd6cd17db96L,    0xd8e41a7335L,    0xd9964c12f8L,    0xddc1f7139eL,    0xdf25495fb8L,    0xe34d8e2da9L,    0x16ccab2fb3L,
            0xe7734adce1L,    0xe82400e6f0L,    0x303963efabL,    0x371a3d8fe0L,    0x6e082d995dL,    0x82960dc05eL,    0xc6ed3a4969L,    0x1957402b09L,
            0x1c0eff5a25L,    0x1d6a77e9ddL,    0x1e181a7e96L,    0x1f732c56daL,    0x20209ba2d1L,    0x2790016836L,    0x2a422ac9eeL,    0x2e4b709deeL,
            0x304f318debL,    0x33a97b2627L,    0x3454f19d58L,    0x35abacd166L,    0x37ad4989aeL,    0x38585cc02fL,    0x3a5933869cL,    0x3daea6332cL,
            0x3e592594a7L,    0x4256cb12f0L,    0x45a86b1961L,    0x070837213dL,    0x49a1e217eeL,    0x4e4210f6f1L,    0x503ca2a6e6L,    0x518e095e0cL,
            0x5387ac1ebcL,    0x5628fc56f2L,    0x5821526d06L,    0x5a191a9805L,    0x5f55d2d75fL,    0x09ece14bdfL,    0x63e7c03a2eL,    0x6535783b8fL,
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
                raise TypeError, '%s() argument 1 must be string, not %s' % (self.__class__.__name__, type(m).__name__)
            self.update(m)
        
        
    def unpack(self, m):
        ret = [0]*64
        l = struct.unpack('!32b',m)
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
        hb = [0]*(self.depth/2)
        i = 0
        for i in range(self.depth/2):
            b = hm[i*2] << 4
            b = b | hm[i*2+1]  
            hb[i] = b
        return struct.pack('!32B',*tuple(hb))
    
    def digest(self):
        return self.pack(self._hashed)
    
    
    def hexdigest(self):
        return '0x' + self.digest().encode('hex')
        
        
    def update(self, m):
        if not m:
            return
        if type(m) is not str:
            raise TypeError, '%s() argument 1 must be string, not %s' % (sys._getframe().f_code.co_name, type(m).__name__)
        
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
        for gateIndex in range(self.size/4):
            block[gateIndex] = block[gateIndex] ^ layerHash[gateIndex]
        
        for gateIndex in range(self.size/4):
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
            
        for gateIndex in range(self.size/4):
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
        return block[wire/4] >> wire%4 & 1 

    def setBit(self, block, wire, bit):
        oldNib = block[wire/4] #int(block[2:][wire/4],16)
        ret = (oldNib & (15^(1 << wire%4)))
        ret = ret | (int(bit) << wire%4)  
        #ret = hex(ret)[2:]
        #block = block[:2 + wire/4] + ret +  block[2 + wire/4 + 1:] 
        block[wire/4] = ret  
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
    print 'Message=',m
    h = mirror256(m=m)
    import time
    t = time.time()
    c = 0
    for i in range(1024):
        digest = h.digest()
        #print i, '0x' + digest.encode('hex')
        randStr = randomAlfanumericString(N=32)
        #print len(randStr), randStr
        msg = 'This is the canary #%d. asdfasdfasdfasdfasdfqwerqwerqwerdfnnjkdfnjldljknsvv' % i
        h = mirror256( msg )
        c += 1
        if time.time() > t + 1:
            print '%d hashes per seconds!' % c
            print 'Example message = ', msg
            print 'Example digest = ', h.hexdigest()
            print 'Example message =',randStr
            print 'Example digest = ', mirror256(randStr).hexdigest()
            c = 0
            t = time.time()
