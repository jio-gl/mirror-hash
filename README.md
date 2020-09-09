# mirror-hash
An experimental hashing algorithm for optical/quantum computers based on Toffoli and Fredkin gates.

With standard 256-bit input it has 64 layers of the following gates. Each has 2 sublayers of Toffoli or Fredkin gates in zig-zag fashion. The symmetry and type of gate is determined by the previous block (called layer encoding here) of the hash and also there is a XOR with the current layer encoding to avoid 0-to-0 hashes.

```
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
```

# Example

There is still some bugs to fix because with random input works well but with not random input is the has is not random.

```
$ python2 mirror.py
Message= This is the canary.
25 hashes per seconds!
Example message =  This is the canary #24. asdfasdfasdfasdfasdfqwerqwerqwerdfnnjkdfnjldljknsvv
Example digest =  0x90c512bbf16505946c50a079620a3a577699d46222b615dad3b46e26cd6839ff
Example message = UK3GR9EE8CHZJ2Z2LVNNETKFY23IMWO4
Example digest =  0x1e7ccad3a02b386de5ed28a89b9c9baacb9de548c3ada6a58281f8c080a19757
25 hashes per seconds!
Example message =  This is the canary #49. asdfasdfasdfasdfasdfqwerqwerqwerdfnnjkdfnjldljknsvv
Example digest =  0x17b712bbf16505946c13f53faf92e6cfecdd15d3ccb70dc4777b18df814e0275
Example message = JTKLD9IYN9N3T6YEWCNSCP87X3FYP3M4
Example digest =  0x2273feacc732a2812b37d829e6f2cc976b7724c851718106e86c2a38e5d3d86b
25 hashes per seconds!
Example message =  This is the canary #74. asdfasdfasdfasdfasdfqwerqwerqwerdfnnjkdfnjldljknsvv
Example digest =  0x90c512bbf16505946c13f53fa7fe0bbf4d33986037827c7f1990be264d6839ff
Example message = QR8Y4D6FNRCI16F8WJV9JOE40AH10NFW
Example digest =  0x8ae028bfc46ae69dedb649ae1792cb059a7f4e02f81b84282bdf93bd46116bd6
25 hashes per seconds!
Example message =  This is the canary #99. asdfasdfasdfasdfasdfqwerqwerqwerdfnnjkdfnjldljknsvv
Example digest =  <strong>0x90c512bbf16505946c13f53fa7fe0bbf</strong>96e6e6bc1e313c1cfc70533f3914779f
Example message = IC8Y2L4VS70WBV64HI2FP9SGDH9D1PJL
Example digest =  0xfe980a1c9613b0c46869f20487747dded3013419bfcd59ae0343e27828d3fb93
25 hashes per seconds!
Example message =  This is the canary #124. asdfasdfasdfasdfasdfqwerqwerqwerdfnnjkdfnjldljknsvv
Example digest =  0x6d3f47247b36c30c115a3d669354fcf8f4c39e7bb3cce77bba04f8c26a896401
Example message = 3KPELWAT572JK6BVZCFQI1J8FJWO9UT7
Example digest =  0x1443240f717721e2fb7e2a339ff721ac344e93dd09531b47da03acc5c9145710
```
