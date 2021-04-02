#!/usr/bin/env python

import binascii

dig_deeper = open('./digDeeper.jpg', 'rb').read()
jump       = 0x1ce9
const_var  = binascii.unhexlify(('a5 00 00 00 bc 00 00 00 bc 00 00 00 a1 00 00 00 5c 00 00 00 6c 00 00 00' +
                                'dc 00 00 00 00 00 00 00 3c 00 00 00 16 00 00 00 9c 00 00 00 42 00 00 00' +
                                '2d 00 00 00 28 00 00 00 db 00 00 00 c8 00 00 00 c0 00 00 00 27 00 00 00' +
                                '21 00 00 00 29 00 00 00 41 00 00 00 08 00 00 00 19 00 00 00 c0 00 00 00' + 
                                '44 00 00 00 8b 00 00 00 1c 00 00 00 2f 00 00 00 27 00 00 00 1f 00 00 00' + 
                                '03 00 00 00 b2 00 00 00 3d 00 00 00 f3 00 00 00 ed 00 00 00 14 00 00 00' +
                                '15 00 00 00 fe 00 00 00 2b 00 00 00 d6 00 00 00 e1 00 00 00 55 00 00 00').replace('00 00 00', '').replace(' ',''))

flag = '' 
for j in range(0, len(const_var)):
    i   = const_var[j]
    out = chr(dig_deeper[(j+2)*jump] ^ i)
    flag += out
    
print(flag)

# output:
# $ python3 decrypt.py 
#   MCL{li7tl3_5P3c1al_S3crET_Ag3n7_'\'m3n'\'}