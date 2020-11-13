# ----------- helpers ------------------------------
def reverse_shuffle(ciphertext, mapping):
    result = bytearray( [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] )
    cursor = 0
    for i in mapping:
        result[i] = ciphertext[cursor] # map

        cursor += 1
    return result


def xor_box(text, xor_map):
    result = bytearray( [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] )
    for i in range(0, len(xor_map)):
        result[i] = text[i] ^ xor_map[i]
    
    return result
# ---------------------------------------------------



# init vars
# ------------
flag_cipher = bytearray([0x43, 0x51, 0x43, 0x36, 0x40, 0x52, 0x21, 0x55, 0x24, 0x42, 0x5b, 0x68, 0x7d, 0x67, 0x1f, 0x7b, 0x5d, 0x7e, 0x4e, 0x0e, 0x58, 0x04, 0x22, 0x40, 0x1e, 0x14, 0x16, 0x2c, 0x20, 0x22, 0x26, 0x34])

# p_box
p_box_raw = bytearray( [0x02,0x07,0x05,0x0e,0x01,0x0c,0x06,0x03, 0x10,0x08,0x0b,0x0f,0x0d,0x0a,0x09,0x04] )
p_box = int.from_bytes(p_box_raw, byteorder='little')

mask = 0x01010101010101010101010101010101
p_box_masked = (p_box - mask) # our lookup table is ready :D
p_box_masked_map = p_box_masked.to_bytes(16, byteorder='little')

# x_box
x_box_raw = bytearray([0x02,0x03,0x05,0x07,0x0b,0x0d,0x11,0x13, 0x17,0x1d,0x1f,0x25,0x29,0x2b,0x2f,0x00])


# main
# ------------

# xoring
flag_cipher[0:16] = xor_box(flag_cipher[0:16], x_box_raw)
flag_cipher[16:32] = xor_box(flag_cipher[16:32], x_box_raw)

# shuffling
shuffled  = reverse_shuffle(flag_cipher[0:16], p_box_masked_map)
shuffled += reverse_shuffle(flag_cipher[16:32], p_box_masked_map)


print( 'plaintext:', shuffled.decode('utf-8') )
