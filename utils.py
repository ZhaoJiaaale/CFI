import struct

def format_code(original_code):
    instr_words = [original_code[i:i+4] for i in range(0, len(original_code), 4)]
    formatted_text = '\n'.join(' '.join(f'{byte:02x}' for byte in word) for word in instr_words)
    return formatted_text


def read_elf_header(elf_data):
    e_shoff = struct.unpack_from('<Q', elf_data, 0x28)[0]       # Section Header Offset
    e_shentsize = struct.unpack_from('<H', elf_data, 0x3a)[0]   # Section Header Entry Size
    e_shnum = struct.unpack_from('<H', elf_data, 0x3c)[0]       # Section Header Entry Num
    return e_shoff, e_shentsize, e_shnum