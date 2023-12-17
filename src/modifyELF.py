import sys
import lief
import struct

def read_elf_header(elf_data):
    e_shoff = struct.unpack_from('<Q', elf_data, 0x28)[0]       # Section Header Offset
    e_shentsize = struct.unpack_from('<H', elf_data, 0x3a)[0]   # Section Header Entry Size
    e_shnum = struct.unpack_from('<H', elf_data, 0x3c)[0]       # Section Header Entry Num
    return e_shoff, e_shentsize, e_shnum

def add_section(elf_path):
    new_section_name = '.trampoline'
    # fd7bbea9 fd030091 20008052 20011fd6
    # 0x98 0xff 0xff 0x1
    new_section_content = b'\xfd\x7b\xbe\xa9\x98\xff\xff\x17'
    new_section_offset = 0x790
    new_section_size = len(new_section_content)
    new_section_type = 1    # PROGBITS
    new_section_flags = 6   # ALLOC + EXECINSTR
    new_section_addr = 0x00400790
    
    with open(elf_path, 'rb') as f:
        elf_data = bytearray(f.read())
    elf_data[new_section_offset: new_section_offset + new_section_size] = new_section_content

    e_shoff, e_shentsize, e_shnum = read_elf_header(elf_data)

    shstrtab_index = struct.unpack_from('<H', elf_data, 0x3e)[0]  # uint16_t string_table 
    shstrtab_offset = struct.unpack_from('<Q', elf_data, e_shoff + shstrtab_index * e_shentsize + 0x18)[0]
    shstrtab_size = struct.unpack_from('<Q', elf_data, e_shoff + shstrtab_index * e_shentsize + 0x20)[0]

    new_section_name_offset = shstrtab_size
    elf_data[shstrtab_offset + shstrtab_size: shstrtab_offset + shstrtab_size + len(new_section_name) + 1] = bytes(new_section_name + '\x00', 'utf-8')
    elf_data[e_shoff + shstrtab_index * e_shentsize + 0x20 : e_shoff + shstrtab_index * e_shentsize + 0x28] = struct.pack('<Q', shstrtab_size + len(new_section_name) + 1)
    
    # New Section Header Entry
    new_section_header = struct.pack(
        '<IIQQQQIIQQ',
        new_section_name_offset,  # 名称偏移（暂时为 0，稍后更新）
        new_section_type,
        new_section_flags,
        new_section_addr,
        new_section_offset,
        new_section_size,
        0,  # 链接到其他节的索引（如果需要）
        0,  # 附加信息
        4,  # alignment
        0   # 固定条目大小
    )

    elf_data[e_shoff + e_shentsize * e_shnum : e_shoff + e_shentsize * (e_shnum + 1)] = new_section_header
    elf_data[0x3c:0x3e] = struct.pack('<H', e_shnum + 1)
    
    with open(elf_path, 'wb') as f:
        f.write(elf_data)
    
    elf = lief.parse(elf_path)
    target_segment = elf.segments[2]
    target_segment.virtual_size = 0x900
    target_segment.physical_size = 0x900
    elf.write(elf_path)

    print(f"Section: {new_section_name}")
    print(f"\tOffset: {hex(new_section_offset)}\n\tSize: {hex(new_section_size)}\n\tAddr: {hex(new_section_addr)}")