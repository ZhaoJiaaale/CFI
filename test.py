# # import lief
# # from elftools.elf.elffile import ELFFile

# # def parse_section(section_name):
# #     section = elf.get_section(section_name)
# #     print(dir(section))
# #     print(section)
# #     print(f"offset: {hex(section.offset)}")
# #     print(f"size: {hex(section.size)}")
# #     print(f"alignment: {hex(section.alignment)}")
# #     print(f"virtual_address: {hex(section.virtual_address)}")

# # def read_elf_headers(elf_path):
# #     with open(elf_path, 'rb') as f:
# #         elffile = ELFFile(f)

# #         # 读取节头表
# #         print("Section Header Table:")
# #         for section in elffile.iter_sections():
# #             print(f"{section.name}: {hex(section['sh_addr'])}, {hex(section['sh_offset'])}, {hex(section['sh_size'])}")

# #         # 读取程序头表
# #         print("\nProgram Header Table:")
# #         for segment in elffile.iter_segments():
# #             print(f"{segment['p_type']}: {hex(segment['p_vaddr'])}, {hex(segment['p_paddr'])}, {hex(segment['p_filesz'])}, {hex(segment['p_memsz'])}")


# # # 加载 ELF 文件
# # elf = lief.parse("./BinaryFile/test_nopac")

# # # 假设我们要修改第一个程序头表条目
# # # 注意：实际情况下，你需要根据需要选择正确的条目
# # phdr = elf.segments[2]
# # # phdr.virtual_size = 0x900
# # # phdr.physical_size = 0x900

# # print(dir(phdr))
# # print(f"file_offset: {phdr.file_offset}")
# # print(f"physical_address: {hex(phdr.physical_address)}")
# # print(f"physical_size: {hex(phdr.physical_size)}")
# # print(f"virtual_address: {hex(phdr.virtual_address)}")
# # print(f"virtual_size: {hex(phdr.virtual_size)}")
# # print(f"alignment: {hex(phdr.alignment)}")

# # print("-------------------------------------------------")

# # section = elf.get_section(".text")
# # print(dir(section))
# # print(section)
# # print(f"offset: {hex(section.offset)}")
# # print(f"size: {hex(section.size)}")
# # print(f"alignment: {hex(section.alignment)}")
# # print(f"virtual_address: {hex(section.virtual_address)}")



# # new_section = lief.ELF.Section()
# # new_section.name = ".trampoline"
# # # new_section.content = [0xfd, 0x7b, 0xbe, 0xa9, 0xc0, 0x03, 0x5f, 0xd6]
# # new_section.type = lief.ELF.SECTION_TYPES.PROGBITS
# # new_section.flags = lief.ELF.SECTION_FLAGS.ALLOC | lief.ELF.SECTION_FLAGS.EXECINSTR
# # new_section.offset = 0x740
# # new_section.alignment = 0x40
# # new_section.size = 0x40

# # new_section.virtual_address = 0x400740


# # # Adjust the segment's size to include the new section

# # elf.add(new_section)

# # # read_elf_headers("./BinaryFile/test_nopac")

# # elf.write("./BinaryFile/test_nopac")


# # # parse_section(".init_array")
# # # parse_section(".eh_frame")



# import struct

# def read_elf_header(elf_data):
#     # 读取节头表的偏移量和每个节头的大小
#     e_shoff = struct.unpack_from('<Q', elf_data, 0x28)[0]  # 节头表偏移量
#     e_shentsize = struct.unpack_from('<H', elf_data, 0x3a)[0]  # 节头大小
#     e_shnum = struct.unpack_from('<H', elf_data, 0x3c)[0]  # 节头数量
#     return e_shoff, e_shentsize, e_shnum

# # ELF 文件路径
# elf_path = './BinaryFile/test_nopac'
# new_elf_path = './BinaryFile/test_nopac'

# # 你已知的新 section 数据和位置信息
# new_section_offset = 0x740  # 新节的 offset
# new_section_size = 0x4  # 新节的 size
# new_section_name = '.newsection'

# # 新 section 的内容，这里以零填充作为示例
# new_section_data = b'\x00' * new_section_size

# # 读取原始 ELF 文件
# with open(elf_path, 'rb') as f:
#     elf_data = bytearray(f.read())

# # 插入新的 section 数据
# elf_data[new_section_offset: new_section_offset + new_section_size] = new_section_data
# # 这里需要实现更新节头表和 ELF 头部的逻辑
# # 注意：这个过程相当复杂，涉及到解析和修改 ELF 文件的二进制结构。
# # 你需要根据 ELF 文件格式手动构造节头表的条目，并更新 ELF 头部中的相关字段。

# # TODO: 更新节头表
# # TODO: 更新 ELF 头部



# # 读取原始 ELF 文件
# with open(elf_path, 'rb') as f:
#     elf_data = bytearray(f.read())

# # 读取 ELF 头部信息
# e_shoff, e_shentsize, e_shnum = read_elf_header(elf_data)

# print(f"e_shoff: {e_shoff}, e_shentsize: {e_shentsize}, e_shnum: {e_shnum}")

# # 假设的新节信息
# new_section_name = '.newsection'
# new_section_type = 1  # 假设类型为 PROGBITS
# new_section_flags = 6  # 假设标志为 ALLOC + EXECINSTR
# new_section_addr = 0x00400740  # 假设的新节虚拟地址
# new_section_offset = 0x740  # 假设的新节偏移量
# new_section_size = 0x4  # 假设的新节大小

# # 创建新的节头表条目
# new_section_header = struct.pack(
#     '<IIQQQQIIQQ',
#     0,  # 名称偏移（暂时为 0，稍后更新）
#     new_section_type,
#     new_section_flags,
#     new_section_addr,
#     new_section_offset,
#     new_section_size,
#     0,  # 链接到其他节的索引（如果需要）
#     0,  # 附加信息
#     4,  # 对齐
#     0   # 固定条目大小
# )

# # 添加新的节头表条目
# elf_data[e_shoff + e_shentsize * e_shnum : e_shoff + e_shentsize * (e_shnum + 1)] = new_section_header

# # 更新 ELF 头部的节头数量
# elf_data[0x3c:0x3e] = struct.pack('<H', e_shnum + 1)


# # 写回 ELF 文件
# with open(new_elf_path, 'wb') as f:
#     f.write(elf_data)

# print(b'\x00'*4)
# print(type(b'\x00'*4))

from capstone import *
from keystone import *
from elftools.elf.elffile import ELFFile
import sys
import os
import lief
from utils import *

def assemble(asm_code):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    encoding, count = ks.asm(asm_code)

    return encoding

asm_code = "b 0x4005bc"

for i in assemble(asm_code):
    print(hex(i))