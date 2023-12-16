from capstone import *
from keystone import *
from elftools.elf.elffile import ELFFile
import sys
import os
import lief
from utils import *

def add_section(elf_path):
    new_section_name = '.trampoline'
    # fd7bbea9 fd030091 20008052 20011fd6
    # 0x98 0xff 0xff 0x1
    new_section_content = b'\xfd\x7b\xbe\xa9\x98\xff\xff\x17'
    new_section_offset = 0x790
    new_section_size = 0x8
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

    print(hex(shstrtab_offset))
    print(hex(shstrtab_size))
    
    new_section_name_offset = shstrtab_size
    elf_data[shstrtab_offset + shstrtab_size: shstrtab_offset + shstrtab_size + len(new_section_name) + 1] = bytes(new_section_name + '\x00', 'utf-8')
    elf_data[e_shoff + shstrtab_index * e_shentsize + 0x20 : e_shoff + shstrtab_index * e_shentsize + 0x28] = struct.pack('<Q', shstrtab_size + len(new_section_name) + 1)
    
    print(hex(shstrtab_offset + shstrtab_size))
    print(hex(shstrtab_offset + shstrtab_size + len(new_section_name) + 1))
    print(bytes(new_section_name + '\x00', 'utf-8'))

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

def read_elf(file_path):
    with open(file_path, 'rb') as f:
        elf = ELFFile(f)
        code = None
        offset = None 
        size = None
        for section in elf.iter_sections():
            if section.name == '.text':
                code = section.data()
                offset = section['sh_offset']
                size = section['sh_size']
                break
        return code, offset, size
    

def disassemble(code, disassemble_path):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    disassembled_code = ""
    for i in md.disasm(code, 0x1000):
        disassembled_code += f"{i.mnemonic} {i.op_str}\n"
        
    with open(disassemble_path, "w+") as f:
        f.write(disassembled_code)

def assemble(asm_code):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    encoding, count = ks.asm(asm_code)

    return bytes(encoding)

def binary_rewrite(elf_path):
    elf_name = os.path.basename(elf_path).split(".")[0]

    """
        Get the Original Code of .text Section in ELF file
    """
    # ---------------------------------------------------------------------------------------------------------------------- #
    print("\n--------------------------------------------------------------------------------------------------------------------------------------------------")
    print(f"Analyzing ELF file: {elf_name}")
    original_code, text_offset, text_size = read_elf(elf_path)
    original_code_path = "./OriginalBinary/" + elf_name + "_text.txt"
    with open(original_code_path, 'w+') as file:
        file.write(format_code(original_code))
    print(f"The Original Code of .text Section in {elf_name} is located in: {original_code_path}")
    print("--------------------------------------------------------------------------------------------------------------------------------------------------\n")
    # ---------------------------------------------------------------------------------------------------------------------- #

    """
        Add a Section to ELF file: .trampoline
    """
    # ---------------------------------------------------------------------------------------------------------------------- #
    print("\n--------------------------------------------------------------------------------------------------------------------------------------------------")
    print(f"Adding a Section: .trampoline to {elf_name} EFL file")
    add_section(elf_path)

    print("--------------------------------------------------------------------------------------------------------------------------------------------------\n")
    # ---------------------------------------------------------------------------------------------------------------------- #
    
    """
        Disassemble the Original Code
    """
    # ---------------------------------------------------------------------------------------------------------------------- #
    print("\n--------------------------------------------------------------------------------------------------------------------------------------------------")
    print(f"Disassembling the Original Code of .text Section in {elf_name} ELF file")
    disassemble_path = "./Disassemble/" + elf_name + ".s"
    disassemble(original_code, disassemble_path)
    print(f"Disassemble Complete. Located in: {disassemble_path}")
    print("--------------------------------------------------------------------------------------------------------------------------------------------------\n")
    # ---------------------------------------------------------------------------------------------------------------------- #

    """
        Modify the ELF file, including:
            1 .text Section
                Patch Jump Instruction
            2 .trampoline Section
                Append context to Trampoline
    """
    # ---------------------------------------------------------------------------------------------------------------------- #
    modified_index_instrs = {}  # index: modified instr
    instrs = []
    with open(disassemble_path, "r") as disassemble_f:
        instrs = disassemble_f.readlines()
    # 随便设置的patch规则，后续会专门设计    
    for i in range(len(instrs)):
        if i > 0:
            if instrs[i] == 'stp x29, x30, [sp, #-0x20]!\n' and instrs[i-1] == "ret \n":
                # modified_index_instrs[i] = "adrp x9, #0x1000"      # fd7bbea9
                # modified_index_instrs[i+1] = "add x9, x9, #-0xa44" 
                modified_index_instrs[i] = "b 0x1a0"           # 20008052

    for index, instr in modified_index_instrs.items():
        modified_index_instrs[index] = assemble(instr)
    
    for index, code in modified_index_instrs.items():
        start_index = index * 4
        end_index = index * 4 + 4
    
        original_code = original_code[:start_index] + code + original_code[end_index:]

    modified_disassemble_path = "./Disassemble/modified_" + elf_name + ".s"
    disassemble(original_code, modified_disassemble_path)


    with open(elf_path, 'r+b') as f:
        f.seek(text_offset)
        f.write(original_code[:text_size])

    # ---------------------------------------------------------------------------------------------------------------------- #
    

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python binary_rewrite.py <elf_file>")
        sys.exit(1)

    elf_path = sys.argv[1]
    binary_rewrite(elf_path)
