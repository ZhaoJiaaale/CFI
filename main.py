from capstone import *
from keystone import *
from elftools.elf.elffile import ELFFile
import sys
import os
import lief
from utils import *

def add_section(elf_path):
    elf = lief.parse(elf_path)

    new_section = lief.ELF.Section()
    new_section.name = ".trampoline"
    # fd7bbea9 c0035fd6 
    new_section.content = [0xfd, 0x7b, 0xbe, 0xa9, 0xc0, 0x03, 0x5f, 0xd6]
    new_section.type = lief.ELF.SECTION_TYPES.PROGBITS
    new_section.flags = lief.ELF.SECTION_FLAGS.ALLOC | lief.ELF.SECTION_FLAGS.EXECINSTR
    new_section.alignment = 0x40

    # new_section.virtual_address = 0x20000

    elf.add(new_section)
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
        # machine_code = ' '.join(f'{byte:02x}' for byte in i.bytes)
        # instr = f"0x{i.address:08x}:\t{machine_code}\t\t\t{i.mnemonic}\t{i.op_str}\n"
        # f.write(instr)
        disassembled_code += f"{i.mnemonic} {i.op_str}\n"
    with open(disassemble_path, "w+") as f:
        f.write(disassembled_code)

def assemble(asm_code):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    encoding, count = ks.asm(asm_code)

    # formatted_text = format_code(bytes(encoding))
    
    # with open(assemble_path, "w+") as f:
    #     f.write(formatted_text)

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
    
    for i in range(len(instrs)):
        if i > 0:
            if instrs[i] == 'stp x29, x30, [sp, #-0x20]!\n' and instrs[i-1] == "ret \n":
                modified_index_instrs[i] = "bl #0x401a50"

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
