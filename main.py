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
    new_section.content = [0xc0, 0x18, 0x02, 0x94]
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
        for section in elf.iter_sections():
            if section.name == '.text':
                code = section.data()
                break
        return code
    

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

def assemble(asm_code, assemble_path):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    encoding, count = ks.asm(asm_code)

    formatted_text = format_code(bytes(encoding))
    
    with open(assemble_path, "w+") as f:
        f.write(formatted_text)

    # return bytes(encoding), count

def binary_rewrite(elf_path):
    elf_name = os.path.basename(elf_path).split(".")[0]

    """
        Get the Original Code of .text Section in ELF file
    """
    # ---------------------------------------------------------------------------------------------------------------------- #
    print("\n--------------------------------------------------------------------------------------------------------------------------------------------------")
    print(f"Analyzing ELF file: {elf_name}")
    original_code = read_elf(elf_path)
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
    
    # Transform hex string to bytes list: e.g. [[0x1f,0x20,0x03,0xd5], [0x1d,0x00,0x80,0xd2], ...]
    byte_array = []
    with open(disassemble_path, "r") as disassemble_f:
        for instr in disassemble_f:
            print(instr)
    # hh

    # ---------------------------------------------------------------------------------------------------------------------- #
    


    """
        Assemble the Modified Code
    """
    # ---------------------------------------------------------------------------------------------------------------------- #
    assemble_path = "./Assemble/" + elf_name + "_text.txt"
    with open(disassemble_path, 'r') as f:
        disassembled_code = f.read()

    assemble(disassembled_code, assemble_path)
    # ---------------------------------------------------------------------------------------------------------------------- #

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python binary_rewrite.py <elf_file>")
        sys.exit(1)

    elf_path = sys.argv[1]
    binary_rewrite(elf_path)
