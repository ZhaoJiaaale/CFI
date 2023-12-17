from capstone import *
from keystone import *
from elftools.elf.elffile import ELFFile
import sys
import os
from src.utils import *
from src.disassemble import *
from src.assemble import *
from src.parseELF import *
from src.modifyELF import *


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
    print(f"Adding a Section to {elf_name} EFL file")
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
        print("Usage: python main.py <elf_file>")
        sys.exit(1)

    elf_path = sys.argv[1]
    binary_rewrite(elf_path)
