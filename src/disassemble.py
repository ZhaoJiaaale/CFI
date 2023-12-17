from capstone import *

def disassemble(code, disassemble_path):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    disassembled_code = ""
    for i in md.disasm(code, 0x1000):
        disassembled_code += f"{i.mnemonic} {i.op_str}\n"
        
    with open(disassemble_path, "w+") as f:
        f.write(disassembled_code)

