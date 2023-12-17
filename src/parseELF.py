from elftools.elf.elffile import ELFFile
import struct

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

