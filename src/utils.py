import struct

def format_code(original_code):
    instr_words = [original_code[i:i+4] for i in range(0, len(original_code), 4)]
    formatted_text = '\n'.join(' '.join(f'{byte:02x}' for byte in word) for word in instr_words)
    return formatted_text

