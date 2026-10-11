#!/usr/bin/env python3
"""
LinuxNative x86_64 to AArch64 Static Binary Transpiler (AOT)
Translates x86_64 ELF binaries directly into native ARM64 ELFs without an emulator.
"""

import sys
import os
import re
import struct
import subprocess
import argparse

# Register mapping: x86_64 -> AArch64
REG_MAP = {
    # 64-bit
    'rax': 'x19', 'rbx': 'x20', 'rcx': 'x21', 'rdx': 'x22',
    'rsi': 'x23', 'rdi': 'x24', 'rbp': 'x25', 'rsp': 'sp',
    'r8': 'x8',   'r9': 'x9',   'r10': 'x10', 'r11': 'x11',
    'r12': 'x12', 'r13': 'x13', 'r14': 'x14', 'r15': 'x15',

    # 32-bit
    'eax': 'w19', 'ebx': 'w20', 'ecx': 'w21', 'edx': 'w22',
    'esi': 'w23', 'edi': 'w24', 'ebp': 'w25', 'esp': 'wsp',
    'r8d': 'w8',  'r9d': 'w9',  'r10d': 'w10', 'r11d': 'w11',
    'r12d': 'w12','r13d': 'w13','r14d': 'w14', 'r15d': 'w15',

    # 16-bit
    'ax': 'w19',  'bx': 'w20',  'cx': 'w21',  'dx': 'w22',
    'si': 'w23',  'di': 'w24',  'bp': 'w25',

    # 8-bit
    'al': 'w19',  'bl': 'w20',  'cl': 'w21',  'dl': 'w22',
    'sil': 'w23', 'dil': 'w24', 'bpl': 'w25',
    'r8b': 'w8',  'r9b': 'w9',  'r10b': 'w10', 'r11b': 'w11',
    'r12b': 'w12','r13b': 'w13','r14b': 'w14', 'r15b': 'w15',
}

SYSCALL_MAP = {
    0: 63,    # read
    1: 64,    # write
    2: 56,    # open -> openat
    3: 57,    # close
    4: 79,    # stat -> newfstatat
    5: 80,    # fstat
    8: 62,    # lseek
    9: 222,   # mmap
    10: 226,  # mprotect
    11: 215,  # munmap
    12: 214,  # brk
    13: 134,  # rt_sigaction
    14: 135,  # rt_sigprocmask
    16: 29,   # ioctl
    20: 66,   # writev
    39: 172,  # getpid
    60: 93,   # exit
    63: 160,  # uname
    72: 25,   # fcntl
    231: 94,  # exit_group
}

def parse_elf_sections(path):
    with open(path, 'rb') as f:
        data = f.read()

    if data[:4] != b'\x7fELF':
        raise ValueError("Not a valid ELF binary")
    if data[4] != 2:
        raise ValueError("Only 64-bit ELF is supported")

    e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHIQQQIHHHHHH', data[16:64])

    if e_machine != 0x3e:
        raise ValueError(f"Expected x86_64 ELF (0x3e), got {hex(e_machine)}")

    shstr_offset = e_shoff + e_shstrndx * e_shentsize
    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack('<IIQQQQIIQQ', data[shstr_offset:shstr_offset+64])
    shstrtab = data[sh_offset:sh_offset+sh_size]

    sections = {}
    for i in range(e_shnum):
        sec = e_shoff + i * e_shentsize
        n_idx, s_type, s_flags, s_addr, s_offset, s_size, s_link, s_info, s_align, s_entsize = struct.unpack('<IIQQQQIIQQ', data[sec:sec+64])
        name = shstrtab[n_idx:].split(b'\0')[0].decode('latin1')
        sec_bytes = data[s_offset:s_offset+s_size] if s_type != 8 else b''
        sections[name] = {
            'addr': s_addr,
            'offset': s_offset,
            'size': s_size,
            'flags': s_flags,
            'type': s_type,
            'align': s_align,
            'data': sec_bytes
        }

    return e_entry, sections

def disassemble_x86(path):
    cmd = ['llvm-objdump', '-d', '-M', 'intel', '--no-show-raw-insn', path]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    lines = proc.stdout.splitlines()

    instructions = []
    in_text = False

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith('Disassembly of section .text:'):
            in_text = True
            continue
        if not in_text:
            continue

        if line.endswith(':'):
            continue

        match = re.match(r'^([0-9a-fA-F]+):\s+(\S+)(?:\s+(.*))?$', line)
        if match:
            addr_str, mnemonic, operands = match.groups()
            addr = int(addr_str, 16)
            operands = operands if operands else ''
            comment = ''
            if '#' in operands:
                operands, comment = operands.split('#', 1)
                operands = operands.strip()
                comment = comment.strip()
            instructions.append((addr, mnemonic, operands, comment))

    return instructions

def map_reg(op):
    op = op.strip().lower()
    return REG_MAP.get(op, op)

def to_w_reg(r):
    if r.startswith('x'):
        return 'w' + r[1:]
    return r

def parse_mem(mem_str):
    size = 'qword'
    lower = mem_str.lower()
    if 'byte ptr' in lower:
        size = 'byte'
    elif 'word ptr' in lower:
        size = 'word'
    elif 'dword ptr' in lower:
        size = 'dword'
    elif 'qword ptr' in lower:
        size = 'qword'

    inner = mem_str[mem_str.index('[')+1 : mem_str.index(']')].strip()
    m = re.match(r'^([a-zA-Z0-9]+)\s*([+-])\s*([0-9a-fA-Fx]+)$', inner)
    if m:
        base, sign, off_str = m.groups()
        off = int(off_str, 16) if off_str.startswith('0x') else int(off_str)
        if sign == '-': off = -off
        return size, map_reg(base), off
    else:
        return size, map_reg(inner), 0

def map_operand(op, rip_target=None):
    op = op.strip()
    if op.lower() in REG_MAP:
        return REG_MAP[op.lower()]
    
    if re.match(r'^-?0x[0-9a-fA-F]+$', op):
        val = int(op, 16)
        return f"#{val}"
    if re.match(r'^-?[0-9]+$', op):
        val = int(op, 10)
        return f"#{val}"

    if '[rip' in op.lower() and rip_target is not None:
        return f"=data_{rip_target:x}"

    return op

def transpile(input_elf, output_asm):
    e_entry, sections = parse_elf_sections(input_elf)
    instructions = disassemble_x86(input_elf)

    asm_out = []
    asm_out.append("/* Auto-generated AArch64 Assembly by LinuxNative AOT Transpiler */")
    asm_out.append(".global _start")
    asm_out.append(".text")
    asm_out.append(".align 4\n")

    # Syscall adapter
    asm_out.append("/* x86_64 Syscall Translation Adapter */")
    asm_out.append(".type x86_syscall_adapter, %function")
    asm_out.append("x86_syscall_adapter:")
    asm_out.append("    stp x29, x30, [sp, #-16]!")
    asm_out.append("    mov x29, sp")
    asm_out.append("    mov x0, x24  /* RDI */")
    asm_out.append("    mov x1, x23  /* RSI */")
    asm_out.append("    mov x2, x22  /* RDX */")
    asm_out.append("    mov x3, x10  /* R10 */")
    asm_out.append("    mov x4, x8   /* R8  */")
    asm_out.append("    mov x5, x9   /* R9  */")
    asm_out.append("")

    for x86_nr, arm_nr in SYSCALL_MAP.items():
        asm_out.append(f"    cmp x19, #{x86_nr}")
        asm_out.append(f"    b.eq .sys_{x86_nr}")

    asm_out.append("    /* Unhandled fallback */")
    asm_out.append("    mov x8, x19")
    asm_out.append("    svc #0")
    asm_out.append("    mov x19, x0")
    asm_out.append("    ldp x29, x30, [sp], #16")
    asm_out.append("    ret")
    asm_out.append("")

    for x86_nr, arm_nr in SYSCALL_MAP.items():
        asm_out.append(f".sys_{x86_nr}:")
        if x86_nr == 2: # open -> openat(AT_FDCWD, path, flags, mode)
            asm_out.append("    mov x3, x2")
            asm_out.append("    mov x2, x1")
            asm_out.append("    mov x1, x0")
            asm_out.append("    mov x0, #-100 /* AT_FDCWD */")
        asm_out.append(f"    mov x8, #{arm_nr}")
        asm_out.append("    svc #0")
        asm_out.append("    mov x19, x0")
        asm_out.append("    ldp x29, x30, [sp], #16")
        asm_out.append("    ret")
        asm_out.append("")

    # Entry point
    asm_out.append("_start:")
    asm_out.append(f"    b loc_{e_entry:x}\n")

    # Collect all referenced data addresses
    referenced_data_addrs = set()
    for addr, mnem, ops, comment in instructions:
        if comment:
            m_target = re.search(r'0x([0-9a-fA-F]+)', comment)
            if m_target:
                referenced_data_addrs.add(int(m_target.group(1), 16))

    # Transpile code
    asm_out.append("/* Transpiled Instructions */")
    for addr, mnem, ops, comment in instructions:
        asm_out.append(f"loc_{addr:x}:")

        rip_target = None
        if comment:
            m_target = re.search(r'0x([0-9a-fA-F]+)', comment)
            if m_target:
                rip_target = int(m_target.group(1), 16)

        parts = [p.strip() for p in ops.split(',')] if ops else []

        if mnem == 'nop':
            asm_out.append("    nop")
        elif mnem == 'syscall':
            asm_out.append("    bl x86_syscall_adapter")
        elif mnem == 'ret':
            asm_out.append("    ret")
        elif mnem == 'mov':
            dst_str = parts[0]
            src_str = parts[1]
            if '[' in dst_str: # store
                size, base, off = parse_mem(dst_str)
                src = map_operand(src_str, rip_target)
                if src.startswith('#'):
                    asm_out.append(f"    mov w16, {src}")
                    src_reg = 'w16' if size in ('byte', 'word', 'dword') else 'x16'
                else:
                    src_reg = to_w_reg(src) if size in ('byte', 'word', 'dword') else src
                inst = 'strb' if size == 'byte' else ('strh' if size == 'word' else ('str' if size == 'dword' else 'str'))
                asm_out.append(f"    {inst} {src_reg}, [{base}, #{off}]")
            elif '[' in src_str: # load
                if '[rip' in src_str and rip_target is not None:
                    dst = map_reg(dst_str)
                    asm_out.append(f"    ldr {dst}, =data_{rip_target:x}")
                else:
                    size, base, off = parse_mem(src_str)
                    dst = map_reg(dst_str)
                    if size in ('byte', 'word', 'dword'):
                        dst = to_w_reg(dst)
                    inst = 'ldrb' if size == 'byte' else ('ldrh' if size == 'word' else 'ldr')
                    asm_out.append(f"    {inst} {dst}, [{base}, #{off}]")
            else: # reg-reg or reg-imm
                dst = map_reg(dst_str)
                src = map_operand(src_str, rip_target)
                if src.startswith('='):
                    asm_out.append(f"    ldr {dst}, {src}")
                elif src.startswith('#') and int(src[1:]) > 65535:
                    asm_out.append(f"    ldr {dst}, ={src[1:]}")
                else:
                    asm_out.append(f"    mov {dst}, {src}")
        elif mnem == 'lea':
            dst = map_reg(parts[0])
            if rip_target is not None:
                asm_out.append(f"    ldr {dst}, =data_{rip_target:x}")
            elif '[' in parts[1]:
                size, base, off = parse_mem(parts[1])
                asm_out.append(f"    add {dst}, {base}, #{off}")
            else:
                asm_out.append(f"    mov {dst}, {map_reg(parts[1])}")
        elif mnem == 'add':
            dst = map_reg(parts[0])
            src = map_operand(parts[1])
            asm_out.append(f"    add {dst}, {dst}, {src}")
        elif mnem == 'sub':
            dst = map_reg(parts[0])
            src = map_operand(parts[1])
            asm_out.append(f"    sub {dst}, {dst}, {src}")
        elif mnem == 'xor':
            dst = map_reg(parts[0])
            src = map_operand(parts[1])
            if dst == src:
                asm_out.append(f"    mov {dst}, #0")
            else:
                asm_out.append(f"    eor {dst}, {dst}, {src}")
        elif mnem == 'and':
            dst = map_reg(parts[0])
            src = map_operand(parts[1])
            asm_out.append(f"    and {dst}, {dst}, {src}")
        elif mnem == 'or':
            dst = map_reg(parts[0])
            src = map_operand(parts[1])
            asm_out.append(f"    orr {dst}, {dst}, {src}")
        elif mnem == 'cmp':
            op1 = map_reg(parts[0])
            op2 = map_operand(parts[1])
            asm_out.append(f"    cmp {op1}, {op2}")
        elif mnem == 'test':
            op1 = map_reg(parts[0])
            op2 = map_operand(parts[1])
            asm_out.append(f"    tst {op1}, {op2}")
        elif mnem == 'inc':
            dst = map_reg(parts[0])
            asm_out.append(f"    add {dst}, {dst}, #1")
        elif mnem == 'dec':
            dst = map_reg(parts[0])
            asm_out.append(f"    sub {dst}, {dst}, #1")
        elif mnem == 'push':
            src = map_reg(parts[0])
            asm_out.append(f"    str {src}, [sp, #-16]!")
        elif mnem == 'pop':
            dst = map_reg(parts[0])
            asm_out.append(f"    ldr {dst}, [sp], #16")
        elif mnem == 'jmp':
            t = parts[0].split()[0].strip()
            if t.startswith('0x') or t.isdigit():
                t_val = int(t, 16) if t.startswith('0x') else int(t)
                asm_out.append(f"    b loc_{t_val:x}")
            else:
                asm_out.append(f"    b {t}")
        elif mnem in ('je', 'jz'):
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.eq loc_{t_val:x}")
        elif mnem in ('jne', 'jnz'):
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.ne loc_{t_val:x}")
        elif mnem in ('jl', 'jnge'):
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.lt loc_{t_val:x}")
        elif mnem in ('jle', 'jng'):
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.le loc_{t_val:x}")
        elif mnem in ('jg', 'jnle'):
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.gt loc_{t_val:x}")
        elif mnem in ('jge', 'jnl'):
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.ge loc_{t_val:x}")
        elif mnem in ('js',):
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.mi loc_{t_val:x}")
        elif mnem in ('jns',):
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.pl loc_{t_val:x}")
        elif mnem == 'call':
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append("    str x30, [sp, #-16]!")
            asm_out.append(f"    bl loc_{t_val:x}")
            asm_out.append("    ldr x30, [sp], #16")
        else:
            asm_out.append(f"    /* UNHANDLED: {mnem} {ops} */")
            asm_out.append("    brk #0")

    # Data and BSS sections
    asm_out.append("\n/* Embedded Data & BSS Sections */")
    for sec_name in ['.rodata', '.data', '.bss']:
        if sec_name in sections and sections[sec_name]['size'] > 0:
            sec_info = sections[sec_name]
            base_addr = sec_info['addr']
            sec_size = sec_info['size']
            asm_out.append(f".section {sec_name}")
            asm_out.append(".align 4")
            
            if sec_name == '.bss':
                bss_points = sorted([a for a in referenced_data_addrs if base_addr <= a < base_addr + sec_size])
                if not bss_points or bss_points[0] != base_addr:
                    bss_points.insert(0, base_addr)
                bss_points.append(base_addr + sec_size)
                for k in range(len(bss_points) - 1):
                    p_start = bss_points[k]
                    p_end = bss_points[k+1]
                    asm_out.append(f"data_{p_start:x}:")
                    if p_end > p_start:
                        asm_out.append(f"    .zero {p_end - p_start}")
            else:
                data_bytes = sec_info['data']
                chunk = []
                chunk_addr = base_addr
                for offset, b in enumerate(data_bytes):
                    cur_addr = base_addr + offset
                    if (cur_addr in referenced_data_addrs or offset == 0) and cur_addr != chunk_addr:
                        if chunk:
                            b_str = ", ".join(f"0x{x:02x}" for x in chunk)
                            asm_out.append(f"    .byte {b_str}")
                            chunk = []
                        asm_out.append(f"data_{cur_addr:x}:")
                        chunk_addr = cur_addr
                    elif cur_addr in referenced_data_addrs and offset == 0:
                        asm_out.append(f"data_{cur_addr:x}:")
                    chunk.append(b)
                    if len(chunk) >= 16:
                        b_str = ", ".join(f"0x{x:02x}" for x in chunk)
                        asm_out.append(f"    .byte {b_str}")
                        chunk = []
                if chunk:
                    b_str = ", ".join(f"0x{x:02x}" for x in chunk)
                    asm_out.append(f"    .byte {b_str}")

    with open(output_asm, 'w') as f:
        f.write("\n".join(asm_out) + "\n")

def main():
    parser = argparse.ArgumentParser(description="LinuxNative x86_64 to ARM64 AOT Transpiler")
    parser.add_argument("input_elf", help="Input x86_64 ELF executable")
    parser.add_argument("-o", "--output", required=True, help="Output AArch64 executable ELF")
    parser.add_argument("--keep-asm", action="store_true", help="Keep generated .s assembly file")
    args = parser.parse_args()

    asm_file = args.output + ".s"
    print(f"[*] Lifting and transpiling {args.input_elf} (x86_64) -> {asm_file} (AArch64)...")
    transpile(args.input_elf, asm_file)

    print(f"[*] Assembling native AArch64 binary: {args.output}...")
    cmd = ['clang', '-O2', '-nostdlib', '-static', asm_file, '-o', args.output]
    subprocess.run(cmd, check=True)

    if not args.keep_asm:
        os.remove(asm_file)

    print(f"[✓] Success! Native AArch64 ELF created: {args.output}")

if __name__ == "__main__":
    main()
