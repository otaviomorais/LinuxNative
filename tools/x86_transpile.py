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
    'rsi': 'x23', 'rdi': 'x24', 'rbp': 'x25', 'rsp': 'x28',
    'r8': 'x26',  'r9': 'x27',  'r10': 'x10', 'r11': 'x11',
    'r12': 'x12', 'r13': 'x13', 'r14': 'x14', 'r15': 'x15',

    # 32-bit
    'eax': 'w19', 'ebx': 'w20', 'ecx': 'w21', 'edx': 'w22',
    'esi': 'w23', 'edi': 'w24', 'ebp': 'w25', 'esp': 'w28',
    'r8d': 'w26', 'r9d': 'w27', 'r10d': 'w10', 'r11d': 'w11',
    'r12d': 'w12','r13d': 'w13','r14d': 'w14', 'r15d': 'w15',

    # 16-bit
    'ax': 'w19',  'bx': 'w20',  'cx': 'w21',  'dx': 'w22',
    'si': 'w23',  'di': 'w24',  'bp': 'w25',  'sp': 'w28',
    'r8w': 'w26', 'r9w': 'w27', 'r10w': 'w10','r11w': 'w11',
    'r12w': 'w12','r13w': 'w13','r14w': 'w14','r15w': 'w15',

    # 8-bit
    'al': 'w19',  'bl': 'w20',  'cl': 'w21',  'dl': 'w22',
    'sil': 'w23', 'dil': 'w24', 'bpl': 'w25', 'spl': 'w28',
    'r8b': 'w26', 'r9b': 'w27', 'r10b': 'w10','r11b': 'w11',
    'r12b': 'w12','r13b': 'w13','r14b': 'w14','r15b': 'w15',
    'ah': 'w19',  'bh': 'w20',  'ch': 'w21',  'dh': 'w22',

    # 128-bit SIMD / SSE (mapped to ARM64 NEON q0-q15)
    'xmm0': 'q0',  'xmm1': 'q1',  'xmm2': 'q2',  'xmm3': 'q3',
    'xmm4': 'q4',  'xmm5': 'q5',  'xmm6': 'q6',  'xmm7': 'q7',
    'xmm8': 'q8',  'xmm9': 'q9',  'xmm10': 'q10','xmm11': 'q11',
    'xmm12': 'q12','xmm13': 'q13','xmm14': 'q14','xmm15': 'q15',
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

def to_x_reg(r):
    if r.startswith('w'):
        return 'x' + r[1:]
    return r

def is_xmm(reg):
    return reg.lower().startswith(('xmm', 'q', 'v', 'd', 's')) and any(c.isdigit() for c in reg)

def xmm_to_v(reg, arr='16b'):
    r = reg.strip().lower()
    m = re.match(r'(?:xmm|q|v|d|s)(\d+)', r)
    if m:
        return f"v{m.group(1)}.{arr}"
    return reg

def xmm_to_q(reg):
    r = reg.strip().lower()
    m = re.match(r'(?:xmm|q|v|d|s)(\d+)', r)
    if m:
        return f"q{m.group(1)}"
    return reg

def xmm_to_d(reg):
    r = reg.strip().lower()
    m = re.match(r'(?:xmm|q|v|d|s)(\d+)', r)
    if m:
        return f"d{m.group(1)}"
    return reg

def xmm_to_s(reg):
    r = reg.strip().lower()
    m = re.match(r'(?:xmm|q|v|d|s)(\d+)', r)
    if m:
        return f"s{m.group(1)}"
    return reg

def parse_x86_mem(mem_str, rip_target=None):
    size = 'qword'
    lower = mem_str.lower()
    if 'xmmword ptr' in lower: size = 'xmmword'
    elif 'byte ptr' in lower: size = 'byte'
    elif 'dword ptr' in lower: size = 'dword'
    elif 'qword ptr' in lower: size = 'qword'
    elif 'word ptr' in lower: size = 'word'

    inner = mem_str[mem_str.index('[')+1 : mem_str.index(']')].strip()
    
    if 'rip' in inner.lower() and rip_target is not None:
        return {'type': 'rip', 'size': size, 'target': f"data_{rip_target:x}"}

    clean = re.sub(r'\s*-\s*', '+-', inner)
    terms = [t.strip() for t in clean.split('+') if t.strip()]
    base_reg = None
    idx_reg = None
    scale = 0
    imm_offset = 0

    for t in terms:
        if '*' in t:
            p = t.split('*')
            if p[0].isdigit():
                scale = int(p[0])
                idx_reg = to_x_reg(map_reg(p[1]))
            else:
                scale = int(p[1])
                idx_reg = to_x_reg(map_reg(p[0]))
        elif re.match(r'^[+-]?(?:0x[0-9a-fA-F]+|[0-9]+)$', t):
            imm_offset += int(t, 16) if '0x' in t.lower() else int(t)
        else:
            r = to_x_reg(map_reg(t))
            if base_reg is None:
                base_reg = r
            elif idx_reg is None:
                idx_reg = r
                scale = 1

    return {
        'type': 'mem',
        'size': size,
        'base': base_reg or 'x28',
        'index': idx_reg,
        'scale': scale,
        'offset': imm_offset
    }

def emit_load(dst_reg, mem_info):
    size = mem_info['size']
    if dst_reg.startswith(('q', 'd', 's')):
        inst = 'ldr'
        target_reg = dst_reg
    else:
        inst = 'ldrb' if size == 'byte' else ('ldrh' if size == 'word' else ('ldr' if size == 'dword' else 'ldr'))
        target_reg = to_w_reg(dst_reg) if size in ('byte', 'word', 'dword') else dst_reg

    if mem_info['type'] == 'rip':
        return [f"    ldr x16, ={mem_info['target']}",
                f"    {inst} {target_reg}, [x16]"]

    base = mem_info['base']
    idx = mem_info['index']
    scale = mem_info['scale']
    off = mem_info['offset']

    if not idx and -256 <= off <= 255:
        return [f"    {inst} {target_reg}, [{base}, #{off}]"]

    lines = []
    if idx:
        shift = {1: 0, 2: 1, 4: 2, 8: 3}.get(scale, 0)
        shift_str = f", lsl #{shift}" if shift > 0 else ""
        lines.append(f"    add x17, {base}, {idx}{shift_str}")
        if -256 <= off <= 255:
            lines.append(f"    {inst} {target_reg}, [x17, #{off}]")
        else:
            lines.append(f"    mov x16, #{off}")
            lines.append(f"    add x17, x17, x16")
            lines.append(f"    {inst} {target_reg}, [x17]")
    else:
        lines.append(f"    mov x16, #{off}")
        lines.append(f"    add x17, {base}, x16")
        lines.append(f"    {inst} {target_reg}, [x17]")
    return lines

def emit_store(src_reg_or_imm, mem_info):
    size = mem_info['size']
    lines = []
    if not src_reg_or_imm.startswith('#') and src_reg_or_imm.startswith(('q', 'd', 's')):
        inst = 'str'
        val_reg = src_reg_or_imm
    else:
        inst = 'strb' if size == 'byte' else ('strh' if size == 'word' else ('str' if size == 'dword' else 'str'))
        if src_reg_or_imm.startswith('#'):
            imm_val = src_reg_or_imm[1:]
            lines.append(f"    mov w16, #{imm_val}")
            val_reg = 'w16' if size in ('byte', 'word', 'dword') else 'x16'
        else:
            val_reg = to_w_reg(src_reg_or_imm) if size in ('byte', 'word', 'dword') else src_reg_or_imm

    if mem_info['type'] == 'rip':
        lines.append(f"    ldr x17, ={mem_info['target']}")
        lines.append(f"    {inst} {val_reg}, [x17]")
        return lines

    base = mem_info['base']
    idx = mem_info['index']
    scale = mem_info['scale']
    off = mem_info['offset']

    scratch_off = 'x7' if src_reg_or_imm.startswith('#') else 'x16'

    if not idx and -256 <= off <= 255:
        lines.append(f"    {inst} {val_reg}, [{base}, #{off}]")
        return lines

    if idx:
        shift = {1: 0, 2: 1, 4: 2, 8: 3}.get(scale, 0)
        shift_str = f", lsl #{shift}" if shift > 0 else ""
        lines.append(f"    add x17, {base}, {idx}{shift_str}")
        if -256 <= off <= 255:
            lines.append(f"    {inst} {val_reg}, [x17, #{off}]")
        else:
            lines.append(f"    mov {scratch_off}, #{off}")
            lines.append(f"    add x17, x17, {scratch_off}")
            lines.append(f"    {inst} {val_reg}, [x17]")
    else:
        lines.append(f"    mov {scratch_off}, #{off}")
        lines.append(f"    add x17, {base}, {scratch_off}")
        lines.append(f"    {inst} {val_reg}, [x17]")
    return lines

def emit_lea(dst_reg, mem_info):
    if mem_info['type'] == 'rip':
        return [f"    ldr {dst_reg}, ={mem_info['target']}"]
    base = mem_info['base']
    idx = mem_info['index']
    scale = mem_info['scale']
    off = mem_info['offset']
    lines = []
    x_dst = to_x_reg(dst_reg)

    if not idx:
        if off == 0:
            lines.append(f"    mov {x_dst}, {base}")
        elif off > 0:
            lines.append(f"    add {x_dst}, {base}, #{off}")
        else:
            lines.append(f"    sub {x_dst}, {base}, #{-off}")
    else:
        shift = {1: 0, 2: 1, 4: 2, 8: 3}.get(scale, 0)
        shift_str = f", lsl #{shift}" if shift > 0 else ""
        lines.append(f"    add {x_dst}, {base}, {idx}{shift_str}")
        if off > 0:
            lines.append(f"    add {x_dst}, {x_dst}, #{off}")
        elif off < 0:
            lines.append(f"    sub {x_dst}, {x_dst}, #{-off}")

    if dst_reg.startswith('w'):
        lines.append(f"    uxtw {x_dst}, {dst_reg}")
    return lines

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
    asm_out.append("    mov x4, x26  /* R8  */")
    asm_out.append("    mov x5, x27  /* R9  */")
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
    asm_out.append("    sub x28, sp, #65536  /* Isolate simulated x86 stack from native ARM64 frames */")
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
        elif mnem in ('mov', 'movabs'):
            dst_str = parts[0]
            src_str = parts[1]
            if '[' in dst_str: # store
                mem_info = parse_x86_mem(dst_str, rip_target)
                src = map_operand(src_str, rip_target)
                asm_out.extend(emit_store(src, mem_info))
            elif '[' in src_str: # load
                mem_info = parse_x86_mem(src_str, rip_target)
                dst = map_reg(dst_str)
                asm_out.extend(emit_load(dst, mem_info))
            else: # reg-reg or reg-imm
                dst = map_reg(dst_str)
                src = map_operand(src_str, rip_target)
                if src.startswith('='):
                    asm_out.append(f"    ldr {dst}, {src}")
                elif src.startswith('#') and (int(src[1:]) > 65535 or int(src[1:]) < -65535):
                    asm_out.append(f"    ldr {dst}, ={src[1:]}")
                else:
                    asm_out.append(f"    mov {dst}, {src}")
        elif mnem == 'movzx':
            dst = map_reg(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load(dst, mem_info))
            else:
                src = map_reg(parts[1])
                asm_out.append(f"    uxtb {to_w_reg(dst)}, {to_w_reg(src)}")
        elif mnem in ('movsx', 'movsxd'):
            dst = map_reg(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                size = mem_info['size']
                asm_out.extend(emit_load('x16', mem_info))
                if size == 'byte':
                    dst_reg = to_w_reg(dst) if dst.startswith('w') else to_x_reg(dst)
                    asm_out.append(f"    sxtb {dst_reg}, w16")
                elif size == 'word':
                    dst_reg = to_w_reg(dst) if dst.startswith('w') else to_x_reg(dst)
                    asm_out.append(f"    sxth {dst_reg}, w16")
                else:
                    asm_out.append(f"    sxtw {to_x_reg(dst)}, w16")
            else:
                src = map_reg(parts[1])
                if parts[1].lower() in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d') or mnem == 'movsxd':
                    asm_out.append(f"    sxtw {to_x_reg(dst)}, {to_w_reg(src)}")
                elif any(parts[1].lower().endswith(x) for x in ('b', 'al', 'bl', 'cl', 'dl', 'sil', 'dil', 'bpl', 'spl')):
                    dst_reg = to_w_reg(dst) if dst.startswith('w') else to_x_reg(dst)
                    asm_out.append(f"    sxtb {dst_reg}, {to_w_reg(src)}")
                else:
                    dst_reg = to_w_reg(dst) if dst.startswith('w') else to_x_reg(dst)
                    asm_out.append(f"    sxth {dst_reg}, {to_w_reg(src)}")
        elif mnem == 'lea':
            dst = map_reg(parts[0])
            mem_info = parse_x86_mem(parts[1], rip_target)
            asm_out.extend(emit_lea(dst, mem_info))
        elif mnem == 'add':
            dst = map_reg(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('x16', mem_info))
                reg_src = 'w16' if dst.startswith('w') else 'x16'
                asm_out.append(f"    add {dst}, {dst}, {reg_src}")
            else:
                src = map_operand(parts[1])
                if src.startswith('#'):
                    imm_val = int(src[1:])
                    if imm_val < 0:
                        asm_out.append(f"    sub {dst}, {dst}, #{-imm_val}")
                    elif imm_val > 4095:
                        scratch = 'w16' if dst.startswith('w') else 'x16'
                        asm_out.append(f"    mov {scratch}, #{imm_val}")
                        asm_out.append(f"    add {dst}, {dst}, {scratch}")
                    else:
                        asm_out.append(f"    add {dst}, {dst}, {src}")
                else:
                    if dst.startswith('w'):
                        src = to_w_reg(src)
                    elif dst.startswith('x'):
                        src = to_x_reg(src)
                    asm_out.append(f"    add {dst}, {dst}, {src}")
        elif mnem == 'sub':
            dst = map_reg(parts[0])
            src = map_operand(parts[1])
            if src.startswith('#'):
                imm_val = int(src[1:])
                if imm_val < 0:
                    asm_out.append(f"    add {dst}, {dst}, #{-imm_val}")
                elif imm_val > 4095:
                    scratch = 'w16' if dst.startswith('w') else 'x16'
                    asm_out.append(f"    mov {scratch}, #{imm_val}")
                    asm_out.append(f"    sub {dst}, {dst}, {scratch}")
                else:
                    asm_out.append(f"    sub {dst}, {dst}, {src}")
            else:
                if dst.startswith('w'):
                    src = to_w_reg(src)
                elif dst.startswith('x'):
                    src = to_x_reg(src)
                asm_out.append(f"    sub {dst}, {dst}, {src}")
        elif mnem == 'sbb':
            dst = map_reg(parts[0])
            src = map_operand(parts[1])
            if src.startswith('#'):
                imm_reg = 'w16' if dst.startswith('w') else 'x16'
                asm_out.append(f"    mov {imm_reg}, {src}")
                asm_out.append(f"    sbc {dst}, {dst}, {imm_reg}")
            else:
                if dst.startswith('w'):
                    src = to_w_reg(src)
                asm_out.append(f"    sbc {dst}, {dst}, {src}")
        elif mnem == 'imul':
            dst = map_reg(parts[0])
            if len(parts) == 3:
                src = map_reg(parts[1])
                imm = map_operand(parts[2])
                asm_out.append(f"    mov w16, {imm}")
                asm_out.append(f"    mul {dst}, {src}, w16")
            else:
                src = map_operand(parts[1])
                asm_out.append(f"    mul {dst}, {dst}, {src}")
        elif mnem == 'mul':
            if len(parts) == 1:
                src = map_reg(parts[0])
                if src.startswith('w'):
                    asm_out.append(f"    umull x16, w19, {src}")
                    asm_out.append("    mov w19, w16")
                    asm_out.append("    lsr x22, x16, #32")
                else:
                    src_x = to_x_reg(src)
                    asm_out.append(f"    mul x16, x19, {src_x}")
                    asm_out.append(f"    umulh x22, x19, {src_x}")
                    asm_out.append("    mov x19, x16")
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
        elif mnem == 'shr':
            dst = map_reg(parts[0])
            src = map_operand(parts[1])
            if src.startswith('#'):
                asm_out.append(f"    lsr {dst}, {dst}, {src}")
            else:
                asm_out.append(f"    lsr {dst}, {dst}, {src}")
        elif mnem in ('shl', 'sal'):
            dst = map_reg(parts[0])
            src = map_operand(parts[1])
            asm_out.append(f"    lsl {dst}, {dst}, {src}")
        elif mnem == 'sar':
            dst = map_reg(parts[0])
            src = map_operand(parts[1])
            asm_out.append(f"    asr {dst}, {dst}, {src}")
        elif mnem == 'neg':
            dst = map_reg(parts[0])
            asm_out.append(f"    neg {dst}, {dst}")
        elif mnem == 'not':
            dst = map_reg(parts[0])
            asm_out.append(f"    mvn {dst}, {dst}")
        elif mnem == 'cmp':
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                asm_out.extend(emit_load('x16', mem_info))
                op2 = map_operand(parts[1])
                val2 = 'w16' if mem_info['size'] in ('byte', 'word', 'dword') else 'x16'
                asm_out.append(f"    cmp {val2}, {op2}")
            elif '[' in parts[1]:
                op1 = map_reg(parts[0])
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('x16', mem_info))
                val2 = 'w16' if mem_info['size'] in ('byte', 'word', 'dword') else 'x16'
                asm_out.append(f"    cmp {op1}, {val2}")
            else:
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
        elif mnem.startswith('set'):
            cond_map = {
                'sete': 'eq', 'setz': 'eq',
                'setne': 'ne', 'setnz': 'ne',
                'setl': 'lt', 'setnge': 'lt',
                'setle': 'le', 'setng': 'le',
                'setg': 'gt', 'setnle': 'gt',
                'setge': 'ge', 'setnl': 'ge',
                'seta': 'hi', 'setnbe': 'hi',
                'setae': 'hs', 'setnb': 'hs',
                'setb': 'lo', 'setnae': 'lo',
                'setbe': 'ls', 'setna': 'ls',
                'sets': 'mi', 'setns': 'pl',
            }
            cond = cond_map.get(mnem, 'al')
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                asm_out.append(f"    cset w16, {cond}")
                asm_out.extend(emit_store('w16', mem_info))
            else:
                dst = to_w_reg(map_reg(parts[0]))
                asm_out.append(f"    cset {dst}, {cond}")
        elif mnem == 'push':
            src = map_reg(parts[0])
            src_x = to_x_reg(src)
            asm_out.append(f"    str {src_x}, [x28, #-8]!")
        elif mnem == 'pop':
            dst = map_reg(parts[0])
            dst_x = to_x_reg(dst)
            asm_out.append(f"    ldr {dst_x}, [x28], #8")
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
        elif mnem in ('ja', 'jnbe'):
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.hi loc_{t_val:x}")
        elif mnem in ('jae', 'jnb'):
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.hs loc_{t_val:x}")
        elif mnem in ('jb', 'jnae'):
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.lo loc_{t_val:x}")
        elif mnem in ('jbe', 'jna'):
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.ls loc_{t_val:x}")
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
        elif mnem.startswith('cmov'):
            cond_map = {
                'cmove': 'eq', 'cmovz': 'eq',
                'cmovne': 'ne', 'cmovnz': 'ne',
                'cmovl': 'lt', 'cmovnge': 'lt',
                'cmovle': 'le', 'cmovng': 'le',
                'cmovg': 'gt', 'cmovnle': 'gt',
                'cmovge': 'ge', 'cmovnl': 'ge',
                'cmova': 'hi', 'cmovnbe': 'hi',
                'cmovae': 'hs', 'cmovnb': 'hs',
                'cmovb': 'lo', 'cmovnae': 'lo',
                'cmovbe': 'ls', 'cmovna': 'ls',
                'cmovs': 'mi', 'cmovns': 'pl',
            }
            cond = cond_map.get(mnem, 'al')
            dst = map_reg(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('x16', mem_info))
                src = 'w16' if dst.startswith('w') else 'x16'
            else:
                src = map_reg(parts[1])
                if dst.startswith('w'): src = to_w_reg(src)
                elif dst.startswith('x'): src = to_x_reg(src)
            asm_out.append(f"    csel {dst}, {src}, {dst}, {cond}")
        elif mnem in ('movaps', 'movups', 'movdqa', 'movdqu'):
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                src = xmm_to_q(parts[1])
                asm_out.extend(emit_store(src, mem_info))
            elif '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                dst = xmm_to_q(parts[0])
                asm_out.extend(emit_load(dst, mem_info))
            else:
                dst = xmm_to_v(parts[0])
                src = xmm_to_v(parts[1])
                asm_out.append(f"    mov {dst}, {src}")
        elif mnem == 'movd':
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                src = xmm_to_s(parts[1]) if is_xmm(parts[1]) else map_reg(parts[1])
                asm_out.extend(emit_store(src, mem_info))
            elif '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                dst = xmm_to_s(parts[0]) if is_xmm(parts[0]) else map_reg(parts[0])
                asm_out.extend(emit_load(dst, mem_info))
            else:
                if is_xmm(parts[0]):
                    dst_s = xmm_to_s(parts[0])
                    src_w = to_w_reg(map_reg(parts[1]))
                    asm_out.append(f"    fmov {dst_s}, {src_w}")
                else:
                    dst_w = to_w_reg(map_reg(parts[0]))
                    src_s = xmm_to_s(parts[1])
                    asm_out.append(f"    fmov {dst_w}, {src_s}")
        elif mnem == 'movq':
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                src = xmm_to_d(parts[1]) if is_xmm(parts[1]) else map_reg(parts[1])
                asm_out.extend(emit_store(src, mem_info))
            elif '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                dst = xmm_to_d(parts[0]) if is_xmm(parts[0]) else map_reg(parts[0])
                asm_out.extend(emit_load(dst, mem_info))
            else:
                if is_xmm(parts[0]) and is_xmm(parts[1]):
                    dst_d = xmm_to_d(parts[0])
                    src_d = xmm_to_d(parts[1])
                    asm_out.append(f"    fmov {dst_d}, {src_d}")
                elif is_xmm(parts[0]):
                    dst_d = xmm_to_d(parts[0])
                    src_x = to_x_reg(map_reg(parts[1]))
                    asm_out.append(f"    fmov {dst_d}, {src_x}")
                else:
                    dst_x = to_x_reg(map_reg(parts[0]))
                    src_d = xmm_to_d(parts[1])
                    asm_out.append(f"    fmov {dst_x}, {src_d}")
        elif mnem == 'movss':
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                asm_out.extend(emit_store(xmm_to_s(parts[1]), mem_info))
            elif '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load(xmm_to_s(parts[0]), mem_info))
            else:
                asm_out.append(f"    fmov {xmm_to_s(parts[0])}, {xmm_to_s(parts[1])}")
        elif mnem == 'movsd':
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                asm_out.extend(emit_store(xmm_to_d(parts[1]), mem_info))
            elif '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load(xmm_to_d(parts[0]), mem_info))
            else:
                asm_out.append(f"    fmov {xmm_to_d(parts[0])}, {xmm_to_d(parts[1])}")
        elif mnem in ('pxor', 'xorps', 'xorpd'):
            dst_v = xmm_to_v(parts[0])
            if parts[0] == parts[1]:
                asm_out.append(f"    movi {dst_v}, #0")
            elif '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('q16', mem_info))
                asm_out.append(f"    eor {dst_v}, {dst_v}, v16.16b")
            else:
                src_v = xmm_to_v(parts[1])
                asm_out.append(f"    eor {dst_v}, {dst_v}, {src_v}")
        elif mnem in ('por', 'orps', 'orpd'):
            dst_v = xmm_to_v(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('q16', mem_info))
                asm_out.append(f"    orr {dst_v}, {dst_v}, v16.16b")
            else:
                src_v = xmm_to_v(parts[1])
                asm_out.append(f"    orr {dst_v}, {dst_v}, {src_v}")
        elif mnem in ('pand', 'andps', 'andpd'):
            dst_v = xmm_to_v(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('q16', mem_info))
                asm_out.append(f"    and {dst_v}, {dst_v}, v16.16b")
            else:
                src_v = xmm_to_v(parts[1])
                asm_out.append(f"    and {dst_v}, {dst_v}, {src_v}")
        elif mnem in ('pandn', 'andnps', 'andnpd'):
            dst_v = xmm_to_v(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('q16', mem_info))
                asm_out.append(f"    bic {dst_v}, v16.16b, {dst_v}")
            else:
                src_v = xmm_to_v(parts[1])
                asm_out.append(f"    bic {dst_v}, {src_v}, {dst_v}")
        elif mnem in ('paddb', 'paddw', 'paddd', 'paddq'):
            arr = {'paddb': '16b', 'paddw': '8h', 'paddd': '4s', 'paddq': '2d'}[mnem]
            dst_v = xmm_to_v(parts[0], arr)
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('q16', mem_info))
                asm_out.append(f"    add {dst_v}, {dst_v}, v16.{arr}")
            else:
                src_v = xmm_to_v(parts[1], arr)
                asm_out.append(f"    add {dst_v}, {dst_v}, {src_v}")
        elif mnem in ('psubb', 'psubw', 'psubd', 'psubq'):
            arr = {'psubb': '16b', 'psubw': '8h', 'psubd': '4s', 'psubq': '2d'}[mnem]
            dst_v = xmm_to_v(parts[0], arr)
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('q16', mem_info))
                asm_out.append(f"    sub {dst_v}, {dst_v}, v16.{arr}")
            else:
                src_v = xmm_to_v(parts[1], arr)
                asm_out.append(f"    sub {dst_v}, {dst_v}, {src_v}")
        elif mnem in ('pcmpeqb', 'pcmpeqw', 'pcmpeqd'):
            arr = {'pcmpeqb': '16b', 'pcmpeqw': '8h', 'pcmpeqd': '4s'}[mnem]
            dst_v = xmm_to_v(parts[0], arr)
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('q16', mem_info))
                asm_out.append(f"    cmeq {dst_v}, {dst_v}, v16.{arr}")
            else:
                src_v = xmm_to_v(parts[1], arr)
                asm_out.append(f"    cmeq {dst_v}, {dst_v}, {src_v}")
        elif mnem == 'punpcklbw':
            dst_v = xmm_to_v(parts[0], '16b')
            src_v = xmm_to_v(parts[1], '16b')
            asm_out.append(f"    zip1 {dst_v}, {dst_v}, {src_v}")
        elif mnem == 'punpckhbw':
            dst_v = xmm_to_v(parts[0], '16b')
            src_v = xmm_to_v(parts[1], '16b')
            asm_out.append(f"    zip2 {dst_v}, {dst_v}, {src_v}")
        elif mnem == 'punpcklwd':
            dst_v = xmm_to_v(parts[0], '8h')
            src_v = xmm_to_v(parts[1], '8h')
            asm_out.append(f"    zip1 {dst_v}, {dst_v}, {src_v}")
        elif mnem == 'punpckhwd':
            dst_v = xmm_to_v(parts[0], '8h')
            src_v = xmm_to_v(parts[1], '8h')
            asm_out.append(f"    zip2 {dst_v}, {dst_v}, {src_v}")
        elif mnem == 'punpckldq':
            dst_v = xmm_to_v(parts[0], '4s')
            src_v = xmm_to_v(parts[1], '4s')
            asm_out.append(f"    zip1 {dst_v}, {dst_v}, {src_v}")
        elif mnem == 'punpckhdq':
            dst_v = xmm_to_v(parts[0], '4s')
            src_v = xmm_to_v(parts[1], '4s')
            asm_out.append(f"    zip2 {dst_v}, {dst_v}, {src_v}")
        elif mnem == 'packuswb':
            dst_base = xmm_to_v(parts[0]).split('.')[0]
            src_base = xmm_to_v(parts[1]).split('.')[0]
            asm_out.append(f"    sqxtun {dst_base}.8b, {dst_base}.8h")
            asm_out.append(f"    sqxtun2 {dst_base}.16b, {src_base}.8h")
        elif mnem == 'pshufd':
            dst_base = xmm_to_v(parts[0]).split('.')[0]
            src_base = xmm_to_v(parts[1]).split('.')[0]
            imm_str = parts[2].split()[0].strip()
            imm = int(imm_str, 16) if '0x' in imm_str.lower() else int(imm_str)
            if imm == 0x00:
                asm_out.append(f"    dup {dst_base}.4s, {src_base}.s[0]")
            elif imm == 0x55:
                asm_out.append(f"    dup {dst_base}.4s, {src_base}.s[1]")
            elif imm == 0xaa:
                asm_out.append(f"    dup {dst_base}.4s, {src_base}.s[2]")
            elif imm == 0xff:
                asm_out.append(f"    dup {dst_base}.4s, {src_base}.s[3]")
            elif imm == 0x4e:
                asm_out.append(f"    ext {dst_base}.16b, {src_base}.16b, {src_base}.16b, #8")
            else:
                if dst_base == src_base:
                    asm_out.append(f"    mov v16.16b, {src_base}.16b")
                    s_reg = "v16"
                else:
                    s_reg = src_base
                for lane in range(4):
                    src_lane = (imm >> (lane * 2)) & 3
                    asm_out.append(f"    mov {dst_base}.s[{lane}], {s_reg}.s[{src_lane}]")
        elif mnem == 'pshuflw':
            dst_base = xmm_to_v(parts[0]).split('.')[0]
            src_base = xmm_to_v(parts[1]).split('.')[0]
            imm_str = parts[2].split()[0].strip()
            imm = int(imm_str, 16) if '0x' in imm_str.lower() else int(imm_str)
            if dst_base != src_base:
                asm_out.append(f"    mov {dst_base}.16b, {src_base}.16b")
                s_reg = dst_base
            else:
                asm_out.append(f"    mov v16.16b, {src_base}.16b")
                s_reg = "v16"
            for lane in range(4):
                src_lane = (imm >> (lane * 2)) & 3
                asm_out.append(f"    mov {dst_base}.h[{lane}], {s_reg}.h[{src_lane}]")
        elif mnem == 'pshufhw':
            dst_base = xmm_to_v(parts[0]).split('.')[0]
            src_base = xmm_to_v(parts[1]).split('.')[0]
            imm_str = parts[2].split()[0].strip()
            imm = int(imm_str, 16) if '0x' in imm_str.lower() else int(imm_str)
            if dst_base != src_base:
                asm_out.append(f"    mov {dst_base}.16b, {src_base}.16b")
                s_reg = dst_base
            else:
                asm_out.append(f"    mov v16.16b, {src_base}.16b")
                s_reg = "v16"
            for lane in range(4):
                src_lane = 4 + ((imm >> (lane * 2)) & 3)
                asm_out.append(f"    mov {dst_base}.h[{4 + lane}], {s_reg}.h[{src_lane}]")
        elif mnem in ('addss', 'subss', 'mulss', 'divss'):
            f_op = {'addss': 'fadd', 'subss': 'fsub', 'mulss': 'fmul', 'divss': 'fdiv'}[mnem]
            dst_s = xmm_to_s(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('s16', mem_info))
                asm_out.append(f"    {f_op} {dst_s}, {dst_s}, s16")
            else:
                src_s = xmm_to_s(parts[1])
                asm_out.append(f"    {f_op} {dst_s}, {dst_s}, {src_s}")
        elif mnem in ('addsd', 'subsd', 'mulsd', 'divsd'):
            f_op = {'addsd': 'fadd', 'subsd': 'fsub', 'mulsd': 'fmul', 'divsd': 'fdiv'}[mnem]
            dst_d = xmm_to_d(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('d16', mem_info))
                asm_out.append(f"    {f_op} {dst_d}, {dst_d}, d16")
            else:
                src_d = xmm_to_d(parts[1])
                asm_out.append(f"    {f_op} {dst_d}, {dst_d}, {src_d}")
        elif mnem == 'cvtsi2ss':
            dst_s = xmm_to_s(parts[0])
            src = map_operand(parts[1])
            src_reg = to_w_reg(src) if src.startswith('w') or not src.startswith('x') else src
            asm_out.append(f"    scvtf {dst_s}, {src_reg}")
        elif mnem == 'cvtsi2sd':
            dst_d = xmm_to_d(parts[0])
            src = map_operand(parts[1])
            src_reg = to_w_reg(src) if src.startswith('w') or not src.startswith('x') else src
            asm_out.append(f"    scvtf {dst_d}, {src_reg}")
        elif mnem == 'cvttss2si':
            dst = map_reg(parts[0])
            src_s = xmm_to_s(parts[1])
            asm_out.append(f"    fcvtzs {dst}, {src_s}")
        elif mnem == 'cvttsd2si':
            dst = map_reg(parts[0])
            src_d = xmm_to_d(parts[1])
            asm_out.append(f"    fcvtzs {dst}, {src_d}")
        elif mnem == 'ucomiss':
            s1 = xmm_to_s(parts[0])
            s2 = xmm_to_s(parts[1])
            asm_out.append(f"    fcmp {s1}, {s2}")
        elif mnem == 'ucomisd':
            d1 = xmm_to_d(parts[0])
            d2 = xmm_to_d(parts[1])
            asm_out.append(f"    fcmp {d1}, {d2}")
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
