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

BYTE_REGS = {'al', 'bl', 'cl', 'dl', 'sil', 'dil', 'bpl', 'spl',
             'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b',
             'ah', 'bh', 'ch', 'dh'}
WORD_REGS = {'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp',
             'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w'}


SYSCALL_MAP = {
    0: 63,    # read
    1: 64,    # write
    2: 56,    # open -> openat
    3: 57,    # close
    4: 79,    # stat -> newfstatat
    5: 80,    # fstat
    7: 73,    # poll -> ppoll
    8: 62,    # lseek
    9: 222,   # mmap
    10: 226,  # mprotect
    11: 215,  # munmap
    12: 214,  # brk
    13: 134,  # rt_sigaction
    14: 135,  # rt_sigprocmask
    16: 29,   # ioctl
    17: 67,   # pread64
    18: 68,   # pwrite64
    19: 65,   # readv
    20: 66,   # writev
    21: 48,   # access -> faccessat
    22: 59,   # pipe -> pipe2
    24: 124,  # sched_yield
    32: 23,   # dup
    33: 24,   # dup2 -> dup3
    39: 172,  # getpid
    40: 71,   # sendfile
    41: 198,  # socket
    42: 203,  # connect
    60: 93,   # exit
    63: 160,  # uname
    72: 25,   # fcntl
    79: 17,   # getcwd
    80: 49,   # chdir
    82: 128,  # rename -> renameat
    83: 34,   # mkdir -> mkdirat
    84: 35,   # rmdir -> unlinkat
    87: 35,   # unlink -> unlinkat
    89: 54,   # readlink -> readlinkat
    96: 169,  # gettimeofday
    97: 163,  # getrlimit
    102: 174, # getuid
    104: 176, # getgid
    105: 146, # setuid
    106: 144, # setgid
    107: 175, # geteuid
    108: 177, # getegid
    109: 154, # setpgid
    110: 173, # getppid
    111: 155, # getpgrp
    112: 157, # setsid
    113: 145, # setreuid
    114: 143, # setregid
    115: 158, # getgroups
    116: 159, # setgroups
    117: 147, # setresuid
    118: 148, # getresuid
    119: 149, # setresgid
    120: 150, # getresgid
    121: 155, # getpgid
    137: 43,  # statfs
    138: 44,  # fstatfs
    157: 167, # prctl
    158: 167, # arch_prctl
    160: 164, # setrlimit
    186: 178, # gettid
    202: 98,  # futex
    218: 96,  # set_tid_address
    228: 113, # clock_gettime
    231: 94,  # exit_group
    254: 27,  # inotify_add_watch
    255: 28,  # inotify_rm_watch
    257: 56,  # openat
    262: 79,  # newfstatat
    280: 88,  # utimensat
    285: 47,  # fallocate
    290: 85,  # timerfd_create
    293: 59,  # pipe2
    294: 26,  # inotify_init1
    302: 261, # prlimit64
    306: 267, # syncfs
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
        if line.startswith('Disassembly of section '):
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
    elif 'tbyte ptr' in lower: size = 'tbyte'

    is_fs = 'fs:' in lower
    clean_mem = re.sub(r'fs:\s*', '', mem_str, flags=re.IGNORECASE)
    inner = clean_mem[clean_mem.index('[')+1 : clean_mem.index(']')].strip()
    
    if 'rip' in inner.lower() and rip_target is not None:
        return {'type': 'rip', 'size': size, 'target': f"data_{rip_target:x}", 'target_addr': rip_target, 'is_fs': False}

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
        'base': base_reg,
        'index': idx_reg,
        'scale': scale,
        'offset': imm_offset,
        'is_fs': is_fs
    }

def emit_load_imm(reg, val):
    try:
        if isinstance(val, str):
            s = val.strip()
            if s.startswith('='):
                s = s[1:]
            if s.startswith('#'):
                s = s[1:]
            num = int(s, 0)
        else:
            num = int(val)
    except (ValueError, TypeError):
        sym = str(val).strip()
        if sym.startswith('='):
            sym = sym[1:]
        if sym.startswith('data_'):
            reg_x = to_x_reg(reg)
            lines = [
                f"    adrp {reg_x}, {sym}",
                f"    add {reg_x}, {reg_x}, :lo12:{sym}"
            ]
            if reg.startswith('w'):
                lines.append(f"    mov {reg}, {to_w_reg(reg_x)}")
            return lines
        return [f"    ldr {reg}, ={sym}"]

    if not reg.startswith(('w', 'x')):
        return [f"    ldr {reg}, ={val}"]

    is_64 = reg.startswith('x')
    if not is_64:
        num = num & 0xffffffff
        h0 = num & 0xffff
        h1 = (num >> 16) & 0xffff
        if h1 == 0:
            return [f"    mov {reg}, #{h0}"]
        elif h0 == 0:
            return [f"    movz {reg}, #{h1}, lsl #16"]
        elif (~num & 0xffffffff) <= 0xffff:
            return [f"    movn {reg}, #{(~num) & 0xffff}"]
        else:
            return [f"    movz {reg}, #{h0}", f"    movk {reg}, #{h1}, lsl #16"]
    else:
        num = num & 0xffffffffffffffff
        chunks = [(num >> (i * 16)) & 0xffff for i in range(4)]
        non_zeros = [(i, c) for i, c in enumerate(chunks) if c != 0]
        if len(non_zeros) == 0:
            return [f"    mov {reg}, #0"]
        if len(non_zeros) == 1:
            idx, c = non_zeros[0]
            if idx == 0:
                return [f"    mov {reg}, #{c}"]
            else:
                return [f"    movz {reg}, #{c}, lsl #{idx * 16}"]
        inv_num = (~num) & 0xffffffffffffffff
        inv_chunks = [(inv_num >> (i * 16)) & 0xffff for i in range(4)]
        inv_non_zeros = [(i, c) for i, c in enumerate(inv_chunks) if c != 0]
        if len(inv_non_zeros) == 1:
            idx, c = inv_non_zeros[0]
            if idx == 0:
                return [f"    movn {reg}, #{c}"]
            else:
                return [f"    movn {reg}, #{c}, lsl #{idx * 16}"]
        lines = []
        first = True
        for idx, c in enumerate(chunks):
            if c != 0:
                if first:
                    shift = f", lsl #{idx * 16}" if idx > 0 else ""
                    lines.append(f"    movz {reg}, #{c}{shift}")
                    first = False
                else:
                    lines.append(f"    movk {reg}, #{c}, lsl #{idx * 16}")
        return lines

def emit_load(dst_reg, mem_info):
    size = mem_info['size']
    if dst_reg.startswith(('q', 'd', 's')):
        inst = 'ldr'
        target_reg = dst_reg
    else:
        inst = 'ldrb' if size == 'byte' else ('ldrh' if size == 'word' else ('ldr' if size == 'dword' else 'ldr'))
        target_reg = to_w_reg(dst_reg) if size in ('byte', 'word', 'dword') else dst_reg

    if mem_info['type'] == 'rip':
        return [f"    adrp x16, {mem_info['target']}",
                f"    add x16, x16, :lo12:{mem_info['target']}",
                f"    {inst} {target_reg}, [x16]"]

    lines = []
    base = mem_info['base']
    if mem_info.get('is_fs'):
        lines.append("    mrs x17, tpidr_el0")
        base = 'x17'

    idx = mem_info['index']
    scale = mem_info['scale']
    off = mem_info['offset']

    if base is None:
        lines = []
        if idx:
            shift = {1: 0, 2: 1, 4: 2, 8: 3}.get(scale, 0)
            shift_str = f", lsl #{shift}" if shift > 0 else ""
            lines.extend(emit_load_imm("x17", off))
            lines.append(f"    add x17, x17, {idx}{shift_str}")
            lines.append(f"    {inst} {target_reg}, [x17]")
        else:
            lines.extend(emit_load_imm("x17", off))
            lines.append(f"    {inst} {target_reg}, [x17]")
        return lines

    if not idx and -256 <= off <= 255:
        return lines + [f"    {inst} {target_reg}, [{base}, #{off}]"]

    if idx:
        shift = {1: 0, 2: 1, 4: 2, 8: 3}.get(scale, 0)
        shift_str = f", lsl #{shift}" if shift > 0 else ""
        lines.append(f"    add x17, {base}, {idx}{shift_str}")
        if -256 <= off <= 255:
            lines.append(f"    {inst} {target_reg}, [x17, #{off}]")
        else:
            lines.extend(emit_load_imm("x7", off))
            lines.append(f"    add x17, x17, x7")
            lines.append(f"    {inst} {target_reg}, [x17]")
    else:
        lines.extend(emit_load_imm("x7", off))
        lines.append(f"    add x17, {base}, x7")
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
            scratch = 'w16' if size in ('byte', 'word', 'dword') else 'x16'
            lines.extend(emit_load_imm(scratch, imm_val))
            val_reg = scratch
        else:
            val_reg = to_w_reg(src_reg_or_imm) if size in ('byte', 'word', 'dword') else src_reg_or_imm

    if mem_info['type'] == 'rip':
        lines.append(f"    adrp x17, {mem_info['target']}")
        lines.append(f"    add x17, x17, :lo12:{mem_info['target']}")
        lines.append(f"    {inst} {val_reg}, [x17]")
        return lines

    base = mem_info['base']
    if mem_info.get('is_fs'):
        lines.append("    mrs x17, tpidr_el0")
        base = 'x17'

    idx = mem_info['index']
    scale = mem_info['scale']
    off = mem_info['offset']

    if base is None:
        if idx:
            shift = {1: 0, 2: 1, 4: 2, 8: 3}.get(scale, 0)
            shift_str = f", lsl #{shift}" if shift > 0 else ""
            lines.extend(emit_load_imm("x17", off))
            lines.append(f"    add x17, x17, {idx}{shift_str}")
            lines.append(f"    {inst} {val_reg}, [x17]")
        else:
            lines.extend(emit_load_imm("x17", off))
            lines.append(f"    {inst} {val_reg}, [x17]")
        return lines

    scratch_off = 'x7'

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
            lines.extend(emit_load_imm(scratch_off, off))
            lines.append(f"    add x17, x17, {scratch_off}")
            lines.append(f"    {inst} {val_reg}, [x17]")
    else:
        lines.extend(emit_load_imm(scratch_off, off))
        lines.append(f"    add x17, {base}, {scratch_off}")
        lines.append(f"    {inst} {val_reg}, [x17]")
    return lines

def emit_lea(dst_reg, mem_info):
    if mem_info['type'] == 'rip':
        if mem_info.get('target_addr') == 0:
            return [f"    mov {to_x_reg(dst_reg)}, #0"]
        x_dst = to_x_reg(dst_reg)
        lines = [f"    adrp {x_dst}, {mem_info['target']}",
                 f"    add {x_dst}, {x_dst}, :lo12:{mem_info['target']}"]
        if dst_reg.startswith('w'):
            lines.append(f"    uxtw {x_dst}, {dst_reg}")
        return lines
    x_dst = to_x_reg(dst_reg)
    off = mem_info['offset']
    if mem_info.get('is_fs'):
        lines = ["    mrs x17, tpidr_el0"]
        if off != 0:
            lines.append(f"    add {x_dst}, x17, #{off}")
        else:
            lines.append(f"    mov {x_dst}, x17")
        return lines
    base = mem_info['base']
    idx = mem_info['index']
    scale = mem_info['scale']
    lines = []

    if base is None:
        if idx:
            shift = {1: 0, 2: 1, 4: 2, 8: 3}.get(scale, 0)
            shift_str = f", lsl #{shift}" if shift > 0 else ""
            if off == 0:
                if shift > 0:
                    lines = [f"    lsl {x_dst}, {idx}, #{shift}"]
                else:
                    lines = [f"    mov {x_dst}, {idx}"]
            elif 0 < off <= 4095:
                if shift > 0:
                    lines = [f"    lsl {x_dst}, {idx}, #{shift}",
                             f"    add {x_dst}, {x_dst}, #{off}"]
                else:
                    lines = [f"    add {x_dst}, {idx}, #{off}"]
            elif -4095 <= off < 0:
                if shift > 0:
                    lines = [f"    lsl {x_dst}, {idx}, #{shift}",
                             f"    sub {x_dst}, {x_dst}, #{-off}"]
                else:
                    lines = [f"    sub {x_dst}, {idx}, #{-off}"]
            else:
                lines = emit_load_imm("x16", off) + [
                    f"    add {x_dst}, x16, {idx}{shift_str}"
                ]
        else:
            lines = emit_load_imm(x_dst, off)
        if dst_reg.startswith('w'):
            lines.append(f"    uxtw {x_dst}, {dst_reg}")
        return lines

    if not idx:
        if off == 0:
            lines.append(f"    mov {x_dst}, {base}")
        elif 0 < off <= 4095:
            lines.append(f"    add {x_dst}, {base}, #{off}")
        elif -4095 <= off < 0:
            lines.append(f"    sub {x_dst}, {base}, #{-off}")
        else:
            lines.extend(emit_load_imm("x16", off))
            lines.append(f"    add {x_dst}, {base}, x16")
    else:
        shift = {1: 0, 2: 1, 4: 2, 8: 3}.get(scale, 0)
        shift_str = f", lsl #{shift}" if shift > 0 else ""
        lines.append(f"    add {x_dst}, {base}, {idx}{shift_str}")
        if 0 < off <= 4095:
            lines.append(f"    add {x_dst}, {x_dst}, #{off}")
        elif -4095 <= off < 0:
            lines.append(f"    sub {x_dst}, {x_dst}, #{-off}")
        elif off != 0:
            lines.extend(emit_load_imm("x16", off))
            lines.append(f"    add {x_dst}, {x_dst}, x16")

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

    all_instruction_addrs = set(addr for addr, _, _, _ in instructions)

    asm_out = []
    asm_out.append("/* Auto-generated AArch64 Assembly by LinuxNative AOT Transpiler */")
    asm_out.append(".global _start")
    asm_out.append(".text")
    asm_out.append(".align 4\n")

    # Syscall adapter
    asm_out.append("/* x86_64 Syscall Translation Adapter */")
    asm_out.append(".type x86_syscall_adapter, %function")
    asm_out.append("x86_syscall_adapter:")
    asm_out.append("    stp x28, x30, [sp, #-32]!")
    asm_out.append("    str x29, [sp, #16]")
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
    asm_out.append("    mov x0, #-38 /* -ENOSYS */")
    asm_out.append("    mov x19, x0")
    asm_out.append("    ldr x29, [sp, #16]")
    asm_out.append("    ldp x28, x30, [sp], #32")
    asm_out.append("    ret")
    asm_out.append("")

    for x86_nr, arm_nr in SYSCALL_MAP.items():
        asm_out.append(f".sys_{x86_nr}:")
        if x86_nr == 2: # open -> openat(AT_FDCWD, path, flags, mode)
            asm_out.append("    mov x3, x2")
            asm_out.append("    mov x2, x1")
            asm_out.append("    mov x1, x0")
            asm_out.append("    mov x0, #-100 /* AT_FDCWD */")
        elif x86_nr == 21: # access -> faccessat(AT_FDCWD, path, mode, 0)
            asm_out.append("    mov x3, #0")
            asm_out.append("    mov x2, x1")
            asm_out.append("    mov x1, x0")
            asm_out.append("    mov x0, #-100 /* AT_FDCWD */")
        elif x86_nr == 33: # dup2 -> dup3(old, new, 0)
            asm_out.append("    mov x2, #0")
        elif x86_nr == 83: # mkdir -> mkdirat(AT_FDCWD, path, mode)
            asm_out.append("    mov x2, x1")
            asm_out.append("    mov x1, x0")
            asm_out.append("    mov x0, #-100 /* AT_FDCWD */")
        elif x86_nr in (84, 87): # unlink -> unlinkat(AT_FDCWD, path, 0)
            asm_out.append("    mov x2, #0")
            asm_out.append("    mov x1, x0")
            asm_out.append("    mov x0, #-100 /* AT_FDCWD */")
        elif x86_nr == 89: # readlink -> readlinkat(AT_FDCWD, path, buf, sz)
            asm_out.append("    mov x3, x2")
            asm_out.append("    mov x2, x1")
            asm_out.append("    mov x1, x0")
            asm_out.append("    mov x0, #-100 /* AT_FDCWD */")
        elif x86_nr == 105: # setuid(uid)
            asm_out.append("    mov x8, #174 /* getuid */")
            asm_out.append("    svc #0")
            asm_out.append("    cmp x24, x0")
            asm_out.append("    b.eq 1f")
            asm_out.append("    mov x0, #-1 /* -EPERM */")
            asm_out.append("    b 2f")
            asm_out.append("1:")
            asm_out.append("    mov x0, #0")
            asm_out.append("2:")
            asm_out.append("    mov x19, x0")
            asm_out.append("    ldr x29, [sp, #16]")
            asm_out.append("    ldp x28, x30, [sp], #32")
            asm_out.append("    ret")
            continue
        elif x86_nr == 106: # setgid(gid)
            asm_out.append("    mov x8, #176 /* getgid */")
            asm_out.append("    svc #0")
            asm_out.append("    cmp x24, x0")
            asm_out.append("    b.eq 1f")
            asm_out.append("    mov x0, #-1 /* -EPERM */")
            asm_out.append("    b 2f")
            asm_out.append("1:")
            asm_out.append("    mov x0, #0")
            asm_out.append("2:")
            asm_out.append("    mov x19, x0")
            asm_out.append("    ldr x29, [sp, #16]")
            asm_out.append("    ldp x28, x30, [sp], #32")
            asm_out.append("    ret")
            continue
        elif x86_nr == 113: # setreuid(ruid, euid)
            asm_out.append("    mov x8, #174 /* getuid */")
            asm_out.append("    svc #0")
            asm_out.append("    mov x6, x0")
            asm_out.append("    mov x8, #175 /* geteuid */")
            asm_out.append("    svc #0")
            asm_out.append("    cmn x24, #1")
            asm_out.append("    b.eq 1f")
            asm_out.append("    cmp x24, x6")
            asm_out.append("    b.ne 3f")
            asm_out.append("1:")
            asm_out.append("    cmn x23, #1")
            asm_out.append("    b.eq 2f")
            asm_out.append("    cmp x23, x0")
            asm_out.append("    b.ne 3f")
            asm_out.append("2:")
            asm_out.append("    mov x0, #0")
            asm_out.append("    b 4f")
            asm_out.append("3:")
            asm_out.append("    mov x0, #-1 /* -EPERM */")
            asm_out.append("4:")
            asm_out.append("    mov x19, x0")
            asm_out.append("    ldr x29, [sp, #16]")
            asm_out.append("    ldp x28, x30, [sp], #32")
            asm_out.append("    ret")
            continue
        elif x86_nr == 114: # setregid(rgid, egid)
            asm_out.append("    mov x8, #176 /* getgid */")
            asm_out.append("    svc #0")
            asm_out.append("    mov x6, x0")
            asm_out.append("    mov x8, #177 /* getegid */")
            asm_out.append("    svc #0")
            asm_out.append("    cmn x24, #1")
            asm_out.append("    b.eq 1f")
            asm_out.append("    cmp x24, x6")
            asm_out.append("    b.ne 3f")
            asm_out.append("1:")
            asm_out.append("    cmn x23, #1")
            asm_out.append("    b.eq 2f")
            asm_out.append("    cmp x23, x0")
            asm_out.append("    b.ne 3f")
            asm_out.append("2:")
            asm_out.append("    mov x0, #0")
            asm_out.append("    b 4f")
            asm_out.append("3:")
            asm_out.append("    mov x0, #-1 /* -EPERM */")
            asm_out.append("4:")
            asm_out.append("    mov x19, x0")
            asm_out.append("    ldr x29, [sp, #16]")
            asm_out.append("    ldp x28, x30, [sp], #32")
            asm_out.append("    ret")
            continue
        elif x86_nr == 116: # setgroups(size, list)
            asm_out.append("    cmp x24, #0")
            asm_out.append("    b.eq 1f")
            asm_out.append("    mov x0, #-1 /* -EPERM */")
            asm_out.append("    b 2f")
            asm_out.append("1:")
            asm_out.append("    mov x0, #0")
            asm_out.append("2:")
            asm_out.append("    mov x19, x0")
            asm_out.append("    ldr x29, [sp, #16]")
            asm_out.append("    ldp x28, x30, [sp], #32")
            asm_out.append("    ret")
            continue
        elif x86_nr == 117: # setresuid(ruid, euid, suid)
            asm_out.append("    mov x8, #174 /* getuid */")
            asm_out.append("    svc #0")
            asm_out.append("    cmp x24, x0")
            asm_out.append("    b.eq 1f")
            asm_out.append("    mov x0, #-1 /* -EPERM */")
            asm_out.append("    b 2f")
            asm_out.append("1:")
            asm_out.append("    mov x0, #0")
            asm_out.append("2:")
            asm_out.append("    mov x19, x0")
            asm_out.append("    ldr x29, [sp, #16]")
            asm_out.append("    ldp x28, x30, [sp], #32")
            asm_out.append("    ret")
            continue
        elif x86_nr == 119: # setresgid(rgid, egid, sgid)
            asm_out.append("    mov x8, #176 /* getgid */")
            asm_out.append("    svc #0")
            asm_out.append("    cmp x24, x0")
            asm_out.append("    b.eq 1f")
            asm_out.append("    mov x0, #-1 /* -EPERM */")
            asm_out.append("    b 2f")
            asm_out.append("1:")
            asm_out.append("    mov x0, #0")
            asm_out.append("2:")
            asm_out.append("    mov x19, x0")
            asm_out.append("    ldr x29, [sp, #16]")
            asm_out.append("    ldp x28, x30, [sp], #32")
            asm_out.append("    ret")
            continue
        elif x86_nr == 158: # arch_prctl(code, addr)
            asm_out.append("    mov x16, #0x1002 /* ARCH_SET_FS */")
            asm_out.append("    cmp x0, x16")
            asm_out.append("    b.ne 1f")
            asm_out.append("    msr tpidr_el0, x1")
            asm_out.append("    mov x0, #0")
            asm_out.append("    b 3f")
            asm_out.append("1:")
            asm_out.append("    mov x16, #0x1003 /* ARCH_GET_FS */")
            asm_out.append("    cmp x0, x16")
            asm_out.append("    b.ne 2f")
            asm_out.append("    mrs x16, tpidr_el0")
            asm_out.append("    str x16, [x1]")
            asm_out.append("    mov x0, #0")
            asm_out.append("    b 3f")
            asm_out.append("2:")
            asm_out.append("    mov x0, #-22 /* -EINVAL */")
            asm_out.append("3:")
            asm_out.append("    mov x19, x0")
            asm_out.append("    ldr x29, [sp, #16]")
            asm_out.append("    ldp x28, x30, [sp], #32")
            asm_out.append("    ret")
            continue

        asm_out.append(f"    mov x8, #{arm_nr}")
        asm_out.append("    svc #0")
        asm_out.append("    mov x19, x0")
        asm_out.append("    ldr x29, [sp, #16]")
        asm_out.append("    ldp x28, x30, [sp], #32")
        asm_out.append("    ret")
        asm_out.append("")

    # Indirect Call & Jump Dispatcher
    asm_out.append("/* Indirect Call & Jump Dispatcher */")
    asm_out.append(".type x86_indirect_dispatcher, %function")
    asm_out.append("x86_indirect_dispatcher:")
    min_x86_code = min(addr for addr, _, _, _ in instructions)
    max_x86_code = max(addr for addr, _, _, _ in instructions) + 16
    asm_out.extend(emit_load_imm("x5", min_x86_code))
    asm_out.append("    cmp x16, x5")
    asm_out.append("    b.lo .Ldirect_dispatch")
    asm_out.extend(emit_load_imm("x5", max_x86_code))
    asm_out.append("    cmp x16, x5")
    asm_out.append("    b.hi .Ldirect_dispatch")
    asm_out.append("    adrp x17, x86_dispatch_table")
    asm_out.append("    add x17, x17, :lo12:x86_dispatch_table")
    asm_out.append("    mov x18, #0")
    asm_out.extend(emit_load_imm("x8", len(instructions) - 1))
    asm_out.append(".Lbinsearch_loop:")
    asm_out.append("    cmp x18, x8")
    asm_out.append("    b.gt .Lnot_found")
    asm_out.append("    add x7, x18, x8")
    asm_out.append("    lsr x7, x7, #1")
    asm_out.append("    lsl x6, x7, #4")
    asm_out.append("    add x6, x17, x6")
    asm_out.append("    ldp x5, x6, [x6]")
    asm_out.append("    cmp x16, x5")
    asm_out.append("    b.eq .Lfound")
    asm_out.append("    b.lt .Lsearch_lower")
    asm_out.append("    add x18, x7, #1")
    asm_out.append("    b .Lbinsearch_loop")
    asm_out.append(".Lsearch_lower:")
    asm_out.append("    sub x8, x7, #1")
    asm_out.append("    b .Lbinsearch_loop")
    asm_out.append(".Lfound:")
    asm_out.append("    br x6")
    asm_out.append(".Ldirect_dispatch:")
    asm_out.append("    br x16")
    asm_out.append(".Lnot_found:")
    asm_out.append("    br x16")
    asm_out.append("")
    asm_out.append("loc_0:")
    asm_out.append("data_0:")
    asm_out.append("    brk #0")
    asm_out.append("")

    # Entry point
    asm_out.append("_start:")
    asm_out.append("    sub x28, sp, #65536  /* Isolate simulated x86 stack from native ARM64 frames */")
    asm_out.append("    /* Dynamically copy process arguments (argc, argv, envp, auxv) from host SP to simulated RSP (x28) */")
    asm_out.append("    mov x0, sp")
    asm_out.append("    mov x1, x28")
    asm_out.append("    ldr x3, [x0], #8     /* Copy argc */")
    asm_out.append("    str x3, [x1], #8")
    asm_out.append("1:  ldr x3, [x0], #8     /* Copy argv until NULL */")
    asm_out.append("    str x3, [x1], #8")
    asm_out.append("    cbnz x3, 1b")
    asm_out.append("2:  ldr x3, [x0], #8     /* Copy envp until NULL */")
    asm_out.append("    str x3, [x1], #8")
    asm_out.append("    cbnz x3, 2b")
    asm_out.append("3:  ldr x3, [x0], #8     /* Copy auxv until AT_NULL (0) */")
    asm_out.append("    ldr x4, [x0], #8")
    asm_out.append("    str x3, [x1], #8")
    asm_out.append("    str x4, [x1], #8")
    asm_out.append("    cbnz x3, 3b")
    asm_out.append(f"    b loc_{e_entry:x}\n")

    # Collect all referenced data addresses
    referenced_data_addrs = set()
    for addr, mnem, ops, comment in instructions:
        if comment:
            m_target = re.search(r'0x([0-9a-fA-F]+)', comment)
            if m_target:
                referenced_data_addrs.add(int(m_target.group(1), 16))
        for m_hex in re.finditer(r'0x([0-9a-fA-F]{5,})', ops):
            val = int(m_hex.group(1), 16)
            if val >= 0x400000:
                referenced_data_addrs.add(val)

    # Transpile code
    asm_out.append("/* Transpiled Instructions */")
    for insn_idx, (addr, mnem, ops, comment) in enumerate(instructions):
        if insn_idx > 0 and insn_idx % 500 == 0:
            asm_out.append(f"    b .Lltorg_{insn_idx}\n    .ltorg\n.Lltorg_{insn_idx}:")
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
        elif mnem == 'lock':
            asm_out.append("    /* lock */")
            asm_out.append("    dmb ish")
        elif mnem == 'pause':
            asm_out.append("    yield")
        elif mnem in ('cld', 'std'):
            asm_out.append("    /* cld/std: DF handled */")
        elif mnem == 'cmc':
            asm_out.append("    cset w16, cc")
            asm_out.append("    cmp w16, #1")
        elif mnem == 'hlt':
            asm_out.append("    brk #0")
        elif mnem == 'leave':
            asm_out.append("    mov x28, x25")
            asm_out.append("    ldr x25, [x28], #8")
        elif mnem == 'ret':
            if len(parts) > 0 and parts[0]:
                imm = int(parts[0], 0)
                asm_out.append("    ldr x16, [x28], #8")
                if imm != 0:
                    asm_out.append(f"    add x28, x28, #{imm}")
                asm_out.append("    br x16")
            else:
                asm_out.append("    ldr x16, [x28], #8")
                asm_out.append("    br x16")
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
                    sym = src[1:]
                    if sym.startswith('data_'):
                        x_dst = to_x_reg(dst)
                        asm_out.append(f"    adrp {x_dst}, {sym}")
                        asm_out.append(f"    add {x_dst}, {x_dst}, :lo12:{sym}")
                        if dst.startswith('w'):
                            asm_out.append(f"    mov {dst}, {to_w_reg(x_dst)}")
                    else:
                        asm_out.append(f"    ldr {dst}, {src}")
                elif src.startswith('#'):
                    asm_out.extend(emit_load_imm(dst, src[1:]))
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
        elif mnem == 'xchg':
            p0, p1 = parts[0], parts[1]
            if '[' not in p0 and '[' not in p1:
                r0 = map_reg(p0)
                r1 = map_reg(p1)
                scratch = 'w16' if r0.startswith('w') else 'x16'
                asm_out.append(f"    mov {scratch}, {r0}")
                asm_out.append(f"    mov {r0}, {r1}")
                asm_out.append(f"    mov {r1}, {scratch}")
            elif '[' in p0:
                mem_info = parse_x86_mem(p0, rip_target)
                r1 = map_reg(p1)
                asm_out.extend(emit_load('x16', mem_info))
                asm_out.extend(emit_store(r1, mem_info))
                target_r1 = to_w_reg(r1) if mem_info['size'] in ('byte', 'word', 'dword') else to_x_reg(r1)
                asm_out.append(f"    mov {target_r1}, {'w16' if target_r1.startswith('w') else 'x16'}")
            else:
                mem_info = parse_x86_mem(p1, rip_target)
                r0 = map_reg(p0)
                asm_out.extend(emit_load('x16', mem_info))
                asm_out.extend(emit_store(r0, mem_info))
                target_r0 = to_w_reg(r0) if mem_info['size'] in ('byte', 'word', 'dword') else to_x_reg(r0)
                asm_out.append(f"    mov {target_r0}, {'w16' if target_r0.startswith('w') else 'x16'}")
        elif mnem == 'cmpxchg':
            dst_str, src_str = parts[0], parts[1]
            src = map_reg(src_str)
            if '[' in dst_str:
                mem_info = parse_x86_mem(dst_str, rip_target)
                size = mem_info['size']
                acc = 'w19' if size in ('byte', 'word', 'dword') else 'x19'
                acc_cmp = 'w16' if size in ('byte', 'word', 'dword') else 'x16'
                asm_out.extend(emit_load('x16', mem_info))
                asm_out.append(f"    cmp {acc}, {acc_cmp}")
                asm_out.append("    b.ne 1f")
                asm_out.extend(emit_store(src, mem_info))
                asm_out.append("    b 2f")
                asm_out.append("1:")
                if size == 'byte':
                    asm_out.append("    and w19, w19, #0xffffff00")
                    asm_out.append("    and w16, w16, #0xff")
                    asm_out.append("    orr w19, w19, w16")
                else:
                    asm_out.append(f"    mov {acc}, {acc_cmp}")
                asm_out.append("2:")
            else:
                dst = map_reg(dst_str)
                acc = 'w19' if dst.startswith('w') else 'x19'
                asm_out.append(f"    cmp {acc}, {dst}")
                asm_out.append("    b.ne 1f")
                asm_out.append(f"    mov {dst}, {src}")
                asm_out.append("    b 2f")
                asm_out.append("1:")
                asm_out.append(f"    mov {acc}, {dst}")
                asm_out.append("2:")
        elif mnem == 'xadd':
            dst_str, src_str = parts[0], parts[1]
            src = map_reg(src_str)
            if '[' in dst_str:
                mem_info = parse_x86_mem(dst_str, rip_target)
                size = mem_info['size']
                scratch = 'w16' if size in ('byte', 'word', 'dword') else 'x16'
                asm_out.extend(emit_load('x16', mem_info))
                asm_out.append(f"    add x17, x16, {to_x_reg(src)}")
                asm_out.extend(emit_store('x17', mem_info))
                asm_out.append(f"    mov {src}, {scratch}")
            else:
                dst = map_reg(dst_str)
                scratch = 'w16' if dst.startswith('w') else 'x16'
                asm_out.append(f"    add {scratch}, {dst}, {src}")
                asm_out.append(f"    mov {src}, {dst}")
                asm_out.append(f"    mov {dst}, {scratch}")
        elif mnem == 'rep':
            sub_op = ops.split()[0].lower() if ops else ''
            if sub_op == 'stosb':
                asm_out.append("    cbz x21, 1f")
                asm_out.append("2:  strb w19, [x24], #1")
                asm_out.append("    subs x21, x21, #1")
                asm_out.append("    b.ne 2b")
                asm_out.append("1:")
            elif sub_op in ('stosd', 'stosl'):
                asm_out.append("    cbz x21, 1f")
                asm_out.append("2:  str w19, [x24], #4")
                asm_out.append("    subs x21, x21, #1")
                asm_out.append("    b.ne 2b")
                asm_out.append("1:")
            elif sub_op == 'stosq':
                asm_out.append("    cbz x21, 1f")
                asm_out.append("2:  str x19, [x24], #8")
                asm_out.append("    subs x21, x21, #1")
                asm_out.append("    b.ne 2b")
                asm_out.append("1:")
            elif sub_op == 'movsb':
                asm_out.append("    cbz x21, 1f")
                asm_out.append("2:  ldrb w16, [x23], #1")
                asm_out.append("    strb w16, [x24], #1")
                asm_out.append("    subs x21, x21, #1")
                asm_out.append("    b.ne 2b")
                asm_out.append("1:")
            elif sub_op in ('movsd', 'movsl'):
                asm_out.append("    cbz x21, 1f")
                asm_out.append("2:  ldr w16, [x23], #4")
                asm_out.append("    str w16, [x24], #4")
                asm_out.append("    subs x21, x21, #1")
                asm_out.append("    b.ne 2b")
                asm_out.append("1:")
            elif sub_op == 'movsq':
                asm_out.append("    cbz x21, 1f")
                asm_out.append("2:  ldr x16, [x23], #8")
                asm_out.append("    str x16, [x24], #8")
                asm_out.append("    subs x21, x21, #1")
                asm_out.append("    b.ne 2b")
                asm_out.append("1:")
            else:
                asm_out.append(f"    /* unhandled rep {sub_op} */")
        elif mnem in ('movsb', 'movsw', 'movsl', 'movsq') or (mnem == 'movsd' and not parts):
            sz = 1 if mnem == 'movsb' else (2 if mnem == 'movsw' else (4 if mnem in ('movsl', 'movsd') else 8))
            inst = 'ldrb' if sz == 1 else ('ldrh' if sz == 2 else 'ldr')
            s_inst = 'strb' if sz == 1 else ('strh' if sz == 2 else 'str')
            scratch = 'w16' if sz < 8 else 'x16'
            asm_out.append(f"    {inst} {scratch}, [x23], #{sz}")
            asm_out.append(f"    {s_inst} {scratch}, [x24], #{sz}")
        elif mnem in ('stosb', 'stosw', 'stosl', 'stosd', 'stosq'):
            sz = 1 if mnem == 'stosb' else (2 if mnem == 'stosw' else (4 if mnem in ('stosl', 'stosd') else 8))
            s_inst = 'strb' if sz == 1 else ('strh' if sz == 2 else 'str')
            val = 'w19' if sz < 8 else 'x19'
            asm_out.append(f"    {s_inst} {val}, [x24], #{sz}")
        elif mnem == 'add':
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                val_reg = 'w16' if mem_info['size'] in ('byte', 'word', 'dword') else 'x16'
                asm_out.extend(emit_load('x16', mem_info))
                src = map_operand(parts[1])
                if src.startswith('#'):
                    imm_val = int(src[1:])
                    asm_out.append(f"    adds {val_reg}, {val_reg}, #{imm_val}")
                else:
                    src_reg = to_w_reg(src) if val_reg.startswith('w') else to_x_reg(src)
                    asm_out.append(f"    adds {val_reg}, {val_reg}, {src_reg}")
                asm_out.extend(emit_store('x16', mem_info))
            else:
                dst = map_reg(parts[0])
                if '[' in parts[1]:
                    mem_info = parse_x86_mem(parts[1], rip_target)
                    asm_out.extend(emit_load('x16', mem_info))
                    reg_src = 'w16' if dst.startswith('w') else 'x16'
                    asm_out.append(f"    adds {dst}, {dst}, {reg_src}")
                else:
                    src = map_operand(parts[1])
                    if src.startswith('#'):
                        imm_val = int(src[1:])
                        if imm_val < 0:
                            asm_out.append(f"    subs {dst}, {dst}, #{-imm_val}")
                        elif imm_val > 4095:
                            scratch = 'w16' if dst.startswith('w') else 'x16'
                            asm_out.extend(emit_load_imm(scratch, imm_val))
                            asm_out.append(f"    adds {dst}, {dst}, {scratch}")
                        else:
                            asm_out.append(f"    adds {dst}, {dst}, {src}")
                    else:
                        if dst.startswith('w'):
                            src = to_w_reg(src)
                        elif dst.startswith('x'):
                            src = to_x_reg(src)
                        asm_out.append(f"    adds {dst}, {dst}, {src}")
        elif mnem == 'sub':
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                val_reg = 'w16' if mem_info['size'] in ('byte', 'word', 'dword') else 'x16'
                asm_out.extend(emit_load('x16', mem_info))
                src = map_operand(parts[1])
                if src.startswith('#'):
                    imm_val = int(src[1:])
                    asm_out.append(f"    subs {val_reg}, {val_reg}, #{imm_val}")
                elif '[' in parts[1]:
                    mem_src = parse_x86_mem(parts[1], rip_target)
                    scratch = 'w9' if val_reg.startswith('w') else 'x9'
                    asm_out.extend(emit_load(scratch, mem_src))
                    asm_out.append(f"    subs {val_reg}, {val_reg}, {scratch}")
                else:
                    src_reg = to_w_reg(src) if val_reg.startswith('w') else to_x_reg(src)
                    asm_out.append(f"    subs {val_reg}, {val_reg}, {src_reg}")
                asm_out.extend(emit_store('x16', mem_info))
            else:
                dst = map_reg(parts[0])
                if '[' in parts[1]:
                    mem_info = parse_x86_mem(parts[1], rip_target)
                    scratch = 'w16' if dst.startswith('w') else 'x16'
                    asm_out.extend(emit_load(scratch, mem_info))
                    asm_out.append(f"    subs {dst}, {dst}, {scratch}")
                else:
                    src = map_operand(parts[1])
                    if src.startswith('#'):
                        imm_val = int(src[1:])
                        if imm_val < 0:
                            asm_out.append(f"    adds {dst}, {dst}, #{-imm_val}")
                        elif imm_val > 4095:
                            scratch = 'w16' if dst.startswith('w') else 'x16'
                            asm_out.extend(emit_load_imm(scratch, imm_val))
                            asm_out.append(f"    subs {dst}, {dst}, {scratch}")
                        else:
                            asm_out.append(f"    subs {dst}, {dst}, {src}")
                    else:
                        if dst.startswith('w'):
                            src = to_w_reg(src)
                        elif dst.startswith('x'):
                            src = to_x_reg(src)
                        asm_out.append(f"    subs {dst}, {dst}, {src}")
        elif mnem == 'adc':
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                val_reg = 'w16' if mem_info['size'] in ('byte', 'word', 'dword') else 'x16'
                asm_out.extend(emit_load('x16', mem_info))
                src = map_operand(parts[1]) if len(parts) > 1 else '#0'
                if src.startswith('#'):
                    imm_val = int(src[1:], 0)
                    if imm_val == 0:
                        asm_out.append(f"    cinc {val_reg}, {val_reg}, lo")
                    else:
                        scratch = 'w17' if val_reg.startswith('w') else 'x17'
                        asm_out.extend(emit_load_imm(scratch, imm_val))
                        asm_out.append(f"    adc {val_reg}, {val_reg}, {scratch}")
                else:
                    src_reg = to_w_reg(src) if val_reg.startswith('w') else to_x_reg(src)
                    asm_out.append(f"    adc {val_reg}, {val_reg}, {src_reg}")
                asm_out.extend(emit_store('x16', mem_info))
            else:
                dst = map_reg(parts[0])
                if '[' in parts[1]:
                    mem_src = parse_x86_mem(parts[1], rip_target)
                    scratch = 'w16' if dst.startswith('w') else 'x16'
                    asm_out.extend(emit_load(scratch, mem_src))
                    asm_out.append(f"    adc {dst}, {dst}, {scratch}")
                else:
                    src = map_operand(parts[1]) if len(parts) > 1 else '#0'
                    if src.startswith('#'):
                        imm_val = int(src[1:], 0)
                        if imm_val == 0:
                            asm_out.append(f"    cinc {dst}, {dst}, lo")
                        else:
                            scratch = 'w16' if dst.startswith('w') else 'x16'
                            asm_out.extend(emit_load_imm(scratch, imm_val))
                            asm_out.append(f"    adc {dst}, {dst}, {scratch}")
                    else:
                        src_reg = to_w_reg(src) if dst.startswith('w') else to_x_reg(src)
                        asm_out.append(f"    adc {dst}, {dst}, {src_reg}")
        elif mnem == 'sbb':
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                val_reg = 'w16' if mem_info['size'] in ('byte', 'word', 'dword') else 'x16'
                asm_out.extend(emit_load('x16', mem_info))
                src = map_operand(parts[1]) if len(parts) > 1 else '#0'
                if src.startswith('#'):
                    scratch = 'w17' if val_reg.startswith('w') else 'x17'
                    asm_out.extend(emit_load_imm(scratch, src[1:]))
                    asm_out.append(f"    sbc {val_reg}, {val_reg}, {scratch}")
                elif '[' in parts[1]:
                    mem_src = parse_x86_mem(parts[1], rip_target)
                    scratch = 'w17' if val_reg.startswith('w') else 'x17'
                    asm_out.extend(emit_load(scratch, mem_src))
                    asm_out.append(f"    sbc {val_reg}, {val_reg}, {scratch}")
                else:
                    src_reg = to_w_reg(src) if val_reg.startswith('w') else to_x_reg(src)
                    asm_out.append(f"    sbc {val_reg}, {val_reg}, {src_reg}")
                asm_out.extend(emit_store('x16', mem_info))
            else:
                dst = map_reg(parts[0])
                if '[' in parts[1]:
                    mem_info = parse_x86_mem(parts[1], rip_target)
                    scratch = 'w16' if dst.startswith('w') else 'x16'
                    asm_out.extend(emit_load(scratch, mem_info))
                    asm_out.append(f"    sbc {dst}, {dst}, {scratch}")
                else:
                    src = map_operand(parts[1])
                    if src.startswith('#'):
                        imm_reg = 'w16' if dst.startswith('w') else 'x16'
                        asm_out.extend(emit_load_imm(imm_reg, src[1:]))
                        asm_out.append(f"    sbc {dst}, {dst}, {imm_reg}")
                    else:
                        if dst.startswith('w'):
                            src = to_w_reg(src)
                        asm_out.append(f"    sbc {dst}, {dst}, {src}")
        elif mnem == 'imul':
            dst = map_reg(parts[0])
            if len(parts) == 3:
                imm = map_operand(parts[2])
                scratch = 'w16' if dst.startswith('w') else 'x16'
                asm_out.extend(emit_load_imm(scratch, imm.replace('#', '')))
                if '[' in parts[1]:
                    mem_info = parse_x86_mem(parts[1], rip_target)
                    src_reg = 'w17' if dst.startswith('w') else 'x17'
                    asm_out.extend(emit_load(src_reg, mem_info))
                else:
                    src = map_reg(parts[1]) if parts[1].lower() in REG_MAP else parts[1]
                    src_reg = to_w_reg(src) if dst.startswith('w') else to_x_reg(src)
                asm_out.append(f"    mul {dst}, {src_reg}, {scratch}")
            else:
                if '[' in parts[1]:
                    mem_info = parse_x86_mem(parts[1], rip_target)
                    scratch = 'w16' if dst.startswith('w') else 'x16'
                    asm_out.extend(emit_load(scratch, mem_info))
                    asm_out.append(f"    mul {dst}, {dst}, {scratch}")
                else:
                    src = map_operand(parts[1])
                    if src.startswith('#'):
                        scratch = 'w16' if dst.startswith('w') else 'x16'
                        asm_out.extend(emit_load_imm(scratch, src[1:]))
                        asm_out.append(f"    mul {dst}, {dst}, {scratch}")
                    else:
                        src_reg = to_w_reg(src) if dst.startswith('w') else to_x_reg(src)
                        asm_out.append(f"    mul {dst}, {dst}, {src_reg}")
        elif mnem == 'mul':
            if len(parts) == 1:
                if '[' in parts[0]:
                    mem_info = parse_x86_mem(parts[0], rip_target)
                    if mem_info['size'] in ('byte', 'word', 'dword'):
                        asm_out.extend(emit_load('w16', mem_info))
                        asm_out.append("    umull x16, w19, w16")
                        asm_out.append("    mov w19, w16")
                        asm_out.append("    lsr x22, x16, #32")
                    else:
                        asm_out.extend(emit_load('x16', mem_info))
                        asm_out.append("    mul x17, x19, x16")
                        asm_out.append("    umulh x22, x19, x16")
                        asm_out.append("    mov x19, x17")
                else:
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
        elif mnem in ('div', 'idiv'):
            div_op = 'sdiv' if mnem == 'idiv' else 'udiv'
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                if mem_info['size'] in ('byte', 'word', 'dword'):
                    asm_out.extend(emit_load('w17', mem_info))
                    asm_out.append(f"    {div_op} w16, w19, w17")
                    asm_out.append(f"    msub w22, w16, w17, w19")
                    asm_out.append("    mov w19, w16")
                else:
                    asm_out.extend(emit_load('x17', mem_info))
                    asm_out.append(f"    {div_op} x16, x19, x17")
                    asm_out.append(f"    msub x22, x16, x17, x19")
                    asm_out.append("    mov x19, x16")
            else:
                src = map_operand(parts[0])
                if src.startswith('w') or (parts[0] in REG_MAP and REG_MAP[parts[0]].startswith('w')):
                    src_reg = to_w_reg(src)
                    asm_out.append(f"    {div_op} w16, w19, {src_reg}")
                    asm_out.append(f"    msub w22, w16, {src_reg}, w19")
                    asm_out.append("    mov w19, w16")
                else:
                    src_reg = to_x_reg(src)
                    asm_out.append(f"    {div_op} x16, x19, {src_reg}")
                    asm_out.append(f"    msub x22, x16, {src_reg}, x19")
                    asm_out.append("    mov x19, x16")
        elif mnem in ('and', 'or', 'xor'):
            arm_op = {'and': 'ands', 'or': 'orr', 'xor': 'eor'}[mnem]
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                val_reg = 'w16' if mem_info['size'] in ('byte', 'word', 'dword') else 'x16'
                asm_out.extend(emit_load('x16', mem_info))
                src = map_operand(parts[1])
                if src.startswith('#'):
                    imm_val = int(src[1:], 0)
                    scratch = 'w17' if val_reg.startswith('w') else 'x17'
                    asm_out.extend(emit_load_imm(scratch, imm_val))
                    asm_out.append(f"    {arm_op} {val_reg}, {val_reg}, {scratch}")
                elif '[' in parts[1]:
                    mem_src = parse_x86_mem(parts[1], rip_target)
                    scratch = 'w17' if val_reg.startswith('w') else 'x17'
                    asm_out.extend(emit_load(scratch, mem_src))
                    asm_out.append(f"    {arm_op} {val_reg}, {val_reg}, {scratch}")
                else:
                    src_reg = to_w_reg(src) if val_reg.startswith('w') else to_x_reg(src)
                    asm_out.append(f"    {arm_op} {val_reg}, {val_reg}, {src_reg}")
                asm_out.extend(emit_store('x16', mem_info))
            else:
                dst = map_reg(parts[0])
                if parts[0] == parts[1] and mnem == 'xor':
                    asm_out.append(f"    mov {dst}, #0")
                elif '[' in parts[1]:
                    mem_info = parse_x86_mem(parts[1], rip_target)
                    scratch = 'w16' if dst.startswith('w') else 'x16'
                    asm_out.extend(emit_load(scratch, mem_info))
                    asm_out.append(f"    {arm_op} {dst}, {dst}, {scratch}")
                else:
                    src = map_operand(parts[1])
                    if src.startswith('#'):
                        imm_val = int(src[1:], 0)
                        scratch = 'w16' if dst.startswith('w') else 'x16'
                        asm_out.extend(emit_load_imm(scratch, imm_val))
                        asm_out.append(f"    {arm_op} {dst}, {dst}, {scratch}")
                    else:
                        src_reg = to_w_reg(src) if dst.startswith('w') else to_x_reg(src)
                        asm_out.append(f"    {arm_op} {dst}, {dst}, {src_reg}")
        elif mnem in ('shr', 'shl', 'sal', 'sar', 'ror', 'rol'):
            is_mem = '[' in parts[0]
            p0_lower = parts[0].strip().lower()
            is_byte = (is_mem and ('byte ptr' in p0_lower or (rip_target and parse_x86_mem(parts[0], rip_target)['size'] == 'byte'))) or (not is_mem and p0_lower in BYTE_REGS)
            is_word = (is_mem and ('word ptr' in p0_lower or (rip_target and parse_x86_mem(parts[0], rip_target)['size'] == 'word'))) or (not is_mem and p0_lower in WORD_REGS)

            if is_mem:
                mem_info = parse_x86_mem(parts[0], rip_target)
                val_reg = 'w16' if mem_info['size'] in ('byte', 'word', 'dword') else 'x16'
                asm_out.extend(emit_load('x16', mem_info))
                target_reg = val_reg
            else:
                target_reg = map_reg(parts[0])

            shift_arm = {'shr': 'lsr', 'shl': 'lsl', 'sal': 'lsl', 'sar': 'asr', 'ror': 'ror'}.get(mnem)
            bits = 8 if is_byte else (16 if is_word else (32 if target_reg.startswith('w') else 64))

            if is_byte and not is_mem:
                asm_out.append(f"    uxtb w16, {to_w_reg(target_reg)}")
                shift_target = 'w16'
            elif is_word and not is_mem:
                asm_out.append(f"    uxth w16, {to_w_reg(target_reg)}")
                shift_target = 'w16'
            else:
                shift_target = target_reg

            if mnem == 'rol':
                if len(parts) > 1 and parts[1].strip().lower() in REG_MAP:
                    src_reg = to_w_reg(map_reg(parts[1])) if shift_target.startswith('w') else to_x_reg(map_reg(parts[1]))
                    scratch = 'w17' if shift_target.startswith('w') else 'x17'
                    asm_out.append(f"    mov {scratch}, #{bits}")
                    asm_out.append(f"    sub {scratch}, {scratch}, {src_reg}")
                    asm_out.append(f"    ror {shift_target}, {shift_target}, {scratch}")
                else:
                    shift = int(parts[1].replace('#', '').strip(), 0) if len(parts) > 1 else 1
                    asm_out.append(f"    ror {shift_target}, {shift_target}, #{(bits - shift) % bits}")
            else:
                src = map_operand(parts[1]) if len(parts) > 1 else '#1'
                if len(parts) > 1 and parts[1].strip().lower() in REG_MAP:
                    src_reg = to_w_reg(map_reg(parts[1])) if shift_target.startswith('w') else to_x_reg(map_reg(parts[1]))
                    asm_out.append(f"    {shift_arm} {shift_target}, {shift_target}, {src_reg}")
                else:
                    asm_out.append(f"    {shift_arm} {shift_target}, {shift_target}, {src}")

                if is_byte:
                    asm_out.append("    sxtb w16, w16" if mnem == 'sar' else "    uxtb w16, w16")
                elif is_word:
                    asm_out.append("    sxth w16, w16" if mnem == 'sar' else "    uxth w16, w16")

                if mnem in ('shr', 'shl', 'sal', 'sar'):
                    asm_out.append(f"    tst {shift_target}, {shift_target}")

            if is_byte and not is_mem:
                asm_out.append(f"    bfi {target_reg}, w16, #0, #8")
            elif is_word and not is_mem:
                asm_out.append(f"    bfi {target_reg}, w16, #0, #16")
            elif is_mem:
                asm_out.extend(emit_store('x16', mem_info))
        elif mnem == 'cdqe':
            asm_out.append("    sxtw x19, w19")
        elif mnem == 'cdq':
            asm_out.append("    asr w22, w19, #31")
        elif mnem == 'cqo':
            asm_out.append("    asr x22, x19, #63")
        elif mnem == 'bswap':
            dst = map_reg(parts[0])
            asm_out.append(f"    rev {dst}, {dst}")
        elif mnem == 'neg':
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                val_reg = 'w16' if mem_info['size'] in ('byte', 'word', 'dword') else 'x16'
                asm_out.extend(emit_load('x16', mem_info))
                asm_out.append(f"    negs {val_reg}, {val_reg}")
                asm_out.extend(emit_store('x16', mem_info))
            else:
                dst = map_reg(parts[0])
                asm_out.append(f"    negs {dst}, {dst}")
        elif mnem == 'not':
            dst = map_reg(parts[0])
            asm_out.append(f"    mvn {dst}, {dst}")
        elif mnem == 'cmp':
            p0_lower = parts[0].strip().lower()
            p1_lower = parts[1].strip().lower() if len(parts) > 1 else ''
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                asm_out.extend(emit_load('x16', mem_info))
                val1 = 'w16' if mem_info['size'] in ('byte', 'word', 'dword') else 'x16'
                if '[' in parts[1]:
                    mem_info2 = parse_x86_mem(parts[1], rip_target)
                    scratch = 'w17' if val1.startswith('w') else 'x17'
                    asm_out.extend(emit_load(scratch, mem_info2))
                    asm_out.append(f"    cmp {val1}, {scratch}")
                else:
                    op2 = map_operand(parts[1])
                    if op2.startswith('#'):
                        imm_val = int(op2[1:], 0)
                        if 0 <= imm_val <= 4095:
                            asm_out.append(f"    cmp {val1}, {op2}")
                        else:
                            scratch = 'w17' if val1.startswith('w') else 'x17'
                            asm_out.extend(emit_load_imm(scratch, imm_val))
                            asm_out.append(f"    cmp {val1}, {scratch}")
                    else:
                        if p1_lower in BYTE_REGS:
                            asm_out.append(f"    uxtb w9, {to_w_reg(map_reg(parts[1]))}")
                            op2_reg = 'w9'
                            val1_cmp = to_w_reg(val1)
                        elif p1_lower in WORD_REGS:
                            asm_out.append(f"    uxth w9, {to_w_reg(map_reg(parts[1]))}")
                            op2_reg = 'w9'
                            val1_cmp = to_w_reg(val1)
                        else:
                            op2_reg = to_w_reg(op2) if val1.startswith('w') else to_x_reg(op2)
                            val1_cmp = val1
                        asm_out.append(f"    cmp {val1_cmp}, {op2_reg}")
            elif '[' in parts[1]:
                op1 = map_reg(parts[0])
                if p0_lower in BYTE_REGS:
                    asm_out.append(f"    uxtb w9, {to_w_reg(op1)}")
                    op1 = 'w9'
                elif p0_lower in WORD_REGS:
                    asm_out.append(f"    uxth w9, {to_w_reg(op1)}")
                    op1 = 'w9'
                mem_info = parse_x86_mem(parts[1], rip_target)
                val2 = 'w16' if op1.startswith('w') else 'x16'
                asm_out.extend(emit_load(val2, mem_info))
                asm_out.append(f"    cmp {op1}, {val2}")
            else:
                op1 = map_reg(parts[0])
                if p0_lower in BYTE_REGS:
                    asm_out.append(f"    uxtb w16, {to_w_reg(op1)}")
                    op1 = 'w16'
                elif p0_lower in WORD_REGS:
                    asm_out.append(f"    uxth w16, {to_w_reg(op1)}")
                    op1 = 'w16'
                op2 = map_operand(parts[1])
                if op2.startswith('#'):
                    imm_val = int(op2[1:], 0)
                    if 0 <= imm_val <= 4095:
                        asm_out.append(f"    cmp {op1}, {op2}")
                    else:
                        scratch = 'w17' if op1.startswith('w') else 'x17'
                        asm_out.extend(emit_load_imm(scratch, imm_val))
                        asm_out.append(f"    cmp {op1}, {scratch}")
                else:
                    if p1_lower in BYTE_REGS:
                        asm_out.append(f"    uxtb w9, {to_w_reg(map_reg(parts[1]))}")
                        op2_reg = 'w9'
                        op1_cmp = to_w_reg(op1)
                    elif p1_lower in WORD_REGS:
                        asm_out.append(f"    uxth w9, {to_w_reg(map_reg(parts[1]))}")
                        op2_reg = 'w9'
                        op1_cmp = to_w_reg(op1)
                    else:
                        op2_reg = to_w_reg(op2) if op1.startswith('w') else to_x_reg(op2)
                        op1_cmp = op1
                    asm_out.append(f"    cmp {op1_cmp}, {op2_reg}")
        elif mnem == 'test':
            p0_lower = parts[0].strip().lower()
            p1_lower = parts[1].strip().lower() if len(parts) > 1 else ''
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                val1 = 'w16' if mem_info['size'] in ('byte', 'word', 'dword') else 'x16'
                asm_out.extend(emit_load('x16', mem_info))
                op2 = map_operand(parts[1])
                if op2.startswith('#'):
                    imm_val = int(op2[1:], 0)
                    scratch = 'w17' if val1.startswith('w') else 'x17'
                    asm_out.extend(emit_load_imm(scratch, imm_val))
                    asm_out.append(f"    tst {val1}, {scratch}")
                else:
                    if p1_lower in BYTE_REGS:
                        asm_out.append(f"    uxtb w9, {to_w_reg(map_reg(parts[1]))}")
                        op2_reg = 'w9'
                        val1_tst = to_w_reg(val1)
                    elif p1_lower in WORD_REGS:
                        asm_out.append(f"    uxth w9, {to_w_reg(map_reg(parts[1]))}")
                        op2_reg = 'w9'
                        val1_tst = to_w_reg(val1)
                    else:
                        op2_reg = to_w_reg(op2) if val1.startswith('w') else to_x_reg(op2)
                        val1_tst = val1
                    asm_out.append(f"    tst {val1_tst}, {op2_reg}")
            elif '[' in parts[1]:
                op1 = map_reg(parts[0])
                if p0_lower in BYTE_REGS:
                    asm_out.append(f"    uxtb w9, {to_w_reg(op1)}")
                    op1 = 'w9'
                elif p0_lower in WORD_REGS:
                    asm_out.append(f"    uxth w9, {to_w_reg(op1)}")
                    op1 = 'w9'
                mem_info = parse_x86_mem(parts[1], rip_target)
                val2 = 'w16' if op1.startswith('w') else 'x16'
                asm_out.extend(emit_load('x16', mem_info))
                asm_out.append(f"    tst {op1}, {val2}")
            else:
                op1 = map_reg(parts[0])
                if p0_lower in BYTE_REGS:
                    asm_out.append(f"    uxtb w9, {to_w_reg(op1)}")
                    op1 = 'w9'
                elif p0_lower in WORD_REGS:
                    asm_out.append(f"    uxth w9, {to_w_reg(op1)}")
                    op1 = 'w9'
                op2 = map_operand(parts[1])
                if op2.startswith('#'):
                    imm_val = int(op2[1:], 0)
                    scratch = 'w16' if op1.startswith('w') else 'x16'
                    asm_out.extend(emit_load_imm(scratch, imm_val))
                    asm_out.append(f"    tst {op1}, {scratch}")
                else:
                    if p1_lower in BYTE_REGS:
                        asm_out.append(f"    uxtb w16, {to_w_reg(map_reg(parts[1]))}")
                        op2_reg = 'w16'
                        op1_tst = to_w_reg(op1)
                    elif p1_lower in WORD_REGS:
                        asm_out.append(f"    uxth w16, {to_w_reg(map_reg(parts[1]))}")
                        op2_reg = 'w16'
                        op1_tst = to_w_reg(op1)
                    else:
                        op2_reg = to_w_reg(op2) if op1.startswith('w') else to_x_reg(op2)
                        op1_tst = op1
                    asm_out.append(f"    tst {op1_tst}, {op2_reg}")
        elif mnem in ('bt', 'btr', 'btc'):
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                asm_out.extend(emit_load('x16', mem_info))
                base_x = 'x16'
            else:
                base = map_reg(parts[0]) if parts[0] in REG_MAP else map_operand(parts[0])
                base_x = to_x_reg(base)
            offset = map_reg(parts[1]) if parts[1] in REG_MAP else map_operand(parts[1])
            if offset.startswith('#'):
                bit = int(offset[1:], 0)
                asm_out.append(f"    lsr x17, {base_x}, #{bit}")
            else:
                off_x = to_x_reg(offset)
                asm_out.append(f"    lsrv x17, {base_x}, {off_x}")
            asm_out.append("    and x17, x17, #1")
            asm_out.append("    subs xzr, xzr, x17")
            if mnem in ('btr', 'btc'):
                if offset.startswith('#'):
                    bit = int(offset[1:], 0)
                    asm_out.extend(emit_load_imm("x17", (1 << bit)))
                else:
                    asm_out.append("    mov x17, #1")
                    asm_out.append(f"    lslv x17, x17, {off_x}")
                if mnem == 'btr':
                    asm_out.append(f"    bic {base_x}, {base_x}, x17")
                else:
                    asm_out.append(f"    eor {base_x}, {base_x}, x17")
                if '[' in parts[0]:
                    asm_out.extend(emit_store(base_x, mem_info))
        elif mnem == 'bsf':
            dst = map_reg(parts[0])
            src = map_operand(parts[1])
            src_reg = map_reg(parts[1]) if parts[1] in REG_MAP else src
            if dst.startswith('w'):
                asm_out.append(f"    rbit w16, {to_w_reg(src_reg)}")
                asm_out.append(f"    clz {dst}, w16")
            else:
                asm_out.append(f"    rbit x16, {to_x_reg(src_reg)}")
                asm_out.append(f"    clz {dst}, x16")
        elif mnem == 'bsr':
            dst = map_reg(parts[0])
            src = map_operand(parts[1])
            src_reg = map_reg(parts[1]) if parts[1] in REG_MAP else src
            if dst.startswith('w'):
                asm_out.append(f"    clz w16, {to_w_reg(src_reg)}")
                asm_out.append(f"    mov {dst}, #31")
                asm_out.append(f"    sub {dst}, {dst}, w16")
            else:
                asm_out.append(f"    clz x16, {to_x_reg(src_reg)}")
                asm_out.append(f"    mov {dst}, #63")
                asm_out.append(f"    sub {dst}, {dst}, x16")
        elif mnem == 'inc':
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                val_reg = 'w16' if mem_info['size'] in ('byte', 'word', 'dword') else 'x16'
                asm_out.extend(emit_load('x16', mem_info))
                asm_out.append(f"    adds {val_reg}, {val_reg}, #1")
                asm_out.extend(emit_store('x16', mem_info))
            else:
                dst = map_reg(parts[0])
                asm_out.append(f"    adds {dst}, {dst}, #1")
        elif mnem == 'dec':
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                val_reg = 'w16' if mem_info['size'] in ('byte', 'word', 'dword') else 'x16'
                asm_out.extend(emit_load('x16', mem_info))
                asm_out.append(f"    subs {val_reg}, {val_reg}, #1")
                asm_out.extend(emit_store('x16', mem_info))
            else:
                dst = map_reg(parts[0])
                asm_out.append(f"    subs {dst}, {dst}, #1")
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
                if cond == 'al':
                    asm_out.append("    mov w16, #1")
                else:
                    asm_out.append(f"    cset w16, {cond}")
                asm_out.extend(emit_store('w16', mem_info))
            else:
                dst = to_w_reg(map_reg(parts[0]))
                if cond == 'al':
                    asm_out.append(f"    mov {dst}, #1")
                else:
                    asm_out.append(f"    cset {dst}, {cond}")
        elif mnem == 'push':
            p = parts[0]
            if p.lower() in REG_MAP:
                src = to_x_reg(map_reg(p))
                if src == 'x28':
                    asm_out.append("    mov x16, x28")
                    asm_out.append("    str x16, [x28, #-8]!")
                else:
                    asm_out.append(f"    str {src}, [x28, #-8]!")
            elif '[' in p:
                mem_info = parse_x86_mem(p, rip_target)
                asm_out.extend(emit_load('x16', mem_info))
                asm_out.append("    str x16, [x28, #-8]!")
            else:
                imm = int(p, 0)
                if imm == 0:
                    asm_out.append("    str xzr, [x28, #-8]!")
                else:
                    asm_out.extend(emit_load_imm("x16", imm))
                    asm_out.append("    str x16, [x28, #-8]!")
        elif mnem == 'pop':
            p = parts[0]
            if '[' in p:
                mem_info = parse_x86_mem(p, rip_target)
                asm_out.append("    ldr x16, [x28], #8")
                asm_out.extend(emit_store('x16', mem_info))
            else:
                dst = map_reg(p)
                dst_x = to_x_reg(dst)
                asm_out.append(f"    ldr {dst_x}, [x28], #8")
        elif mnem == 'jmp':
            t = parts[0].split()[0].strip()
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                asm_out.extend(emit_load('x16', mem_info))
                asm_out.append("    b x86_indirect_dispatcher")
            elif t in REG_MAP:
                r = to_x_reg(map_reg(t))
                asm_out.append(f"    mov x16, {r}")
                asm_out.append("    b x86_indirect_dispatcher")
            elif t.startswith('0x') or t.isdigit():
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
        elif mnem == 'jo':
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.vs loc_{t_val:x}")
        elif mnem == 'jno':
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.vc loc_{t_val:x}")
        elif mnem in ('jp', 'jpe'):
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.vs loc_{t_val:x}")
        elif mnem in ('jnp', 'jpo'):
            t = parts[0].split()[0].strip()
            t_val = int(t, 16) if t.startswith('0x') else int(t)
            asm_out.append(f"    b.vc loc_{t_val:x}")
        elif mnem == 'call':
            t = parts[0].split()[0].strip()
            ret_label = f"ret_{addr:x}"
            if '[' in parts[0]:
                mem_info = parse_x86_mem(parts[0], rip_target)
                asm_out.append(f"    adr x17, {ret_label}")
                asm_out.append("    str x17, [x28, #-8]!")
                asm_out.extend(emit_load('x16', mem_info))
                asm_out.append("    b x86_indirect_dispatcher")
                asm_out.append(f"{ret_label}:")
            elif t in REG_MAP:
                r = to_x_reg(map_reg(t))
                asm_out.append(f"    adr x17, {ret_label}")
                asm_out.append("    str x17, [x28, #-8]!")
                asm_out.append(f"    mov x16, {r}")
                asm_out.append("    b x86_indirect_dispatcher")
                asm_out.append(f"{ret_label}:")
            else:
                try:
                    t_val = int(t, 16) if (t.startswith('0x') or all(c in '0123456789abcdefABCDEF' for c in t)) else int(t)
                    asm_out.append(f"    adr x17, {ret_label}")
                    asm_out.append("    str x17, [x28, #-8]!")
                    asm_out.append(f"    b loc_{t_val:x}")
                    asm_out.append(f"{ret_label}:")
                except ValueError:
                    raise ValueError(f"unsupported call target: {t}")
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
        elif mnem in ('movaps', 'movups', 'movdqa', 'movdqu', 'movapd'):
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
        elif mnem in ('maxsd', 'minsd'):
            op = 'fmax' if mnem == 'maxsd' else 'fmin'
            d1 = xmm_to_d(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('d16', mem_info))
                asm_out.append(f"    {op} {d1}, {d1}, d16")
            else:
                d2 = xmm_to_d(parts[1])
                asm_out.append(f"    {op} {d1}, {d1}, {d2}")
        elif mnem == 'sqrtsd':
            d1 = xmm_to_d(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('d16', mem_info))
                asm_out.append(f"    fsqrt {d1}, d16")
            else:
                d2 = xmm_to_d(parts[1])
                asm_out.append(f"    fsqrt {d1}, {d2}")
        elif mnem == 'cvtss2sd':
            d1 = xmm_to_d(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('s16', mem_info))
                asm_out.append(f"    fcvt {d1}, s16")
            else:
                s2 = xmm_to_s(parts[1])
                asm_out.append(f"    fcvt {d1}, {s2}")
        elif mnem == 'cvtsd2ss':
            s1 = xmm_to_s(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('d16', mem_info))
                asm_out.append(f"    fcvt {s1}, d16")
            else:
                d2 = xmm_to_d(parts[1])
                asm_out.append(f"    fcvt {s1}, {d2}")
        elif mnem in ('cvtsi2ss', 'cvtsi2sd'):
            is_sd = (mnem == 'cvtsi2sd')
            dst_reg = xmm_to_d(parts[0]) if is_sd else xmm_to_s(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                src_reg = 'w16' if mem_info['size'] in ('byte', 'word', 'dword') else 'x16'
                asm_out.extend(emit_load(src_reg, mem_info))
                asm_out.append(f"    scvtf {dst_reg}, {src_reg}")
            else:
                src = map_operand(parts[1])
                src_reg = to_w_reg(src) if src.startswith('w') or not src.startswith('x') else src
                asm_out.append(f"    scvtf {dst_reg}, {src_reg}")
        elif mnem in ('cvttss2si', 'cvttsd2si'):
            is_sd = (mnem == 'cvttsd2si')
            dst = map_reg(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                f_scratch = 'd16' if is_sd else 's16'
                asm_out.extend(emit_load(f_scratch, mem_info))
                asm_out.append(f"    fcvtzs {dst}, {f_scratch}")
            else:
                src_f = xmm_to_d(parts[1]) if is_sd else xmm_to_s(parts[1])
                asm_out.append(f"    fcvtzs {dst}, {src_f}")
        elif mnem == 'ucomiss':
            s1 = xmm_to_s(parts[0])
            s2 = xmm_to_s(parts[1])
            asm_out.append(f"    fcmp {s1}, {s2}")
        elif mnem in ('ucomisd', 'comisd'):
            d1 = xmm_to_d(parts[0])
            if '[' in parts[1]:
                mem_info = parse_x86_mem(parts[1], rip_target)
                asm_out.extend(emit_load('d16', mem_info))
                asm_out.append(f"    fcmp {d1}, d16")
            else:
                d2 = xmm_to_d(parts[1])
                asm_out.append(f"    fcmp {d1}, {d2}")
        elif mnem == 'cmpltsd':
            v1 = xmm_to_v(parts[0], '2d')
            v2 = xmm_to_v(parts[1], '2d')
            asm_out.append(f"    fcmgt {v1}, {v2}, {v1}")
        elif mnem == 'psrlq':
            v_dst = xmm_to_v(parts[0], '2d')
            shift = map_operand(parts[1])
            if shift.startswith('#'):
                asm_out.append(f"    ushr {v_dst}, {v_dst}, {shift}")
            else:
                asm_out.append(f"    ushr {v_dst}, {v_dst}, #1")
        # x87 Floating-Point Stack
        elif mnem.startswith('f'):
            if mnem == 'fld':
                asm_out.append("    fmov d31, d30; fmov d30, d29; fmov d29, d28")
                asm_out.append("    fmov d28, d27; fmov d27, d26; fmov d26, d25; fmov d25, d24")
                if '[' in parts[0]:
                    mem_info = parse_x86_mem(parts[0], rip_target)
                    asm_out.extend(emit_load('d24', mem_info))
                else:
                    asm_out.append("    fmov d24, d25")
            elif mnem == 'fild':
                asm_out.append("    fmov d31, d30; fmov d30, d29; fmov d29, d28")
                asm_out.append("    fmov d28, d27; fmov d27, d26; fmov d26, d25; fmov d25, d24")
                if '[' in parts[0]:
                    mem_info = parse_x86_mem(parts[0], rip_target)
                    asm_out.extend(emit_load('x16', mem_info))
                    if mem_info['size'] == 'dword':
                        asm_out.append("    scvtf d24, w16")
                    else:
                        asm_out.append("    scvtf d24, x16")
            elif mnem == 'fldz':
                asm_out.append("    fmov d31, d30; fmov d30, d29; fmov d29, d28")
                asm_out.append("    fmov d28, d27; fmov d27, d26; fmov d26, d25; fmov d25, d24")
                asm_out.append("    fmov d24, xzr")
            elif mnem == 'fld1':
                asm_out.append("    fmov d31, d30; fmov d30, d29; fmov d29, d28")
                asm_out.append("    fmov d28, d27; fmov d27, d26; fmov d26, d25; fmov d25, d24")
                asm_out.append("    fmov d24, #1.0")
            elif mnem == 'fstp':
                if len(parts) > 0 and '[' in parts[0]:
                    mem_info = parse_x86_mem(parts[0], rip_target)
                    asm_out.extend(emit_store('d24', mem_info))
                asm_out.append("    fmov d24, d25; fmov d25, d26; fmov d26, d27")
                asm_out.append("    fmov d27, d28; fmov d28, d29; fmov d29, d30; fmov d30, d31")
            elif mnem == 'fistp':
                if len(parts) > 0 and '[' in parts[0]:
                    mem_info = parse_x86_mem(parts[0], rip_target)
                    if mem_info['size'] == 'dword':
                        asm_out.append("    fcvtzs w16, d24")
                    else:
                        asm_out.append("    fcvtzs x16, d24")
                    asm_out.extend(emit_store('x16', mem_info))
                asm_out.append("    fmov d24, d25; fmov d25, d26; fmov d26, d27")
                asm_out.append("    fmov d27, d28; fmov d28, d29; fmov d29, d30; fmov d30, d31")
            elif mnem == 'fxch':
                asm_out.append("    fmov d16, d24; fmov d24, d25; fmov d25, d16")
            elif mnem in ('fadd', 'faddp'):
                asm_out.append("    fadd d25, d25, d24")
                if mnem == 'faddp':
                    asm_out.append("    fmov d24, d25; fmov d25, d26; fmov d26, d27")
                    asm_out.append("    fmov d27, d28; fmov d28, d29; fmov d29, d30; fmov d30, d31")
                else:
                    asm_out.append("    fmov d24, d25")
            elif mnem in ('fsub', 'fsubp', 'fsubrp', 'fisub'):
                if mnem == 'fsubrp':
                    asm_out.append("    fsub d25, d24, d25")
                else:
                    asm_out.append("    fsub d25, d25, d24")
                asm_out.append("    fmov d24, d25; fmov d25, d26; fmov d26, d27")
                asm_out.append("    fmov d27, d28; fmov d28, d29; fmov d29, d30; fmov d30, d31")
            elif mnem in ('fmul', 'fmulp'):
                asm_out.append("    fmul d25, d25, d24")
                if mnem == 'fmulp':
                    asm_out.append("    fmov d24, d25; fmov d25, d26; fmov d26, d27")
                    asm_out.append("    fmov d27, d28; fmov d28, d29; fmov d29, d30; fmov d30, d31")
                else:
                    asm_out.append("    fmov d24, d25")
            elif mnem == 'fdivp':
                asm_out.append("    fdiv d25, d25, d24")
                asm_out.append("    fmov d24, d25; fmov d25, d26; fmov d26, d27")
                asm_out.append("    fmov d27, d28; fmov d28, d29; fmov d29, d30; fmov d30, d31")
            elif mnem in ('fcomi', 'fcompi', 'fucomi', 'fucompi'):
                asm_out.append("    fcmp d24, d25")
                if 'p' in mnem:
                    asm_out.append("    fmov d24, d25; fmov d25, d26; fmov d26, d27")
                    asm_out.append("    fmov d27, d28; fmov d28, d29; fmov d29, d30; fmov d30, d31")
            elif mnem == 'fchs':
                asm_out.append("    fneg d24, d24")
            elif mnem == 'fabs':
                asm_out.append("    fabs d24, d24")
            elif mnem in ('fldcw', 'fnstcw'):
                if '[' in parts[0]:
                    mem_info = parse_x86_mem(parts[0], rip_target)
                    if mnem == 'fnstcw':
                        asm_out.append("    mov w16, #0x37f")
                        asm_out.extend(emit_store('w16', mem_info))
                    else:
                        asm_out.extend(emit_load('w16', mem_info))
            elif mnem == 'fnstsw':
                asm_out.append("    mov w19, #0")
            elif mnem == 'fprem':
                asm_out.append("    /* fprem */")
            else:
                asm_out.append(f"    /* unhandled x87: {mnem} {ops} */")
        else:
            asm_out.append(f"    /* UNHANDLED: {mnem} {ops} */")
            asm_out.append("    brk #0")

    # Indirect Dispatch Table in .dispatch_table
    asm_out.append("\n/* x86 to ARM64 Indirect Dispatch Table */")
    asm_out.append('.section .dispatch_table, "a"')
    asm_out.append(".align 4")
    asm_out.append(".global x86_dispatch_table")
    asm_out.append("x86_dispatch_table:")
    for addr, _, _, _ in instructions:
        asm_out.append(f"    .quad 0x{addr:x}, loc_{addr:x}")
    asm_out.append(f".equ x86_dispatch_table_len, {len(instructions) - 1}")

    # Data and BSS sections
    asm_out.append("\n/* Embedded Data & BSS Sections */")
    data_sec_names = ['.rodata', '.eh_frame', '.ctors', '.dtors', '.data', '.bss']
    for sec_name in data_sec_names:
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
                offset = 0
                while offset < len(data_bytes):
                    cur_addr = base_addr + offset

                    if cur_addr in referenced_data_addrs or offset == 0:
                        if chunk:
                            b_str = ", ".join(f"0x{x:02x}" for x in chunk)
                            asm_out.append(f"    .byte {b_str}")
                            chunk = []
                        asm_out.append(f"data_{cur_addr:x}:")

                    # Pre-relocate 8-byte code pointers
                    if offset % 8 == 0 and offset + 8 <= len(data_bytes):
                        val = struct.unpack('<Q', data_bytes[offset:offset+8])[0]
                        if val in all_instruction_addrs:
                            if chunk:
                                b_str = ", ".join(f"0x{x:02x}" for x in chunk)
                                asm_out.append(f"    .byte {b_str}")
                                chunk = []
                            asm_out.append(f"    .quad loc_{val:x} /* pre-relocated code pointer 0x{val:x} */")
                            offset += 8
                            continue

                    b = data_bytes[offset]
                    chunk.append(b)
                    if len(chunk) >= 16:
                        b_str = ", ".join(f"0x{x:02x}" for x in chunk)
                        asm_out.append(f"    .byte {b_str}")
                        chunk = []
                    offset += 1

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
    try:
        transpile(args.input_elf, asm_file)
    except Exception as e:
        sys.stderr.write(f"[-] Transpilation error: {e}\n")
        if not args.keep_asm and os.path.exists(asm_file):
            try:
                os.remove(asm_file)
            except OSError:
                pass
        sys.exit(1)

    print(f"[*] Assembling native AArch64 binary: {args.output}...")
    _, sections = parse_elf_sections(args.input_elf)
    has_fixed_addrs = any(s['addr'] >= 0x400000 for s in sections.values())

    lds_file = None
    extra_link_args = []
    if has_fixed_addrs:
        lds_file = args.output + ".ld"
        rodata_base = sections.get('.rodata', {}).get('addr', 0x4d9860)
        data_candidates = [s['addr'] for name, s in sections.items() if name in ('.data', '.ctors', '.dtors', '.bss') and s['addr'] >= 0x400000]
        data_base = min(data_candidates) if data_candidates else 0x711fe0
        max_data_end = max(s['addr'] + s['size'] for s in sections.values() if s['addr'] >= 0x400000)
        text_base = ((max_data_end + 0xffff) // 0x10000) * 0x10000
        lds_content = f"""ENTRY(_start)
SECTIONS
{{
    . = 0x{rodata_base:x};
    .rodata : {{
        *(.rodata)
        *(.eh_frame)
    }}

    . = 0x{data_base:x};
    .data : {{
        *(.ctors)
        *(.dtors)
        *(.data)
    }}
    .bss : {{
        *(.bss)
        *(COMMON)
    }}

    . = ALIGN(0x10000);
    . = 0x{text_base:x};
    .text : {{
        *(.text*)
    }}
    .dispatch_table : {{
        *(.dispatch_table)
    }}
}}
"""
        with open(lds_file, 'w') as f:
            f.write(lds_content)
        extra_link_args = [f"-Wl,-T,{lds_file}"]

    cmd = ['clang', '-O2', '-nostdlib', '-static'] + extra_link_args + [asm_file, '-o', args.output]
    try:
        subprocess.run(cmd, check=True)
    except Exception as e:
        sys.stderr.write(f"[-] Clang error: {e}\n")
        if not args.keep_asm and os.path.exists(asm_file):
            try:
                os.remove(asm_file)
            except OSError:
                pass
        if not args.keep_asm and lds_file and os.path.exists(lds_file):
            try:
                os.remove(lds_file)
            except OSError:
                pass
        sys.exit(1)

    if not args.keep_asm and os.path.exists(asm_file):
        os.remove(asm_file)
    if not args.keep_asm and lds_file and os.path.exists(lds_file):
        os.remove(lds_file)

    print(f"[✓] Success! Native AArch64 ELF created: {args.output}")

if __name__ == "__main__":
    main()
