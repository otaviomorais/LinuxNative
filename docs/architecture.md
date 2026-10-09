# Milestone 0: load-time syscall rewriting

The first experiment intentionally avoids the complexity of relocating arbitrary
instruction blocks. Original guest code keeps its linked addresses. Each
instruction-region `svc #0` becomes an unconditional `B` to a nearby 48-byte stub.
PC-relative guest instructions therefore retain their original meaning.

```text
guest SVC site -> B stub -> BLR runtime gateway -> C syscall dispatcher
                    ^                                |
                    +--------- gateway return -------+
                    |
                    B original site + 4
```

## Decoder boundary

The loader does not claim to disassemble arbitrary stripped executables. It
requires AArch64 ABI mapping symbols (`$x` for code, `$d` for data), checks their
ranges against section and segment bounds, and scans only aligned instruction
regions. A fixture contains a `0xd4000001` data word inside its executable section;
the probe verifies that this word is not rewritten.

This dependency excludes many distribution binaries. Future stripped-binary
support needs a more complete execution-control strategy; removing this check
and scanning raw bytes is not an acceptable substitute.

## Loading and permissions

ELF headers, table sizes, segment bounds, entry point, symbol strings, and mapping
regions are checked before mapping executable code. File size is bounded to
64 MiB, image span to 32 MiB, and patched sites to 65,536. Dynamic/TLS segments,
overlapping pages and writable executable segments are rejected.

The loader reserves the original guest address range plus gateway space with
`MAP_FIXED_NOREPLACE`. It refuses collisions and kernels that ignore this flag;
it never falls back to destructive `MAP_FIXED`. The reservation starts PROT_NONE,
segments become RW for copying/patching, and code becomes RX after cache
maintenance. The stub area follows the same RW-to-RX sequence. There is no RWX
mapping. Segment alignment is checked against the runtime's actual page size;
the test linker script separates segments at 64 KiB boundaries.

## Gateway ABI

The stub saves x16, x17 and the guest LR, loads the absolute gateway address,
calls it, restores those registers, and branches back. The gateway saves x0-x30,
NZCV, FPCR/FPSR and all 32 128-bit NEON registers; only x0 becomes the syscall
result. SVE/SME state is not supported. SP remains 16-byte aligned and is restored.

Before calling host C code, the gateway restores the host x18 captured at entry,
because Android reserves that register (including for shadow call stacks).
This is a synchronous, single-thread experiment, not signal-safe Android ABI
support. Guest code must not alter TPIDR_EL0 or otherwise corrupt host TLS.

There is one host process and a separate guarded guest stack. The initial stack
contains argc/argv, an empty environment, AT_PAGESZ and AT_NULL; it is not a
complete Linux auxiliary vector. The supported exit syscalls terminate this
process with the guest's status.

## Compatibility policy

An absolute guest file path is resolved relative to an open root-directory FD.
The host libc performs allowed operations and its `-1`/errno convention is
converted to Linux's raw negative errno convention. The runtime returns
`-ENOSYS` for unsupported syscalls instead of forwarding unknown operations.

This is compatibility routing, not confinement. Guest pointers are trusted;
invalid non-null pathname pointers can crash the process. File descriptors are
shared, symlinks are not contained, and malicious control flow can bypass metadata
assumptions. Even complete syscall rewriting would not alone isolate host memory.

## What the experiment establishes

A known static ARM64 guest can have all its declared syscall instruction sites
redirected in memory, preserving the tested register state and calling convention,
without ptrace or a signal trap. A test with deliberately corrupted register
initialization confirms that the guest's ABI checks actually fail.

It does not establish general Debian compatibility, Android compatibility before
on-device tests, full instruction coverage for unknown programs, async-signal
correctness, reproducible releases, security isolation, or a speed improvement.

The code is original to this repository. Future work should evaluate prior art
in syscall rewriting and dynamic binary instrumentation before claiming novelty.
