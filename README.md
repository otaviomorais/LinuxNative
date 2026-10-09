# LinuxNative

An experimental Debian/Linux compatibility runtime for **Android ARM64 without
root or ptrace**. Milestone 0 proves direct syscall rewriting for a deliberately
small class of static ELF programs. It does **not** yet run arbitrary Debian
packages, BusyBox, Python, Go, or an entire Debian userland.

The loader replaces each supported guest `svc #0` with a direct branch to an
in-process gateway. The gateway implements a small syscall ABI and returns to
the original next instruction. There is no ptrace supervisor, signal-based
syscall trap, seccomp notification broker, or CPU emulator in the runtime.
QEMU is used only to test ARM64 code on x86_64 development machines.

## Current evidence

- Cross-compiled with GCC 14 and executed with QEMU user mode 10 on Linux x86_64.
- 23 integration tests pass: actual file redirection, negative errno, exit
  status, integer/NEON/flags preservation, embedded instruction-looking data,
  unchanged input ELF, and malformed/unsupported ELF rejection.
- Android device execution is **pending**, including the user's Poco F3
  (reported Android 17). Linux/QEMU results do not establish Android compatibility.
- The native ARM64 CI workflow is provided but has not been run remotely.

## Build and test

On Debian/Ubuntu x86_64, install `gcc-aarch64-linux-gnu`,
`libc6-dev-arm64-cross`, `qemu-user`, `make`, and `python3`, then:

```sh
make
make test
```

On the Debian 13 cloud development machine, a rootless bootstrap downloads
packages using Debian's signed APT metadata and extracts them outside the repo:

```sh
sh tools/bootstrap-cloud.sh
. /workspace/.linuxnative-tools/activate.sh
make test
```

The default tool directory is `.linuxnative-tools` beside this checkout; set
`LN_TOOLS_DIR` to override it. The bootstrap reuses its verified installation.
It follows Debian trixie package updates; it is not a bit-reproducible toolchain lock.

On native Linux ARM64:

```sh
make CC=gcc RUNNER= test
```

### Android / Termux

Keep the checkout inside Termux's private `$HOME`, not `/sdcard`. The runtime
must be built with Termux's compiler so it uses Android's Bionic libraries.
The cloud's static glibc runtime is not the recommended Android executable.

```sh
pkg install git clang make python
git clone --branch main https://github.com/otaviomorais/LinuxNative.git ~/LinuxNative
cd ~/LinuxNative
sh tools/test-termux.sh
```

This runs the same tests directly on the CPU, without QEMU, root, or ptrace.
It records limited device metadata, build output, and test results in
`build/device-info.txt`, `build/device-build.log`, and `build/device-test.log`.
It does not collect serial numbers, accounts, or environment-variable values.
See [device setup instructions](docs/device-testing.md), including what to do
if that checkout directory already exists.

### Manual example on the cloud machine

```sh
mkdir -p build/demo-root/etc
printf 'Hello from the mapped Debian directory!\n' > build/demo-root/etc/linuxnative-probe.txt
qemu-aarch64 build/lnative --verbose --root build/demo-root build/probe
```

On a native ARM64 machine, omit `qemu-aarch64`. The test program first checks
register preservation and error behavior, then reads `/etc/linuxnative-probe.txt`
from the selected root and writes its contents to stdout. The original ELF is
never modified on disk.

## Milestone 0 contract

- Trusted, little-endian AArch64 `ET_EXEC`; static, non-PIE, without TLS.
- Complete AArch64 `$x`/`$d` mapping symbols, retained section/symbol tables,
  and one code section per executable load segment. Stripped binaries are refused.
- Non-overlapping load-segment pages, no writable executable segments, and an
  image span no larger than 32 MiB. Fixed guest addresses must be available.
- Single thread; no guest signals, process creation, dynamic loading, JIT,
  self-modifying code, SVE/SME, or modifications to the host TLS pointer.
- Valid guest pointers and aligned, sufficiently sized guest stacks.
- Syscalls: `openat` (absolute paths, read-only, optionally `O_CLOEXEC`), `read`,
  `write`, `close`, `exit`, `exit_group`. Others return raw `-ENOSYS`.
- Unsupported open modes and relative paths return `-EOPNOTSUPP`; `..` components
  return `-EACCES`. No claim of a complete Linux filesystem or process ABI.

**This is not a sandbox.** Guest code shares memory and privileges with the
runtime. It can access inherited descriptors and host memory; symlinks can lead
outside the selected root. Mapping symbols are trusted metadata, not a security
boundary. Never run untrusted programs with this prototype.

The runtime cannot grant privileges denied by Android's kernel, SELinux, or
seccomp. It uses RW-then-RX memory permissions, never RWX; executable mappings
still require validation in the actual Android app context.

## Next milestones

1. Validate this mechanism on Android hardware, including Bionic, executable
   memory policy, instruction-cache coherence, and 4/16 KiB pages.
2. Expand the tested syscall and process ABI, with differential Linux tests.
3. Add a loader and rewriting strategy for ordinary dynamic/stripped binaries.
4. Address threads, signals, exec, and code generated at runtime.
5. Measure correctness and performance against native Linux and PRoot workloads.

No novelty or near-native performance claim has been established. This source
is a new prototype, not a copy of deb-native. See [architecture](docs/architecture.md).
