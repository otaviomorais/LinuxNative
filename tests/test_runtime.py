"""Functional tests of the actual AArch64 loader and syscall gateway."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parent.parent
RUNTIME = PROJECT / "build/lnative"
PROBE = PROJECT / "build/probe"
FILE_SCAN = PROJECT / "build/file-scan"
FILE_ABI = PROJECT / "build/file-abi"
MEM_ABI = PROJECT / "build/mem-abi"
MINI_LS = PROJECT / "build/mini-ls"
FS_MUT = PROJECT / "build/fs-mut"
PIE_ABI = PROJECT / "build/pie-abi"
RUNNER = []


def program_headers(data):
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    return [offset + i * size for i in range(count)]


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lnative test ")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root = self.directory / "root"
        (self.root / "etc").mkdir(parents=True)
        self.content = b"LinuxNative: root translation works\n"
        (self.root / "etc/linuxnative-probe.txt").write_bytes(self.content)

    def run_guest(self, image=PROBE, root=None, verbose=False, args=()):
        command = RUNNER + [str(RUNTIME)]
        if verbose:
            command.append("--verbose")
        command += ["--root", str(root or self.root), str(image)]
        command += list(args)
        return subprocess.run(command, capture_output=True, timeout=15)

    def run_direct(self, image, args=()):
        return subprocess.run(RUNNER + [str(image)] + list(args),
                              capture_output=True, timeout=15)

    def mutated(self, mutate):
        data = bytearray(PROBE.read_bytes())
        mutate(data)
        image = self.directory / "mutated.elf"
        image.write_bytes(data)
        return image

    def assert_rejected(self, mutate, reason):
        result = self.run_guest(self.mutated(mutate))
        self.assertEqual(result.returncode, 1, result.stderr.decode(errors="replace"))
        self.assertIn(reason.encode(), result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_file_mapping_registers_vectors_flags_errno_and_literal(self):
        result = self.run_guest(verbose=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, self.content)
        self.assertIn(b"patched 10 SVC sites", result.stderr)
        for value in (b"32767 -> -38", b"56 -> -2", b"56 -> -95", b"56 -> -13"):
            self.assertIn(value, result.stderr)

    def test_quiet_mode(self):
        result = self.run_guest()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, self.content)
        self.assertEqual(result.stderr, b"")

    def test_independent_roots(self):
        other = self.directory / "another root"
        (other / "etc").mkdir(parents=True)
        payload = b"a different root\x00binary content\n"
        (other / "etc/linuxnative-probe.txt").write_bytes(payload)
        result = self.run_guest(root=other)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, payload)

    def test_input_elf_is_unchanged(self):
        before = hashlib.sha256(PROBE.read_bytes()).digest()
        result = self.run_guest()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(hashlib.sha256(PROBE.read_bytes()).digest(), before)

    def test_guest_failure_status_propagates(self):
        (self.root / "etc/linuxnative-probe.txt").unlink()
        result = self.run_guest()
        self.assertEqual(result.returncode, 23, result.stderr.decode())
        self.assertEqual(result.stdout, b"")

    def test_probe_detects_register_corruption(self):
        def mutate(data):
            text = program_headers(data)[0]
            offset = struct.unpack_from("<Q", data, text + 8)[0]
            self.assertEqual(struct.unpack_from("<I", data, offset)[0], 0xD2800021)
            struct.pack_into("<I", data, offset, 0xD2800C61)  # mov x1, #99
        result = self.run_guest(self.mutated(mutate))
        self.assertEqual(result.returncode, 21, result.stderr.decode())

    def test_nonexistent_root(self):
        result = self.run_guest(root=self.directory / "absent")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"root directory", result.stderr)

    def test_truncated_file(self):
        self.assert_rejected(lambda d: d.clear(), "invalid file size")

    def test_wrong_architecture(self):
        self.assert_rejected(lambda d: struct.pack_into("<H", d, 18, 62), "AArch64 ET_EXEC")

    def test_pie_rejected(self):
        self.assert_rejected(lambda d: struct.pack_into("<H", d, 16, 3), "AArch64 ET_EXEC")

    def test_wrong_endianness(self):
        self.assert_rejected(lambda d: d.__setitem__(5, 2), "little-endian")

    def test_program_header_overflow(self):
        self.assert_rejected(lambda d: struct.pack_into("<Q", d, 32, 2**64 - 8), "program headers")

    def test_unaligned_program_headers(self):
        self.assert_rejected(lambda d: struct.pack_into("<Q", d, 32, 65), "program headers")

    def test_section_header_overflow(self):
        self.assert_rejected(lambda d: struct.pack_into("<Q", d, 40, 2**64 - 8), "section table")

    def test_stripped_metadata(self):
        self.assert_rejected(lambda d: struct.pack_into("<H", d, 60, 0), "mapping symbols")

    def test_writable_executable_segment(self):
        self.assert_rejected(
            lambda d: struct.pack_into("<I", d, program_headers(d)[0] + 4, 7),
            "writable-executable")

    def test_segment_outside_file(self):
        self.assert_rejected(
            lambda d: struct.pack_into("<Q", d, program_headers(d)[0] + 32, 2**64 - 1),
            "segment")

    def test_segment_address_overflow(self):
        self.assert_rejected(
            lambda d: struct.pack_into("<Q", d, program_headers(d)[0] + 16, 2**64 - 4),
            "segment")

    def test_overlapping_segments(self):
        def mutate(d):
            first, second, *_ = program_headers(d)
            address = struct.unpack_from("<Q", d, first + 16)[0]
            struct.pack_into("<Q", d, second + 16, address)
        self.assert_rejected(mutate, "overlapping")

    def test_dynamic_segment(self):
        self.assert_rejected(
            lambda d: struct.pack_into("<I", d, program_headers(d)[1], 2), "dynamic linking")

    def test_tls_segment(self):
        self.assert_rejected(
            lambda d: struct.pack_into("<I", d, program_headers(d)[1], 7), "TLS")

    def test_entry_in_data(self):
        def mutate(d):
            address = struct.unpack_from("<Q", d, program_headers(d)[1] + 16)[0]
            struct.pack_into("<Q", d, 24, address)
        self.assert_rejected(mutate, "entry point")

    def test_nonzero_svc_immediate(self):
        def mutate(d):
            site = d.index(struct.pack("<I", 0xD4000001))
            struct.pack_into("<I", d, site, 0xD4000021)
        self.assert_rejected(mutate, "unsupported SVC immediate")

    def test_c_file_inspector_matches_direct_execution_and_host(self):
        path = self.root / "etc/file with spaces-ação.bin"
        for content in (b"", b"C program running without ptrace\n", bytes(range(256)) * 41):
            with self.subTest(size=len(content)):
                path.write_bytes(content)
                os.chmod(path, 0o640)
                expected = path.stat()
                native = self.run_direct(FILE_SCAN, [str(path)])
                translated = self.run_guest(FILE_SCAN, args=["/etc/" + path.name])
                self.assertEqual(native.returncode, 0, native.stderr.decode())
                self.assertEqual(translated.returncode, 0, translated.stderr.decode())
                self.assertEqual(translated.stdout, native.stdout)
                actual = json.loads(translated.stdout)
                fingerprint = 14695981039346656037
                for value in content:
                    fingerprint = ((fingerprint ^ value) * 1099511628211) & ((1 << 64) - 1)
                self.assertEqual(actual, {
                    "size": expected.st_size, "mode": expected.st_mode,
                    "uid": expected.st_uid, "gid": expected.st_gid,
                    "nlink": expected.st_nlink, "ino": expected.st_ino,
                    "dev": expected.st_dev, "blksize": expected.st_blksize,
                    "blocks": expected.st_blocks,
                    "mtime_sec": expected.st_mtime_ns // 1_000_000_000,
                    "mtime_nsec": expected.st_mtime_ns % 1_000_000_000,
                    "fnv1a64": f"{fingerprint:016x}",
                })

    def test_c_program_usage_arguments(self):
        for args in ([], ["one", "two"], ["", ""]):
            with self.subTest(args=args):
                native = self.run_direct(FILE_SCAN, args)
                translated = self.run_guest(FILE_SCAN, args=args)
                self.assertEqual(native.returncode, 2)
                self.assertEqual(translated.returncode, native.returncode)
                self.assertEqual(translated.stderr, native.stderr)

    def test_c_program_missing_file(self):
        native = self.run_direct(FILE_SCAN, [str(self.root / "missing")])
        translated = self.run_guest(FILE_SCAN, args=["/missing"])
        self.assertEqual(native.returncode, 3)
        self.assertEqual(translated.returncode, native.returncode)
        self.assertEqual(translated.stderr, native.stderr)

    def test_c_program_directory_rejected(self):
        native = self.run_direct(FILE_SCAN, [str(self.root / "etc")])
        translated = self.run_guest(FILE_SCAN, args=["/etc"])
        self.assertEqual(native.returncode, 4)
        self.assertEqual(translated.returncode, native.returncode)
        self.assertEqual(translated.stderr, native.stderr)

    def test_file_abi_errors_and_64bit_seek_match_direct_execution(self):
        path = self.root / "etc/linuxnative-probe.txt"
        native = self.run_direct(FILE_ABI, [str(path)])
        translated = self.run_guest(FILE_ABI, args=["/etc/linuxnative-probe.txt"])
        self.assertEqual(native.returncode, 0, native.stderr.decode())
        self.assertEqual(translated.returncode, 0, translated.stderr.decode())
        self.assertEqual(translated.stdout, native.stdout)
        self.assertEqual(translated.stdout, b"file ABI ok\n")

    def test_compiled_c_elf_is_unchanged(self):
        before = hashlib.sha256(FILE_SCAN.read_bytes()).digest()
        result = self.run_guest(FILE_SCAN, args=["/etc/linuxnative-probe.txt"])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(hashlib.sha256(FILE_SCAN.read_bytes()).digest(), before)

    def test_guest_argument_stack_budget(self):
        result = self.run_guest(FILE_SCAN, args=["x" * 110000] * 5)
        self.assertEqual(result.returncode, 1, result.stderr.decode())
        self.assertIn(b"arguments exceed stack budget", result.stderr)

    def test_file_bytes_in_zero_memory_segment_rejected(self):
        self.assert_rejected(
            lambda d: struct.pack_into("<Q", d, program_headers(d)[1] + 40, 0),
            "segment")

    def test_c_file_inspector_empty_path_argument(self):
        native = self.run_direct(FILE_SCAN, [""])
        translated = self.run_guest(FILE_SCAN, args=[""])
        self.assertEqual(native.returncode, 3)
        self.assertEqual(translated.returncode, 3)
        self.assertEqual(translated.stderr, native.stderr)

    def test_memory_abi_matches_direct_execution(self):
        native = self.run_direct(MEM_ABI)
        translated = self.run_guest(MEM_ABI, verbose=True)
        self.assertEqual(native.returncode, 0, native.stderr.decode())
        self.assertEqual(translated.returncode, 0, translated.stderr.decode())
        self.assertEqual(translated.stdout, native.stdout)
        self.assertEqual(translated.stdout, b"memory ABI ok\n")
        self.assertIn(b"patched 19 SVC sites", translated.stderr)
        self.assertIn(b"syscall 160 -> 0", translated.stderr)
        self.assertIn(b"syscall 214", translated.stderr)
        self.assertIn(b"syscall 222", translated.stderr)

    def test_memory_security_policies_enforced(self):
        result = self.run_guest(MEM_ABI, args=["--security-check"])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"security policy ok\n")

    def test_mini_ls_directory_listing_and_heap_matches_direct_execution(self):
        native = self.run_direct(MINI_LS, [str(self.root / "etc")])
        translated = self.run_guest(MINI_LS, args=["/etc"], verbose=True)
        self.assertEqual(native.returncode, 0, native.stderr.decode())
        self.assertEqual(translated.returncode, 0, translated.stderr.decode())
        self.assertIn(b"entry: linuxnative-probe.txt type: 8\n", translated.stdout)
        self.assertIn(b"entries counted: 3\n", translated.stdout)
        self.assertIn(b"entries counted: 3\n", native.stdout)
        self.assertIn(b"syscall 172", translated.stderr)
        self.assertIn(b"syscall 174", translated.stderr)
        self.assertIn(b"syscall 61", translated.stderr)
        self.assertIn(b"syscall 222", translated.stderr)
        self.assertIn(b"syscall 215", translated.stderr)

    def test_mini_ls_non_directory_rejected(self):
        native = self.run_direct(MINI_LS, [str(self.root / "etc/linuxnative-probe.txt")])
        translated = self.run_guest(MINI_LS, args=["/etc/linuxnative-probe.txt"])
        self.assertEqual(native.returncode, 1)
        self.assertEqual(translated.returncode, 1)
        self.assertIn(b"mini-ls: open failed\n", translated.stdout)
        self.assertIn(b"mini-ls: open failed\n", native.stdout)
        self.assertIn(f"uid: {os.getuid()}\n".encode(), translated.stdout)
        self.assertIn(f"uid: {os.getuid()}\n".encode(), native.stdout)

    def test_filesystem_mutation_matches_direct_execution(self):
        base_native = str(self.directory / "testdir")
        native = self.run_direct(FS_MUT, [base_native])
        translated = self.run_guest(FS_MUT, args=["/testdir"], verbose=True)
        self.assertEqual(native.returncode, 0, native.stderr.decode())
        self.assertEqual(translated.returncode, 0, translated.stderr.decode())
        self.assertEqual(native.stdout, b"fs mutation ok\n")
        self.assertEqual(translated.stdout, b"fs mutation ok\n")
        self.assertIn(b"syscall 34", translated.stderr)
        self.assertIn(b"syscall 35", translated.stderr)
        self.assertIn(b"syscall 56", translated.stderr)
        self.assertIn(b"syscall 64", translated.stderr)

    def test_filesystem_security_policies_enforced(self):
        result = self.run_guest(FS_MUT, args=["--security-check"])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"fs security policy ok\n")

    def test_static_pie_matches_direct_execution(self):
        native = self.run_direct(PIE_ABI)
        translated = self.run_guest(PIE_ABI, verbose=True)
        self.assertEqual(native.returncode, 0, native.stderr.decode())
        self.assertEqual(translated.returncode, 0, translated.stderr.decode())
        self.assertEqual(native.stdout, b"static PIE ABI ok\n")
        self.assertEqual(translated.stdout, b"static PIE ABI ok\n")
        self.assertIn(b"syscall 172", translated.stderr)
        self.assertIn(b"syscall 174", translated.stderr)
        self.assertIn(b"syscall 222", translated.stderr)
        self.assertIn(b"syscall 215", translated.stderr)

    def test_stripped_binary_matches_direct_execution(self):
        stripped = self.directory / "file-scan.stripped"
        data = bytearray(FILE_SCAN.read_bytes())
        stripped.write_bytes(data)
        subprocess.run(["strip", str(stripped)], check=True)
        path = self.root / "etc/linuxnative-probe.txt"
        native = self.run_direct(FILE_SCAN, [str(path)])
        translated = self.run_guest(stripped, args=["/etc/linuxnative-probe.txt"], verbose=True)
        self.assertEqual(translated.returncode, 0, translated.stderr.decode())
        self.assertEqual(translated.stdout, native.stdout)
        self.assertIn(b"patched 19 SVC sites", translated.stderr)

    def test_stripped_mini_ls_matches_direct_execution(self):
        stripped = self.directory / "mini-ls.stripped"
        data = bytearray(MINI_LS.read_bytes())
        stripped.write_bytes(data)
        subprocess.run(["strip", str(stripped)], check=True)
        native = self.run_direct(MINI_LS, [str(self.root / "etc")])
        translated = self.run_guest(stripped, args=["/etc"], verbose=True)
        self.assertEqual(translated.returncode, 0, translated.stderr.decode())
        self.assertIn(b"entries counted: 3\n", translated.stdout)
        self.assertIn(b"entries counted: 3\n", native.stdout)

    def test_glibc_ldso_and_debian_utilities(self):
        ldso = Path("/data/data/com.termux/files/usr/glibc/lib/ld-linux-aarch64.so.1")
        glibc_root = Path("/data/data/com.termux/files/usr/glibc")
        if not ldso.exists() or not (glibc_root / "bin/true").exists():
            self.skipTest("glibc environment not available")
        # 1. Test /bin/true
        res_true = self.run_guest(ldso, root=glibc_root, args=["--library-path", "/lib", "/bin/true"], verbose=True)
        self.assertEqual(res_true.returncode, 0, res_true.stderr.decode())
        # 2. Test /bin/uname -s
        res_uname = self.run_guest(ldso, root=glibc_root, args=["--library-path", "/lib", "/bin/uname", "-s"])
        self.assertEqual(res_uname.returncode, 0, res_uname.stderr.decode())
        self.assertEqual(res_uname.stdout, b"Linux\n")
        # 3. Test /bin/echo
        res_echo = self.run_guest(ldso, root=glibc_root, args=["--library-path", "/lib", "/bin/echo", "DebianOK"])
        self.assertEqual(res_echo.returncode, 0, res_echo.stderr.decode())
        self.assertEqual(res_echo.stdout, b"DebianOK\n")



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", default=os.environ.get("RUNNER", "qemu-aarch64"))
    args, remainder = parser.parse_known_args()
    RUNNER = shlex.split(args.runner)
    unittest.main(argv=[__file__] + remainder, verbosity=2)
