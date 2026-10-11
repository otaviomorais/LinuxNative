/* Real x86_64 Linux Application: Mini Tool Suite (File Inspector & Math Engine) */

static long sys_write(int fd, const void *buf, unsigned long count) {
    register long rax __asm__("rax") = 1;
    register long rdi __asm__("rdi") = fd;
    register const void *rsi __asm__("rsi") = buf;
    register unsigned long rdx __asm__("rdx") = count;
    __asm__ volatile("syscall" : "+r"(rax) : "r"(rdi), "r"(rsi), "r"(rdx) : "rcx", "r11", "memory");
    return rax;
}

static long sys_open(const char *pathname, int flags, int mode) {
    register long rax __asm__("rax") = 2;
    register const char *rdi __asm__("rdi") = pathname;
    register long rsi __asm__("rsi") = flags;
    register long rdx __asm__("rdx") = mode;
    __asm__ volatile("syscall" : "+r"(rax) : "r"(rdi), "r"(rsi), "r"(rdx) : "rcx", "r11", "memory");
    return rax;
}

static long sys_read(int fd, void *buf, unsigned long count) {
    register long rax __asm__("rax") = 0;
    register long rdi __asm__("rdi") = fd;
    register void *rsi __asm__("rsi") = buf;
    register unsigned long rdx __asm__("rdx") = count;
    __asm__ volatile("syscall" : "+r"(rax) : "r"(rdi), "r"(rsi), "r"(rdx) : "rcx", "r11", "memory");
    return rax;
}

static long sys_close(int fd) {
    register long rax __asm__("rax") = 3;
    register long rdi __asm__("rdi") = fd;
    __asm__ volatile("syscall" : "+r"(rax) : "r"(rdi) : "rcx", "r11", "memory");
    return rax;
}

static void sys_exit(int code) {
    register long rax __asm__("rax") = 60;
    register long rdi __asm__("rdi") = code;
    __asm__ volatile("syscall" : "+r"(rax) : "r"(rdi) : "memory");
    __builtin_unreachable();
}

static unsigned long my_strlen(const char *s) {
    unsigned long n = 0;
    while (s && s[n]) n++;
    return n;
}

static void print_str(const char *s) {
    sys_write(1, s, my_strlen(s));
}

static void print_num(long n) {
    char buf[32];
    int i = 0;
    if (n == 0) {
        print_str("0");
        return;
    }
    if (n < 0) {
        print_str("-");
        n = -n;
    }
    while (n > 0) {
        buf[i++] = '0' + (n % 10);
        n /= 10;
    }
    for (int j = 0; j < i / 2; j++) {
        char tmp = buf[j];
        buf[j] = buf[i - 1 - j];
        buf[i - 1 - j] = tmp;
    }
    buf[i] = '\0';
    print_str(buf);
}

static int my_strcmp(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static long my_atoi(const char *s) {
    long res = 0;
    int sign = 1;
    if (*s == '-') { sign = -1; s++; }
    while (*s >= '0' && *s <= '9') {
        res = res * 10 + (*s - '0');
        s++;
    }
    return res * sign;
}

static void do_wc(const char *filepath) {
    char clean_path[512];
    const char *open_target = filepath;
    if (filepath && filepath[0] != '/') {
        clean_path[0] = '/';
        int k = 0;
        while (filepath[k] && k < 509) {
            clean_path[k + 1] = filepath[k];
            k++;
        }
        clean_path[k + 1] = '\0';
        open_target = clean_path;
    }
    int fd = (int)sys_open(open_target, 0 /* O_RDONLY */, 0);
    if (fd < 0) {
        print_str("Error: could not open file '");
        print_str(filepath);
        print_str("'\n");
        return;
    }

    char buf[512];
    long nread;
    long lines = 0, words = 0, bytes = 0;
    int in_word = 0;

    while ((nread = sys_read(fd, buf, sizeof(buf))) > 0) {
        bytes += nread;
        for (long i = 0; i < nread; i++) {
            char c = buf[i];
            if (c == '\n') lines++;
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                in_word = 0;
            } else if (!in_word) {
                in_word = 1;
                words++;
            }
        }
    }
    sys_close(fd);

    print_str("  Lines: ");
    print_num(lines);
    print_str(" | Words: ");
    print_num(words);
    print_str(" | Bytes: ");
    print_num(bytes);
    print_str(" | File: ");
    print_str(filepath);
    print_str("\n");
}

int main(int argc, char **argv) {
    print_str("\n=======================================================\n");
    print_str("  LinuxNative: Real x86_64 Application Execution Demo  \n");
    print_str("=======================================================\n\n");

    print_str("[+] Guest Process Initialized:\n");
    print_str("    - Architecture: x86_64 (Transpiled AOT to AArch64)\n");
    print_str("    - Argument Count (argc): ");
    print_num(argc);
    print_str("\n");

    for (int i = 0; i < argc; i++) {
        print_str("    - argv[");
        print_num(i);
        print_str("] = '");
        print_str(argv[i]);
        print_str("'\n");
    }

    if (argc < 2) {
        print_str("\n[!] Usage:\n");
        print_str("    ./lnative real_app_x86 --calc <num1> <op> <num2>\n");
        print_str("    ./lnative real_app_x86 --file <path_to_file>\n");
        return 0;
    }

    if (my_strcmp(argv[1], "--calc") == 0 && argc >= 5) {
        long a = my_atoi(argv[2]);
        const char *op = argv[3];
        long b = my_atoi(argv[4]);
        long result = 0;

        print_str("\n[*] Math Engine Calculation:\n    ");
        print_num(a);
        print_str(" ");
        print_str(op);
        print_str(" ");
        print_num(b);
        print_str(" = ");

        if (my_strcmp(op, "+") == 0) result = a + b;
        else if (my_strcmp(op, "-") == 0) result = a - b;
        else if (my_strcmp(op, "*") == 0 || my_strcmp(op, "x") == 0) result = a * b;
        else if (my_strcmp(op, "/") == 0) result = (b != 0) ? (a / b) : 0;
        else if (my_strcmp(op, "%") == 0) result = (b != 0) ? (a % b) : 0;

        print_num(result);
        print_str("\n");
    } else if (my_strcmp(argv[1], "--file") == 0 && argc >= 3) {
        print_str("\n[*] Analyzing File Content:\n");
        do_wc(argv[2]);
    } else {
        print_str("\n[*] Processing Argument: ");
        print_str(argv[1]);
        print_str("\n");
    }

    print_str("\n[✓] Program finished with exit code 0.\n\n");
    return 0;
}

__attribute__((naked)) void _start(void) {
    __asm__ volatile(
        "mov (%rsp), %rdi\n"
        "lea 8(%rsp), %rsi\n"
        "call main\n"
        "mov %rax, %rdi\n"
        "mov $60, %rax\n"
        "syscall\n"
    );
}
