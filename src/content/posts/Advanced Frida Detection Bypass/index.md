---
title: "Advanced Frida Detection Bypass"
published: 2025-11-28
description: "A comprehensive guide to bypassing advanced Frida detection mechanisms in Android apps, including port detection, memory maps artifact scanning, and direct syscall hooking techniques."
tags: ["android", "mobile", "frida", "reverse-engineering", "anti-frida", "bypass", "native", "hooking", "security"]
category: "Mobile"
image: "./Gemini_Generated_Image_a931q3a931q3a931.png"
---

*( بِسْمِ اللَّـهِ الرَّحْمَـٰنِ الرَّحِيمِ )*

:::caution
FreePalestine
:::

---

# Introduction

In this noob-friendly writeup, I will explain and share some of the **advanced Frida detection techniques** I have faced during my last pentest engagements. However, due to confidentiality of the apps, we will use an open-source app which I found very matching to some of these advanced bypasses I encountered.

> **Sample APK**: [adv_frida_apk](https://github.com/fatalSec/android_in_app_protections/blob/main/adv_frida.apk)

---

# Prerequisites: Understanding Android Layers & Frida Internals

Before digging deep, I will explain some simple basic topics that will help us understand the flow of these detections.
I made them into flows, comparios, Q&A to make them easier to understand.

## 1. Java Level vs Native Level vs Low Level

First, we need to understand the 3 different levels when dealing with Android Apps.

### The Three Layers of Android

### Java Level (Dalvik/ART)

The topmost layer where your `MainActivity.java`, Activities, and Services live. This layer uses Android SDK APIs (`android.*`, `java.*`) and runs in the Android Runtime (ART) as interpreted or JIT-compiled DEX bytecode (`.dex` files inside the APK).

**Example:** `String password = editText.getText().toString();`

---

### Native Level (C/C++)

Connected to Java via **JNI (Java Native Interface)**. This layer consists of `.so` libraries (like `libnative-lib.so`, `libc.so`) containing compiled ARM64/ARM32 machine code. It provides direct memory access through pointers and is developed using the NDK (Native Development Kit). The `libc.so` is the C standard library containing functions like `printf`, `malloc`, `open`, `read`.

**Example:** `int fd = open("/proc/self/maps", O_RDONLY);`

---

### Low Level (Kernel)

Accessed from Native level via **System Calls** (`syscall`/`SVC #0`). This is the Linux Kernel handling direct hardware interaction, process/memory/file management. **Cannot be bypassed from userspace.**

**Example:** `SVC #0` with `x8=56` (openat syscall)

### How They Communicate

| From | To | Mechanism |
| --- | --- | --- |
| Java → Native | JNI | `System.loadLibrary("native")` then call `native void doCheck()` |
| Native → Java | JNI | `env->CallVoidMethod(obj, methodID)` |
| Native → Kernel | Syscall | `libc.so` wrapper OR direct `SVC #0` instruction |
| Kernel → Native | Return value | Syscall returns result in `x0` register |

---

## 2. What Happens When Frida Hooks an App?

### Frida Injection Process

When you run `frida -U -f com.app.target -l script.js`, here's what happens:

When you run Frida, the **frida-server** first receives commands from your PC while listening on port 27042 (the default port). It then spawns or attaches to the target process using `ptrace()` to gain control. Next, it injects **frida-agent-64.so** into the target process, which creates several artifacts in memory: `frida-agent-64.so` (main Frida agent library), `frida-gadget.so` (embedded gadget for spawn mode), `libfrida-gum.so` (Frida's hooking engine), `[anon:gum-js-loop]` (V8 JavaScript runtime memory), and various `[anon:frida-*]` allocations. These all appear in `/proc/self/maps` (we will learn about this file later).

Frida's **Gum engine** then hooks functions by modifying memory. For example, before hooking, `connect()` might have original instructions like `FF 43 00 91` and `FD 7B BF A9`. After hooking, these are replaced with `50 00 00 58` (`LDR X16, #8`), `00 02 1F D6` (`BR X16` - jump to trampoline), followed by the address of the hook handler. This means **memory is modified**. Finally, your JavaScript runs in the V8 engine inside the process, where `Java.perform()` uses ART internals for Java hooks.

### Java Runtime Side (ART)

When you use `Java.perform()` in Frida:

```jsx
Java.perform(function() {
    var Activity = Java.use("android.app.Activity");
    Activity.onCreate.implementation = function(bundle) {
        console.log("onCreate hooked");
        this.onCreate(bundle);
    };
});
```

Frida interacts with **ART (Android Runtime)** internals:

- Uses `art::Runtime` to access class definitions
- Modifies **ArtMethod** structures to redirect method calls
- Replaces method entry points with trampoline code

### Native Side (libc, linker64)

**Q: What is linker64?**

> A: Android's dynamic linker for 64-bit. It's responsible for loading all .so libraries at runtime.
>

When you use `Interceptor.attach()` in Frida:

```jsx
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) { console.log("open called"); }
});

```

Frida's **Gum engine**:

- Finds function address in memory
- **Overwrites first instructions** with jump to trampoline
- Saves original bytes for calling the real function

### Important Frida Artifacts

These are the artificats that Frida leaves behind when hooking the app APIs or when even idle.

| Artifact | Location | Detection Method | Description |
| --- | --- | --- | --- |
| Port `27042` listening | Network | `connect()` to localhost:27042 | frida-server binds to this default TCP port to receive commands from the Frida client on your PC |
| `frida-agent-64.so` | /proc/self/maps | String search for "frida" | The main Frida agent library injected into the target process to execute JavaScript hooks |
| Modified function bytes | `libc.so` in memory | Checksum disk vs memory | Frida's Interceptor overwrites function prologues with trampolines (LDR X16; BR X16) to redirect execution |
| `/data/local/tmp/re.frida.server` | Filesystem | File existence check | Directory created by frida-server to store temporary files, gadgets, and agent libraries |

---

# Overview

This app has **3 anti-frida detection mechanisms** implemented in its native library `libantifrida.so`:

**Check 1: Frida Port Detection (27042)** — Detects Frida by attempting to connect to port `27042`.

**Check 2: Frida Artifacts in maps** — Scans `/proc/self/maps` for Frida-related strings.

**Check 3: libc Checksum Detection** — Compares in-memory `libc` bytes against to the one in the disk to detect tampering. (We will cover this later in another blog).

:::tip

Anti-frida code often lives in the **Native Level** because:

1. Harder to reverse engineer than Java (no easy decompilation)
2. Can use direct syscalls to bypass Frida's libc hooks
3. Lower-level = more control, fewer abstraction layers to trust

:::
---

# Check 1: Frida Port Detection (Port 27042)

## Technical Deep Dive

>This detection exploits the fact that `frida-server` binds to **TCP port 27042** on localhost (`127.0.0.1`) by default. The detection code uses the `connect()` libc function—which internally triggers the `SYS_connect` syscall. On ARM64 Android, the anti-frida library calls `connect()` with a `sockaddr_in` structure containing `sin_family = AF_INET (2)`, `sin_addr = 127.0.0.1`, and `sin_port = 27042` in network byte order. Network byte order is big-endian, so port 27042 (hex `0x69A2`) becomes `0xA269` when the bytes are swapped. The detection reads the port from `sockaddr_in` at offset +2 bytes from the structure base (after the 2-byte `sin_family` field). If `connect()` returns 0 (success), it means something is listening on that port—likely Frida.

## How the detection works

The anti-frida code first creates a TCP socket using `socket(AF_INET, SOCK_STREAM, 0)`. It then fills a `sockaddr_in` structure with `sin_family = AF_INET`, `sin_addr = 127.0.0.1`, and `sin_port = 27042` (in network byte order). Next, it calls `connect(fd, &addr, sizeof(addr))` to attempt a connection. If `connect()` returns 0 (success), `Frida` is detected because something is listening on that port. If it returns -1 (fail), no Frida is detected.

:::caution
`27042` is **not** the **only** port that a `developer` can search for, so you need to read/understand the code to figure out if there is any `port` configured by the devleopered to be scanned as well.
:::

## The Bypass

> Our bypass hooks `connect()` in `libc.so`, intercepts the call, reads the port from the sockaddr structure using pointer arithmetic, converts it from network to host byte order using `((port & 0xff) << 8) | (port >> 8)`, and if it matches 27042, we change it to a random port like 1337, causing the connection to fail harmlessly.
>
### Code

```jsx
// Find the memory address of the 'connect' function in libc.so
var connectPtr = Module.findExportByName("libc.so", "connect");

// Create a callable wrapper for the original connect function
var connect = new NativeFunction(connectPtr, 'int', ['int', 'pointer', 'int']);

// Replace connect() with our custom implementation
Interceptor.replace(connectPtr, new NativeCallback(function(fd, addr, len) {
    // Read address family (AF_INET = 2)
    var family = addr.readU16();

    // Read port from sockaddr_in structure (offset +2 bytes)
    // Port is in network byte order (big-endian)
    var port = addr.add(2).readU16();

    // Convert network byte order to host byte order (swap bytes)
    port = ((port & 0xff) << 8) | (port >> 8);

    // If trying to connect to Frida's default port...
    if(port == 27042){
        console.error(`[+] Bypassing frida port check...`);

        // Change to a different port (27043 or any unused port)
        var tmp = ((27043 >> 8) & 0xff) | ((27043 & 0xff) << 8);
        addr.add(2).writeU16(tmp);
    }

    // Call original connect with (possibly modified) parameters
    var retval = connect(fd, addr, len);
    return retval;
}, 'int', ['int', 'pointer', 'int']));


```

### Understanding The Byte Order

>Port `27042` in hexadecimal is `0x69A2`. In **network order (big-endian)**, bytes are stored as `0x69 0xA2` with the high byte first. In **host order (little-endian)**, bytes are stored as `0xA2 0x69` with the low byte first. The conversion formula `((port & 0xff) << 8) | (port >> 8)` works by: (1) extracting the low byte with `port & 0xff`, (2) shifting it to the high position with `<< 8`, (3) extracting the high byte with `port >> 8`, and (4) combining both bytes with `|`. The result is that the bytes are swapped.

:::note
I hate assembly.
:::

---

# Check 2: Frida Artifacts Detection (/proc/maps)

## Technical Deep Dive

> This detection abuses the Linux `/proc` filesystem, specifically `/proc/self/maps`, which is a virtual file provided by the kernel that lists all memory-mapped regions of the current process. Each line contains: `start_addr-end_addr permissions offset dev inode pathname`. When Frida injects `frida-agent-64.so` into the target process, new memory regions appear with telltale names like `frida-agent`, `frida-gadget`, `libfrida-gum.so`, or anonymous mappings named `[anon:gum-js-loop]`. The anti-frida library bypasses libc entirely and uses direct syscalls via `SVC #0` (ARM64 supervisor call instruction) to read this file—this is why we can't just hook `open()` or `fopen()` in libc. The library executes `openat` (syscall 56) with register `x0=AT_FDCWD (-100)`, `x1=pointer to "/proc/self/maps"`, `x2=O_RDONLY`. We find these syscall sites by disassembling `libantifrida.so` using Radare2 with `/asj svc` to locate all `SVC #0` instructions and their offsets (e.g., `{"addr":3868,"name":"openat","sysnum":56}`).

Before understanding more about how this detection works, we need to understand more about `proc` and about the `wrappers` and `syscalls`.

### What is /proc?

The `/proc` filesystem is a **virtual filesystem** in Linux that doesn't exist on disk—it's generated by the kernel in real-time to expose process and system information. Every running process has a directory `/proc/[pid]/` containing information about it.

### /proc/self/maps - Memory Map File

`/proc/self/maps` shows all memory regions mapped into the current process:

- **ADDRESS RANGE** (e.g., `749088f000-749098c000`)
- **PERMS** (permissions)
- **OFFSET**, **DEV** (device)
- **INODE**, and **PATHNAME**.

For example: `749088f000-749098c000 r--p 00000000 fd:00 123456 /system/lib64/libc.so`.
The permissions field uses the following notation: `r` = readable, `w` = writable, `x` = executable, `p` = private, and `s` = shared. This file is useful because it shows **every loaded library** (including `frida-agent-64.so`), shows **anonymous mappings** (including `[anon:gum-js-loop]`), and cannot be hidden from the kernel—it always shows the truth.

### /proc/self/status - Process Status File

`/proc/self/status` provides detailed process information in a human-readable format:

- **Name** (`com.example.app`) which is the process name
- **State** (`S (sleeping)`) showing the current state
- **Tgid** (`12345`) the thread group ID (PID)
- **Pid** (`12345`) the process ID
- **PPid** (`1234`) the parent process ID
- **TracerPid** (`0`) indicating who is tracing the process
- **Uid** (`10123 10123 10123 10123`) the user IDs
- **Gid** (`10123 10123 10123 10123`) the group IDs
- **VmSize** (`1234567 kB`) the virtual memory size
- **VmRSS** (`12345 kB`) the resident memory
- **Threads** (`15`) the number of threads.

:::tip
For **debugging/frida detection**, the key field is `TracerPid`: if it's non-zero, something is debugging/tracing this process. When Frida attaches via ptrace, `TracerPid` will equal frida-server's PID.
:::

### What is a Wrapper Function?

A **wrapper** is a convenient function in `libc.so` that prepares arguments and calls the kernel:

When your code calls `open("/proc/maps", 0)`, it goes through **libc.so's wrapper function** before reaching the kernel. The wrapper performs several tasks: it validates the arguments, then sets up the CPU registers with the appropriate values—`x0 = AT_FDCWD`, `x1 = "/proc/maps"`, `x2 = O_RDONLY`, and `x8 = 56` (the syscall number). Finally, it executes the `SVC #0` instruction to trigger the kernel's syscall handler.
`Frida` can hook the libc wrapper function, but it **cannot** hook inside the kernel itself.

### What is a Syscall?

A `syscall` (system call) is the interface between userspace and the kernel. On ARM64 (it differs depending on the arch):

On `ARM64`, syscalls use specific registers:

- `x8` holds the syscall number (which kernel function to call)
- `x0-x5` hold the arguments (1st through 6th), and the `SVC #0` instruction (Supervisor Call) triggers kernel mode. After the syscall returns
- `x0` contains the return value.

> **Resource:**: [syscalls.md](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#arm64-64_bit)

Common syscalls include: `56 (openat)` to open a file relative to a directory fd, `57 (close)` to close a file descriptor, `62 (lseek)` to move the file read/write position, `63 (read)` to read bytes from a file descriptor, and `64 (write)` to write bytes to a file descriptor.

:::warning
do not forget to check for the arch you are using :"D
:::

### Why Anti-Frida Code Uses Direct Syscalls

**Normal App (Uses libc Wrapper):**

When a normal app calls `int fd = open("/proc/self/maps", O_RDONLY);`, the execution flow is: `Code → libc.so::open() → SVC #0 → Kernel`. Frida hooks at the `libc.so::open()` level, where it can see arguments, modify them, and log calls.

**Anti-Frida Code (Direct Syscall):**

Anti-frida code bypasses libc entirely by using inline assembly:

```asm
mov x8, #56           // syscall number for openat
mov x0, #-100         // AT_FDCWD
ldr x1, ="/proc/self/maps"
mov x2, #0            // O_RDONLY
svc #0                // Direct to kernel
```

The execution flow becomes: `Code → SVC #0 → Kernel`. Frida **cannot hook by name** because there is no function name—just a raw instruction. You must hook the SVC instruction itself at a specific offset.

so the solution was to find `SVC #0` offsets in `libantifrida.so` using Radare2:

```bash
r2 libantifrida.so
/asj svc    # Search for all SVC instructions
```

Example output: `{"addr":3868,"name":"openat","sysnum":56}`

Then hook using: `Interceptor.attach(base.add(3868), {...})`

:::warning
do not forget the base address :"D
:::

## How the detection works

When Frida injects into a process, it loads libraries and creates memory regions that appear in `/proc/self/maps`. Anti-frida code scans this file looking for telltale strings.

### What Frida leaves behind in memory maps

```
  Normal entries...
  7a1234000-7a1235000 r-xp  /system/lib64/libc.so
  ...

  ╔════════════════════════════════════════════════════════════╗
  ║  FRIDA ARTIFACTS - THESE REVEAL FRIDA IS PRESENT           ║
  ╠════════════════════════════════════════════════════════════╣
  ║  7b5000000-7b5100000 r-xp  frida-agent-64.so               ║
  ║  7b5100000-7b5200000 rw-p  frida-agent-64.so               ║
  ║  7b6000000-7b6001000 r--p  frida-gadget.so                 ║
  ║  7b7000000-7b7010000 rw-p  [anon:gum-js-loop]              ║
  ║  7b8000000-7b8100000 r-xp  libfrida-gum.so                 ║
  ╚════════════════════════════════════════════════════════════╝


```

### Detection Flow

>The **artifacts detection flow** works as follows: The anti-frida code first calls `openat("/proc/self/maps")` to open the memory maps file. It then uses `read()` to process the file line by line. For each line, it searches for suspicious strings including `"frida"`, `"gadget"`, `"gum-js-loop"`, and `"frida-agent"`. If any of these strings are **found**, Frida is **detected**. If **not found**, the app concludes there is no Frida present.

## The Bypass

Actually in here we got 2 Strategies, we will dive into each one of them alone. Lets see which one will work.

## Strategy 1

>This  bypass hooks these specific offsets using `Interceptor.attach(base_addr.add(offset), {...})`. In the `onEnter` callback, we check if `x1` contains `"self/maps"` and redirect it to `/data/local/tmp/maps`—a fake maps file we created that contains no Frida artifacts.

SO, we will:

1. Run the app with `frida` attached, no scripts attached, dump the maps file.
2. Transfer the `maps` file to your PC and `replace` all strings that has the string `frida`.
3. Push back the `maps` file to `/data/local/tmp/maps` and give it `chmod 777`.
4. `Spawn` the app with the solver `script` below.
5. When anti-frida opens `/proc/self/maps`, redirect to our `fake` file.

### Code

```jsx
// Inside the syscall hook for openat (syscall 56)
case 56:
    // Check if opening /proc/self/maps
    if(this.context.x1.readCString().indexOf("self/maps") >= 1){
        console.error(`[+] bypassing maps...`);
        // Redirect to our clean fake maps file
        this.context.x1.writeUtf8String("/data/local/tmp/maps");
    }
    break;

```

### Bypass Flow

When the anti-frida code calls `openat("/proc/self/maps")`, our Frida hook intercepts the call. The hook checks if the path contains `"self/maps"`, and if so, redirects it to `"/data/local/tmp/maps"`. This causes the actual syscall to open our fake maps file instead.

The **fake maps file contents** contain only normal entries with no Frida strings:

```
7a1234000-7a1235000 /system/libc.so
... normal entries only ...
```

When the app searches for `"frida"` in the redirected file, it finds **nothing**. The app concludes: *"No Frida detected"*.

>However, this is not what happened :"(, the app kept `crashing`, or stuck at the `splash` screen. Thats why we made `Strategy 2` :"D
> My thought is this is happening as we are forcing the system to read the maps file  from another directory, while the frida logs show that it does open it, it takes too long to show that it closed it, which why something went wrong inside while reading/parsing it.

---

## Strategy 2

>In this bypass we evade basic Frida artifact checks (e.g. `/proc/pid/maps`, `/data/local/tmp/re.frida.server`) by patching the Android `frida-server` binary so all visible agent/server names become custom (`brida-bgent-*`).

I found this `article` with this `github` issue which talks about this idea/solution very helpful.

- [Detect Frida for Android - DarvinciTech](https://darvincitech.wordpress.com/2019/12/23/detect-frida-for-android/)
- [Github Issue](https://github.com/frida/frida-core/issues/310)

### 1. Download and unpack frida-server

Pick the right version/arch and unpack:

```bash
wget https://github.com/frida/frida/releases/download/16.5.6/frida-server-16.5.6-android-arm64.xz
unxz frida-server-16.5.6-android-arm64.xz
mv frida-server-16.5.6-android-arm64 frida-server
chmod +x frida-server
```

Quick recon of embedded strings:

```bash
strings frida-server | grep -i 'frida-agent'
strings frida-server | grep -i 're.frida.server'
```

### 2. Python patcher (frida → brida-bgent)

```python
from pathlib import Path

IN_PATH  = Path("frida-server")
OUT_PATH = Path("brida-bgent-server")  # you can change this to whatever you want.

REPLACEMENTS = {
    # Concrete agent .so names
    b"frida-agent-32.so":      b"brida-bgent-32.so",
    b"frida-agent-64.so":      b"brida-bgent-64.so",
    b"frida-agent-arm.so":     b"brida-bgent-arm.so",
    b"frida-agent-arm64.so":   b"brida-bgent-arm64.so",

    # Generic template string
    b"frida-agent-<arch>.so":  b"brida-bgent-<arch>.so",

    # Container / helper names
    b"frida-agent-container":  b"brida-bgent-container",

    # Raw agent libs
    b"libfrida-agent-raw.so":  b"libbrida-bgent-raw.so",

    # Directory name
    b"re.frida.server":        b"re.brida.server",
}

data = IN_PATH.read_bytes()

for orig, repl in REPLACEMENTS.items():
    if len(orig) = len(repl):
        raise ValueError(f"Length mismatch: {origr} vs {replr}")
    count = data.count(orig)
    if count == 0:
        print(f"[] Pattern not found: {origr}")
        continue
    print(f"[+] Replacing {count} occurrence(s) of {origr} with {replr}")
    data = data.replace(orig, repl)

OUT_PATH.write_bytes(data)
OUT_PATH.chmod(0o755)
print(f"[+] Wrote patched server to {OUT_PATH}")
```

Run:

```bash
python3 brida-patch.py
```

### 3. Verify patched artifacts

```bash
strings brida-bgent-server | grep -i 'frida-agent'
strings brida-bgent-server | grep -i 'brida-bgent'
strings brida-bgent-server | grep -i 're.frida.server'
strings brida-bgent-server | grep -i 're.brida.server'
```

Expected: only the harmless error message still contains `frida-agent`, all real artifacts are `brida-bgent-*` and `re.brida.server`.

### 4. Deploy on device

```bash
adb push brida-bgent-server /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"
```

Attach from PC as usual (same frida CLI / version). On target app:

```bash
adb shell "grep -i brida /proc/$(pidof <package>)/maps"
adb shell "grep -i frida /proc/$(pidof <package>)/maps"
adb shell "ls -R /data/local/tmp | grep -i brida"
```

And this strategy worked like a charm.
Now `/proc/pid/maps` and `/data/local/tmp` expose `brida-bgent-*.so` and `re.brida.server`, so naive Frida name-based detections on `frida-agent.so` / `re.frida.server` no longer fire.

:::tip
can you think of another way to bypass this ? :D
:::

## Some Questions that came to my mind

**Q: Why use `/proc/self/maps`?**

> A: This special file shows ALL memory regions mapped into the current process. It's provided by the Linux kernel and always shows what's really loaded, so, triying to remove such file will cause the app even the system to crash

**Q: What strings does anti-frida look for?**

> A: Common ones include:
>
> - `gadget` - frida-gadget.so
> - `gum` - frida's Gum engine
> - `agent` - frida-agent.so

**Q: Why can't we just search by module and hook directly?**

> A: Because `libantifrida.so` doesn't exist in memory when our script starts. It's loaded later by the app at runtime.

**Q: Why Direct Syscall Hooking is Necessary?**

> Normal hooking by function name **won't work** because `libantifrida.so` uses **direct syscalls**, bypassing `libc` entirely.

**Q: Why not just hook by function name like `openat`, `read`, `close`?**

> A: Because anti-frida code doesn't call libc functions. It uses direct `syscalls`.

**Q: What's the difference?**

Normal App

```
App code → libc.so (openat function) → kernel syscall
              ↑
         Frida can hook here
```

Anti-Frida Code

```
App code → SVC #0 instruction (direct syscall) → kernel
              ↑
         No function to hook Must hook the SVC instruction itself.
```

---

## Lessons Learned

> Sometimes you can't just hook everything or fake/block every check—doing so will lead to crashes, timeouts, unintended behaviors, and an unstable runtime. Instead, it's often better to use a **workaround** and view the detection from the other side. This approach typically requires **less effort**, **less overthinking**, and yields **better results**.
---

## Credits & Resources

This writeup is based on the work of **fatalSec**. The sample APK and solver scripts used in this guide are his creations—full credit goes to him.

- **YouTube Tutorial**: [Advanced Frida Detection Bypass](https://www.youtube.com/watch?v=FNtzJDU5BAI)
- **GitHub Repository**: [android_in_app_protections](https://github.com/fatalSec/android_in_app_protections)

---

<!-- # Check 3: libc Checksum-Based Detection

> Technical Deep Dive: This is the most sophisticated detection method. It exploits the fact that Frida's Interceptor modifies executable code in memory—when you hook a function like connect(), Frida overwrites the first few instructions with a trampoline (typically LDR X16, #8; BR X16 followed by the hook address) that redirects execution to your handler. The detection works as follows: First, it parses /proc/self/maps to find libc.so entries with r-xp (read-execute) permissions—these are the executable code sections. It extracts the memory address range (e.g., 749098c000-7490abf000) and the file path (/system/lib64/libc.so). Then it performs two reads: (1) Memory read: directly read bytes from the mapped memory addresses, (2) Disk read: open the libc.so file using openat (syscall 56), use lseek (syscall 62) to navigate to the correct offset within the file (since the executable section isn't always at offset 0), then read (syscall 63) the same number of bytes. Finally, it computes checksums (MD5/CRC32) of both and compares them. If Frida has hooked any libc function, the memory bytes will differ from disk bytes, causing a mismatch. Our bypass is elegant: since this detection depends on parsing /proc/self/maps to find libc.so's address, we simply remove or rename libc.so entries in our fake maps file. When the detection code searches for "libc.so" in the redirected fake maps, it finds nothing—so it can't determine where libc is in memory, can't compute the checksum, and the check becomes a no-op. The detection code trusts /proc/self/maps to be accurate, and we exploit that trust.
>

## The Issue

Frida hooks functions in `libc.so` by modifying the in-memory code (inserting jump instructions to trampolines). This changes the bytes in memory compared to the original file on disk.

## Thinking Process

### How the checksum detection works

```
┌────────────────────────────────────────────────────────────────────┐
              CHECKSUM DETECTION LOGIC                               
├────────────────────────────────────────────────────────────────────┤
                                                                    
   Step 1: Find libc.so in /proc/self/maps                          
   ┌─────────────────────────────────────────────────────────────┐ 
    /proc/self/maps contains:                                     
    749088f000-749098c000 r--p  /system/lib64/libc.so            
    749098c000-7490abf000 r-xp  /system/lib64/libc.so  ← CODE    
   └─────────────────────────────────────────────────────────────┘ 
                                                                   
         ▼                                                          
   Step 2: Extract memory addresses                                 
   ┌─────────────────────────────────────────────────────────────┐ 
    Start: 0x749098c000                                           
    End:   0x7490abf000                                           
    Path:  /system/lib64/libc.so                                  
   └─────────────────────────────────────────────────────────────┘ 
                                                                   
         ├─────────────────────┬────────────────────────┐          
         ▼                     ▼                                  
   ┌──────────────┐     ┌──────────────┐                         
     DISK READ         MEMORY READ                           
                                                             
    Open file at       Read memory                           
    path from          at addresses                          
    maps               from maps                             
   └──────────────┘     └──────────────┘                         
                                                                
         ▼                     ▼                                  
   ┌──────────────┐     ┌──────────────┐                         
     CHECKSUM A         CHECKSUM B                           
     (Original)         (Current)                            
   └──────────────┘     └──────────────┘                         
                                                                
         └──────────┬──────────┘                                  
                    ▼                                             
            ┌──────────────┐                                     
               COMPARE                                         
               A == B ?                                        
            └──────────────┘                                     
                                                                 
         ┌──────────┴──────────┐                                 
         ▼                     ▼                                 
   ┌──────────┐         ┌──────────┐                            
     EQUAL                NOT EQUAL                             
       ✓                  ✗                                 
   └──────────┘         └──────────┘                            
                                                               
         ▼                     ▼                                 
   ┌──────────┐         ┌──────────┐                            
    No Frida              FRIDA                               
                          DETECTED                            
   └──────────┘         └──────────┘                            
                                                                    
└────────────────────────────────────────────────────────────────────┘

```

### Why checksums don't match with Frida

```
┌────────────────────────────────────────────────────────────────────┐
            WHAT FRIDA DOES TO libc.so IN MEMORY                     
├────────────────────────────────────────────────────────────────────┤
                                                                    
   ORIGINAL libc.so (on disk):                                      
   ┌─────────────────────────────────────────────────────────────┐ 
    Address       Original Bytes       Function                
   ├─────────────────────────────────────────────────────────────┤ 
    0x1000        FF 43 00 91          connect() start         
    0x1004        FD 7B BF A9          connect() prologue      
    ...           ...                  ...                     
   └─────────────────────────────────────────────────────────────┘ 
                                                                    
   MODIFIED libc.so (in memory with Frida):                         
   ┌─────────────────────────────────────────────────────────────┐ 
    Address       Modified Bytes       What it does            
   ├─────────────────────────────────────────────────────────────┤ 
    0x1000        50 00 00 58          LDR X16, #8             
    0x1004        00 02 1F D6          BR X16 (jump to hook)   
    0x1008        XX XX XX XX          Hook address            
    ...           ...                  ...                     
   └─────────────────────────────────────────────────────────────┘ 
                                                                    
   Frida replaced the first instructions with a TRAMPOLINE         
   These different bytes cause checksum mismatch.                   
                                                                    
└────────────────────────────────────────────────────────────────────┘

```

## Questions & Answers

**Q: What is `lseek`?**

> A: lseek = "long seek" - it moves the file read/write cursor position.
>
>
> ```c
> lseek(fd, 0, SEEK_SET);    // Go to beginning (byte 0)
> lseek(fd, 100, SEEK_SET);  // Go to byte 100
> lseek(fd, -50, SEEK_END);  // Go to 50 bytes before end
> 
> ```
>
> Used when computing checksum to navigate to specific sections of [libc.so](http://libc.so/)
>

**Q: What do the syscall numbers mean?**

> A: They are Linux kernel syscall identifiers (ARM64):
>
>
>
> | sysnum | Name | Purpose |
> | --- | --- | --- |
> | 56 | openat | Open a file |
> | 57 | close | Close a file descriptor |
> | 62 | lseek | Move read position in file |
> | 63 | read | Read data from file |

**Q: What does the [libc.so](http://libc.so/) part of the code actually do?**

> if(this.context.x1.readCString().indexOf("libc.so") >= 1){
var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
.map(DebugSymbol.fromAddress).join("\\n\\t");
console.log("\\nBacktrace:" + backtrace);
}
>
>
> A: This code **does NOT bypass** the checksum check It only **LOGS** when [libc.so](http://libc.so/) is being accessed. The backtrace shows the call chain - used for debugging/analysis to understand how the check works.
>

**Q: How did removing [libc.so](http://libc.so/) from maps bypass the checksum?**

> A: The checksum code relies on /proc/self/maps to find libc.so By removing or renaming libc.so entries in the fake maps file:
>
> - The code can't find where libc is in memory
> - It can't get the file path to read from disk
> - **The check effectively becomes a no-op**

## The Bypass

### Strategy

**Same fake maps file** used for Check 2, but also remove/rename `libc.so` entries

### Why This Works

```
┌────────────────────────────────────────────────────────────────────┐
                 WHY REMOVING LIBC FROM MAPS WORKS                   
├────────────────────────────────────────────────────────────────────┤
                                                                    
   ORIGINAL ATTACK (without bypass):                                
   ┌─────────────────────────────────────────────────────────────┐ 
    1. Open /proc/self/maps                                       
    2. Find line containing "libc.so"                             
    3. Parse address: 749098c000-7490abf000                      
    4. Read memory at 0x749098c000                                
    5. Compute checksum of memory contents                        
    6. Compare to disk checksum                                   
    7. Frida modified memory → MISMATCH → DETECTED               
   └─────────────────────────────────────────────────────────────┘ 
                                                                    
   WITH BYPASS (libc.so removed from fake maps):                    
   ┌─────────────────────────────────────────────────────────────┐ 
    1. Open /proc/self/maps → REDIRECTED to fake file            
    2. Find line containing "libc.so" → NOT FOUND               
    3. Can't get address → Can't compute checksum                
    4. Check FAILS SILENTLY or SKIPS                             
    5. NO DETECTION                                            
   └─────────────────────────────────────────────────────────────┘ 
                                                                    
   The checksum code TRUSTS /proc/self/maps to tell it where       
   libc is. We LIE to it, and it never checks the real libc       
                                                                    
└────────────────────────────────────────────────────────────────────┘

```

### Bypass Flow

```
┌────────────────────────────────────────────────────────────────────┐
                    BYPASS FLOW                                      
├────────────────────────────────────────────────────────────────────┤
                                                                    
   Anti-Frida Checksum Code                                         
                                                                   
         ▼                                                          
   openat("/proc/self/maps")                                        
                                                                   
         ▼                                                          
   ┌─────────────────────────────────────┐                         
        OUR HOOK REDIRECTS TO                                    
        /data/local/tmp/maps                                     
   └─────────────────────────────────────┘                         
                                                                   
         ▼                                                          
   ┌─────────────────────────────────────┐                         
     FAKE MAPS FILE:                                             
                                                                 
     - NO frida strings (Check 2)                                
     - NO libc.so entries (Check 3)                              
                                                                 
   └─────────────────────────────────────┘                         
                                                                   
         ▼                                                          
   Search for "libc.so" → NOT FOUND                                 
                                                                   
         ▼                                                          
   Cannot determine libc memory location                            
                                                                   
         ▼                                                          
   Checksum comparison SKIPPED                                      
                                                                   
         ▼                                                          
   App thinks: "No tampering detected"                            
                                                                    
└────────────────────────────────────────────────────────────────────┘

```

---

## Questions & Answers

**Q: Why can't we just search by module and hook directly?**

> A: Because libantifrida.so doesn't exist in memory when our script starts. It's loaded later by the app at runtime.
>

**Q: Why use `call_constructor` specifically?**

> A: Library loading has multiple stages:
>
>
>
> | Stage | What Happens | Can We Hook? |
> | --- | --- | --- |
> | `do_dlopen` starts | File path is known | ❌ Not mapped yet |
> | Memory mapping | Library loaded to memory | ❌ Not initialized |
> | `call_constructor` | Library's init code runs | **Perfect timing** |

## The Code Explained

```jsx
// Variables to store linker function addresses
var do_dlopen = null;       // Called when loading a library
var call_constructor = null; // Called after library is mapped

// Search linker64's symbols to find these functions
Process.findModuleByName("linker64").enumerateSymbols().forEach(function(symbol){
    if(symbol.name.indexOf("do_dlopen") >= 0){
        do_dlopen = symbol.address;
    }
    if(symbol.name.indexOf("call_constructor") >= 0){
        call_constructor = symbol.address;
    }
});

// Flag to prevent hooking multiple times
var lib_loaded = 0;

// Hook do_dlopen to monitor ALL library loads
Interceptor.attach(do_dlopen, function(){
    // x0 register contains the library path (ARM64 calling convention)
    var library_path = this.context.x0.readCString();

    // Check if THIS is the anti-frida library
    if(library_path.indexOf("libantifrida.so") >= 0){
        // Now hook the constructor to catch it AFTER it's fully loaded
        Interceptor.attach(call_constructor, function(){
            if(lib_loaded == 0){
                lib_loaded = 1;  // Only do this once

                // NOW we can get the module info
                var module = Process.findModuleByName("libantifrida.so");
                console.log(`[+] libantifrida is loaded at ${module.base}`);

                // Hook all the syscalls inside it
                hook_svc(module.base);
            }
        });
    }
});

```

### Timeline

```
┌────────────────────────────────────────────────────────────────────┐
                    EXECUTION TIMELINE                               
├────────────────────────────────────────────────────────────────────┤
                                                                    
  TIME ──────────────────────────────────────────────────────────►  
                                                                    
  App starts                                                        
                                                                   
      ▼                                                             
  Frida script loads ──────► libantifrida.so NOT LOADED YET        
                                                                   
      ▼                                                             
  Hook do_dlopen ──────────► Waiting for library loads...          
                                                                   
      ▼                                                             
  App calls dlopen("libantifrida.so")                               
                                                                   
      ├──► do_dlopen hook triggers ──► We know it's coming        
                                                                   
      ▼                                                             
  Library mapped to memory                                          
                                                                   
      ├──► call_constructor hook ──► NOW we hook syscalls         
                                                                   
      ▼                                                             
  Library's anti-frida checks run ──► But we already hooked them  
                                                                   
      ▼                                                             
  Checks bypassed                                                
                                                                    
└────────────────────────────────────────────────────────────────────┘

```

---

# The Fake Maps File

## What to Remove/Modify

### Original `/proc/self/maps` (REAL)

```
... normal entries ...
749088f000-749098c000 r--p 00000000  /system/lib64/libc.so      ← EDIT
749098c000-7490abf000 r-xp 00000000  /system/lib64/libc.so      ← EDIT
...
7b5000000-7b5100000 r-xp  frida-agent-64.so                     ← EDIT
7b6000000-7b6001000 r--p  frida-gadget.so                       ← EDIT
... normal entries ...

```

### Fake `/data/local/tmp/maps` (SANITIZED)

```
... normal entries ...
749088f000-749098c000 r--p 00000000  /system/lib64/xxxx.so      
749098c000-7490abf000 r-xp 00000000  /system/lib64/xxxx.so      
...
7b5000000-7b5100000 r-xp  xxxx-xxxx-64.so                     
7b6000000-7b6001000 r--p  xxxx-xxxx.so                                         
... normal entries ...

``` -->
