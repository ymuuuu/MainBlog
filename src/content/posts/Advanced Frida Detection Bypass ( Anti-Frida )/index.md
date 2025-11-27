---
title: "Advanced Frida Detection Bypass ( Anti-Frida )"
published: 2025-11-27
description: "To be changed"
tags: ["ios", "mobile", "android","frida", "hook", "advanced", "bypass", "native"]
category: "Mobile"
image: ""
---

In this noob friendly writeup, I will explain and share some of the advanced Frida detection I have faced during my last pentest engagments, however, due to confiednlty of the apps, we will use a open source app which I found very matching to some of these advanved bypasses I found.
you can found it repo here
<https://github.com/fatalSec/android_in_app_protections/blob/main/adv_frida.apk>

another useful source is this one
<https://darvincitech.wordpress.com/2019/12/23/detect-frida-for-android/>

---

# Prerequisites: Understanding Android Layers & Frida Internals

Before digging deep, I will explain some simple basic topics that will help us understand the flow of these detections.
I made them into flows, comparios, Q&A to make them easier to understand.

## 1. Java Level vs Native Level vs Low Level

### The Three Layers of Android

```
┌─────────────────────────────────────────────────────────────────────────────┐
                    ANDROID APPLICATION LAYERS                                
├─────────────────────────────────────────────────────────────────────────────┤
                                                                             
   ┌─────────────────────────────────────────────────────────────────────┐   
                         JAVA LEVEL (Dalvik/ART)                           
                                                                           
      • Your MainActivity.java, Activities, Services                       
      • Android SDK APIs (android.*, java.*)                              
      • Runs in Android Runtime (ART) - interpreted/JIT compiled          
      • DEX bytecode (.dex files inside APK)                                                                                                              
      Example: String password = editText.getText().toString();           
   └─────────────────────────────────────────────────────────────────────┘   
                                                                            
                JNI (Java Native Interface)                  
                              ▼                                              
   ┌─────────────────────────────────────────────────────────────────────┐   
                         NATIVE LEVEL (C/C++)                              
                                                                           
      • .so libraries (libnative-lib.so, libc.so)                        
      • Compiled ARM64/ARM32 machine code                                 
      • Direct memory access (pointers)                                   
      • NDK (Native Development Kit) code                                 
      • libc.so = C standard library (printf, malloc, open, read)         
                                                                           
      Example: int fd = open("/proc/self/maps", O_RDONLY);                
   └─────────────────────────────────────────────────────────────────────┘   
                                                                            
                System Calls (syscall/SVC #0)                
                              ▼                                              
   ┌─────────────────────────────────────────────────────────────────────┐   
                         LOW LEVEL (Kernel)                                
                                                                           
      • Linux Kernel system calls                                         
      • Direct hardware interaction                                       
      • Process/memory/file management                                    
      • Cannot be bypassed from userspace                                 
                                                                           
      Example: SVC #0 with x8=56 (openat syscall)                         
   └─────────────────────────────────────────────────────────────────────┘   
                                                                             
└─────────────────────────────────────────────────────────────────────────────┘

```

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

```
┌─────────────────────────────────────────────────────────────────────────────┐
                    FRIDA INJECTION & ARTIFACTS                               
├─────────────────────────────────────────────────────────────────────────────┤
                                                                             
  STEP 1: frida-server receives command from PC                             
          └── Listening on port 27042 (default port)          
                                                                             
  STEP 2: frida-server spawns/attaches to target process                    
          └── Uses ptrace() to gain control                                 
                                                                             
  STEP 3: Injects frida-agent-64.so into target process                     
          ┌────────────────────────────────────────────────────────────┐    
            ARTIFACTS CREATED IN MEMORY:                                  
                                                                          
            • frida-agent-64.so    - Main Frida agent library            
            • frida-gadget.so      - Embedded gadget (spawn mode)        
            • libfrida-gum.so      - Frida's hooking engine              
            • [anon:gum-js-loop]   - V8 JavaScript runtime memory        
            • [anon:frida-*]       - Various Frida allocations           
                                                                          
            These appear in /proc/self/maps (We will learn this file later)   
          └────────────────────────────────────────────────────────────┘    
                                                                             
  STEP 4: Frida's Gum engine hooks functions                                
          ┌────────────────────────────────────────────────────────────┐    
            HOW HOOKING WORKS (Native Level):                             
                                                                          
            BEFORE HOOK:                                                  
            connect():  FF 43 00 91    ; original instruction            
                        FD 7B BF A9    ; original prologue               
                                                                          
            AFTER HOOK:                                                   
            connect():  50 00 00 58    ; LDR X16, #8                     
                        00 02 1F D6    ; BR X16 (jump to trampoline)     
                        XX XX XX XX    ; address of hook handler         
                                                                          
            Memory is MODIFIED!                  
          └────────────────────────────────────────────────────────────┘    
                                                                             
  STEP 5: Your JavaScript runs in V8 engine inside the process             
          └── Java.perform() uses ART internals for Java hooks             
                                                                             
└─────────────────────────────────────────────────────────────────────────────┘

```

### Java Runtime Side (ART)

When you use `Java.perform()` in Frida:

```jsx
Java.perform(function() {
    var Activity = Java.use("android.app.Activity");
    Activity.onCreate.implementation = function(bundle) {
        console.log("onCreate hooked!");
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
    onEnter: function(args) { console.log("open called!"); }
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
| Port 27042 listening | Network | `connect()` to localhost:27042 | frida-server binds to this default TCP port to receive commands from the Frida client on your PC |
| frida-agent-64.so | /proc/self/maps | String search for "frida" | The main Frida agent library injected into the target process to execute JavaScript hooks |
| Modified function bytes | libc.so in memory | Checksum disk vs memory | Frida's Interceptor overwrites function prologues with trampolines (LDR X16; BR X16) to redirect execution |
| /data/local/tmp/re.frida.server | Filesystem | File existence check | Directory created by frida-server to store temporary files, gadgets, and agent libraries |
| frida-server process | /proc | Process name enumeration | The daemon process running with root privileges that handles injection and communication |

---

# Overview

**3 anti-frida detection mechanisms** implemented in `libantifrida.so`:

```
┌─────────────────────────────────────────────────────────────────────┐
                    3 ANTI-FRIDA CHECKS                              
├─────────────────────────────────────────────────────────────────────┤
                                                                     
  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐             
     CHECK 1          CHECK 2          CHECK 3                
                                                              
    Frida Port         Frida                 libc                  
    Detection         Artifacts            Checksum                
    (27042)           in maps              Detection               
  └─────────────┘    └─────────────┘    └─────────────┘             
                                                                  
         ▼                  ▼                  ▼                     
  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐             
     BYPASS:          BYPASS:          BYPASS:                
       Hook             Redirect            Remove                   
      connect()         maps file           libc.so                  
    change port         hide frida          from maps                
  └─────────────┘    └─────────────┘    └─────────────┘             
                                                                     
└─────────────────────────────────────────────────────────────────────┘
```

**Key Insight**: Anti-frida code often lives in the **Native Level** because:

1. Harder to reverse engineer than Java (no easy decompilation)
2. Can use direct syscalls to bypass Frida's libc hooks
3. Lower-level = more control, fewer abstraction layers to trust

---

# Check 1: Frida Port Detection (Port 27042)

> Technical Deep Dive: This detection exploits the fact that frida-server binds to TCP port 27042 on localhost (127.0.0.1) by default. The detection code uses the POSIX socket API—specifically the connect() libc function—which internally triggers the SYS_connect syscall. On ARM64 Android, the anti-frida library calls connect() with a sockaddr_in structure containing sin_family = AF_INET (2), sin_addr = 127.0.0.1, and sin_port = 27042 in network byte order. Network byte order is big-endian, so port 27042 (hex 0x69A2) becomes 0xA269 when the bytes are swapped. The detection reads the port from sockaddr_in at offset +2 bytes from the structure base (after the 2-byte sin_family field). If connect() returns 0 (success), it means something is listening on that port—likely Frida. Our bypass hooks connect() in libc.so, intercepts the call, reads the port from the sockaddr structure using pointer arithmetic, converts it from network to host byte order using ((port & 0xff) << 8) | (port >> 8), and if it matches 27042, we change it to a random port like 1337, causing the connection to fail harmlessly.
>

## The Issue

Frida server by default listens on **TCP port 27042** on localhost. Anti-frida code exploits this by attempting to connect to this port.

## Thinking Process

### How the detection works

```
┌────────────────────────────────────────────────────────────────────┐
                    PORT DETECTION FLOW                              
├────────────────────────────────────────────────────────────────────┤
                                                                    
   Anti-Frida Code                                                  
                                                                   
         ▼                                                          
   ┌─────────────────────────────────────┐                         
    socket(AF_INET, SOCK_STREAM, 0)       Create TCP socket      
   └─────────────────────────────────────┘                         
                                                                   
         ▼                                                          
   ┌─────────────────────────────────────┐                         
    Fill sockaddr_in:                                            
      sin_family = AF_INET                                       
      sin_addr   = 127.0.0.1                                     
      sin_port   = 27042 (network order)                         
   └─────────────────────────────────────┘                         
                                                                   
         ▼                                                          
   ┌─────────────────────────────────────┐                         
    connect(fd, &addr, sizeof(addr))                             
   └─────────────────────────────────────┘                         
                                                                   
         ├────────────────┬───────────────┐                        
         ▼                ▼                                       
   ┌──────────┐    ┌──────────┐                                  
    Returns 0       Returns -1                                  
    SUCCESS         FAIL                                      
   └──────────┘    └──────────┘                                  
                                                                
         ▼                ▼                                       
   ┌──────────┐    ┌──────────┐                                  
     FRIDA          NO                                       
    DETECTED!       FRIDA                                     
   └──────────┘    └──────────┘                                  
                                                                    
└────────────────────────────────────────────────────────────────────┘

```

### Why this works

- Frida server runs on device and listens on `127.0.0.1:27042`
- Any app can try to connect locally
- If connection succeeds → Frida server is running

## Questions & Answers

**Q: Why port 27042?**

> A: This is Frida's default port. The frida-server binary listens on this port waiting for frida client connections from PC.
>

## The Bypass

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

### Bypass Flow

```
┌────────────────────────────────────────────────────────────────────┐
                    BYPASS FLOW                                      
├────────────────────────────────────────────────────────────────────┤
                                                                    
   Anti-Frida Code                                                  
                                                                   
         ▼                                                          
   connect(fd, addr{port=27042}, len)                               
                                                                   
         ▼                                                          
   ┌─────────────────────────────────────┐                         
        OUR FRIDA HOOK INTERCEPTS                                
                                                                 
     if (port == 27042) {                                        
         port = 27043;  // Change it!                            
     }                                                           
   └─────────────────────────────────────┘                         
                                                                   
         ▼                                                          
   connect(fd, addr{port=27043}, len)   ← Modified!                
                                                                   
         ▼                                                          
   Returns -1 (nothing on 27043)                                    
                                                                   
         ▼                                                          
   App thinks: "No Frida detected"                                
                                                                    
└────────────────────────────────────────────────────────────────────┘

```

### Understanding Byte Order

```
Network Byte Order (Big-Endian) vs Host Byte Order (Little-Endian)

Port 27042 = 0x69A2

Network order: 0x69 0xA2  (high byte first)
Host order:    0xA2 0x69  (low byte first)

Conversion: ((port & 0xff) << 8) | (port >> 8)
            Swaps the two bytes

```

---

# Check 2: Frida Artifacts Detection (/proc/maps)

> Technical Deep Dive: This detection abuses the Linux /proc filesystem, specifically /proc/self/maps, which is a virtual file provided by the kernel that lists all memory-mapped regions of the current process. Each line contains: start_addr-end_addr permissions offset dev inode pathname. When Frida injects frida-agent-64.so into the target process, new memory regions appear with telltale names like frida-agent, frida-gadget, libfrida-gum.so, or anonymous mappings named [anon:gum-js-loop]. The anti-frida library bypasses libc entirely and uses direct syscalls via SVC #0 (ARM64 supervisor call instruction) to read this file—this is why we can't just hook open() or fopen() in libc. The library executes openat (syscall 56) with register x0=AT_FDCWD (-100), x1=pointer to "/proc/self/maps", x2=O_RDONLY. We find these syscall sites by disassembling libantifrida.so using Radare2 with /asj svc to locate all SVC #0 instructions and their offsets (e.g., {"addr":3868,"name":"openat","sysnum":56}). Our bypass hooks these specific offsets using Interceptor.attach(base_addr.add(offset), {...}). In the onEnter callback, we check if x1 contains "self/maps" and redirect it to /data/local/tmp/maps—a fake maps file we created that contains no Frida artifacts.
>

---

## Understanding /proc Files

### What is /proc?

The `/proc` filesystem is a **virtual filesystem** in Linux that doesn't exist on disk—it's generated by the kernel in real-time to expose process and system information. Every running process has a directory `/proc/[pid]/` containing information about it.

### /proc/self/maps - Memory Map File

`/proc/self/maps` shows all memory regions mapped into the current process:

```
┌─────────────────────────────────────────────────────────────────────────────┐
                    /proc/self/maps FORMAT                                    
├─────────────────────────────────────────────────────────────────────────────┤
                                                                             
  ADDRESS RANGE      PERMS  OFFSET   DEV    INODE    PATHNAME                
  ─────────────      ─────  ──────   ───    ─────    ────────                
  749088f000-749098c000 r--p 00000000 fd:00 123456 /system/lib64/libc.so    
  749098c000-7490abf000 r-xp 000fd000 fd:00 123456 /system/lib64/libc.so    
  7490abf000-7490ac3000 rw-p 00230000 fd:00 123456 /system/lib64/libc.so    
  7b5000000-7b5100000  r-xp 00000000 00:00 0       [anon:frida-agent]       
                                                                             
  PERMISSIONS MEANING:                                                       
  r = readable     w = writable     x = executable     p = private          
  s = shared                                                                 
                                                                             
  WHY IT'S USEFUL:                                            
  • Shows EVERY loaded library (including frida-agent-64.so)               
  • Shows anonymous mappings (including [anon:gum-js-loop])                
  • Cannot be hidden from kernel—it always shows the truth                  
          
                                                                             
└─────────────────────────────────────────────────────────────────────────────┘

```

### /proc/self/status - Process Status File

`/proc/self/status` provides detailed process information in a human-readable format:

```
┌─────────────────────────────────────────────────────────────────────────────┐
                    /proc/self/status CONTENTS                                
├─────────────────────────────────────────────────────────────────────────────┤
                                                                             
  Name:    com.example.app                    ← Process name                 
  State:   S (sleeping)                       ← Current state                
  Tgid:    12345                              ← Thread group ID (PID)        
  Pid:     12345                              ← Process ID                   
  PPid:    1234                               ← Parent process ID            
  TracerPid: 0                                ← WHO IS TRACING US?           
  Uid:     10123   10123   10123   10123      ← User IDs                     
  Gid:     10123   10123   10123   10123      ← Group IDs                    
  VmSize:  1234567 kB                         ← Virtual memory size          
  VmRSS:   12345 kB                           ← Resident memory              
  Threads: 15                                 ← Number of threads            
                                                                             
  ANTI-DEBUG DETECTION:                                                      
  • TracerPid: If non-zero, something is debugging/tracing this process!    
  • When Frida attaches via ptrace: TracerPid = frida-server's PID             
                                                                             
└─────────────────────────────────────────────────────────────────────────────┘

```

---

## Wrappers vs Syscalls: Why Direct Syscalls Matter

### What is a Wrapper Function?

A **wrapper** is a convenient function in `libc.so` that prepares arguments and calls the kernel:

```
┌─────────────────────────────────────────────────────────────────────────────┐
                    WRAPPER FUNCTION FLOW                                     
├─────────────────────────────────────────────────────────────────────────────┤
                                                                             
  YOUR CODE                    LIBC.SO (WRAPPER)              KERNEL         
  ──────────                   ─────────────────              ──────         
                                                                             
  open("/proc/maps", 0)  ──►  libc's open() function:        syscall        
                                                             handler        
                               ├─ Validate arguments                        
                               ├─ Set up registers:                         
                                  x0 = AT_FDCWD                            
                                  x1 = "/proc/maps"                        
                                  x2 = O_RDONLY                            
                                  x8 = 56 (syscall number)                 
                                                                           
                               └─ SVC #0  ────────────────────┘              
                                                                             
  FRIDA CAN HOOK HERE! ───────►◄──────── BUT NOT HERE (kernel)             
                                                                             
└─────────────────────────────────────────────────────────────────────────────┘

```

### What is a Syscall?

A **syscall** (system call) is the interface between userspace and the kernel. On ARM64 (it differs depending on the arch):

```
┌─────────────────────────────────────────────────────────────────────────────┐
                    SYSCALL MECHANISM (ARM64)                                 
├─────────────────────────────────────────────────────────────────────────────┤
                                                                             
  REGISTERS FOR SYSCALL:                                                     
  ┌────────────────────────────────────────────────────────────────────┐    
    x8  = Syscall number (sys_num) (which kernel function to call)                  
    x0  = 1st argument                                                    
    x1  = 2nd argument                                                    
    x2  = 3rd argument                                                    
    x3  = 4th argument                                                    
    x4  = 5th argument                                                    
    x5  = 6th argument                                                    
                                                                          
    SVC #0  ← Supervisor Call instruction (triggers kernel mode)          
                                                                          
    x0  = Return value (after syscall returns)                            
  └────────────────────────────────────────────────────────────────────┘    
                                                                             
  COMMON SYSCALLS (sys_num):                                                           
   Number  Name    Purpose                                              
     56    openat  Open a file relative to directory fd                 
     57    close   Close a file descriptor                              
     62    lseek   Move file read/write position                        
     63    read    Read bytes from file descriptor                      
     64    write   Write bytes to file descriptor                       
                                                                             
└─────────────────────────────────────────────────────────────────────────────┘

```

### Why Anti-Frida Code Uses Direct Syscalls

```
┌─────────────────────────────────────────────────────────────────────────────┐
                    WHY BYPASS LIBC WRAPPERS?                                 
├─────────────────────────────────────────────────────────────────────────────┤
                                                                             
  NORMAL APP (USES LIBC WRAPPER):                                           
  ┌─────────────────────────────────────────────────────────────────────┐   
    int fd = open("/proc/self/maps", O_RDONLY);                           
                                                                          
    Code ──► libc.so::open() ──► SVC #0 ──► Kernel                       
                    ▲                                                     
                                                                         
             FRIDA HOOKS HERE!                                            
             Can see arguments, modify them, log calls                    
  └─────────────────────────────────────────────────────────────────────┘   
                                                                             
  ANTI-FRIDA CODE (DIRECT SYSCALL):                                         
  ┌─────────────────────────────────────────────────────────────────────┐   
    // In assembly:                                                       
    mov x8, #56           // syscall number for openat                    
    mov x0, #-100         // AT_FDCWD                                     
    ldr x1, ="/proc/self/maps"                                           
    mov x2, #0            // O_RDONLY                                     
    svc #0                // Direct to kernel!                            
                                                                          
    Code ──────────────────► SVC #0 ──► Kernel                           
                                ▲                                         
                                                                         
             FRIDA CANNOT HOOK BY NAME!                                   
             No function name, just raw instruction                       
             Must hook the SVC instruction itself at specific offset      
  └─────────────────────────────────────────────────────────────────────┘   
                                                                             
  SOLUTION: Find SVC #0 offsets in libantifrida.so using Radare2:           
            r2 libantifrida.so                                              
            /asj svc    # Search for all SVC instructions                   
            Output: {"addr":3868,"name":"openat","sysnum":56}              
            Hook: Interceptor.attach(base.add(3868), {...})                 
                                                                             
└─────────────────────────────────────────────────────────────────────────────┘

```

### Summary

| Concept | Explanation |
| --- | --- |
| **SVC** | Supervisor Call — ARM64 instruction to enter kernel mode |
| **#0** | Immediate value (Linux ignores it, always 0) |
| **x8 register** | Contains syscall number (56=openat, 63=read, etc.) |
| **x0-x5 registers** | Contain syscall arguments |
| **Why hook it?** | Anti-frida code uses direct `SVC #0` to bypass libc — no function name exists to hook, so we hook the raw instruction at its memory offset |

| Register | Value | Meaning |
| --- | --- | --- |
| x0 (dfd) | -100 (AT_FDCWD) | "Use current directory" — but ignored for absolute paths |
| x1 (filename) | "/proc/self/maps" | Absolute path to open |
| x2 (flags) | 0 (O_RDONLY) | Open for reading only |

---

## The Issue

When Frida injects into a process, it loads libraries and creates memory regions that appear in `/proc/self/maps`. Anti-frida code scans this file looking for telltale strings.

## Thinking Process

### What Frida leaves behind in memory maps

```
┌────────────────────────────────────────────────────────────────────┐
             /proc/self/maps WITH FRIDA RUNNING                      
├────────────────────────────────────────────────────────────────────┤
                                                                    
  Normal entries...                                                 
  7a1234000-7a1235000 r-xp  /system/lib64/libc.so                  
  ...                                                               
                                                                    
  ╔════════════════════════════════════════════════════════════╗   
  ║  FRIDA ARTIFACTS - THESE REVEAL FRIDA IS PRESENT!          ║   
  ╠════════════════════════════════════════════════════════════╣   
  ║  7b5000000-7b5100000 r-xp  frida-agent-64.so               ║   
  ║  7b5100000-7b5200000 rw-p  frida-agent-64.so               ║   
  ║  7b6000000-7b6001000 r--p  frida-gadget.so                 ║   
  ║  7b7000000-7b7010000 rw-p  [anon:gum-js-loop]              ║   
  ║  7b8000000-7b8100000 r-xp  libfrida-gum.so                 ║   
  ╚════════════════════════════════════════════════════════════╝   
                                                                    
└────────────────────────────────────────────────────────────────────┘

```

### Detection Flow

```
┌────────────────────────────────────────────────────────────────────┐
                ARTIFACTS DETECTION FLOW                             
├────────────────────────────────────────────────────────────────────┤
                                                                    
   Anti-Frida Code                                                  
                                                                   
         ▼                                                          
   ┌─────────────────────────────────────┐                         
    openat("/proc/self/maps")                                    
   └─────────────────────────────────────┘                         
                                                                   
         ▼                                                          
   ┌─────────────────────────────────────┐                         
    read() line by line                                          
   └─────────────────────────────────────┘                         
                                                                   
         ▼                                                          
   ┌─────────────────────────────────────┐                         
    Search for strings:                                          
      - "frida"                                                  
      - "gadget"                                                 
      - "gum-js-loop"                                            
      - "frida-agent"                                            
   └─────────────────────────────────────┘                         
                                                                   
         ├──────────────┬────────────────┐                         
         ▼              ▼                                         
   ┌──────────┐   ┌──────────┐                                   
     FOUND!        NOT FOUND                                    
   └──────────┘   └──────────┘                                   
                                                                
         ▼              ▼                                         
   ┌──────────┐   ┌──────────┐                                   
     FRIDA          NO                                        
    DETECTED!       FRIDA                                      
   └──────────┘   └──────────┘                                   
                                                                    
└────────────────────────────────────────────────────────────────────┘

```

## Questions & Answers

**Q: Why use `/proc/self/maps`?**

> A: This special file shows ALL memory regions mapped into the current process. It's provided by the Linux kernel and always shows what's really loaded, so, triying to remove such file will cause the app even the system to crash
>

**Q: What strings does anti-frida look for?**

> A: Common ones include:
>
> - `frida` - appears in frida library names
> - `gadget` - [frida-gadget.so](http://frida-gadget.so/)
> - `gum` - frida's Gum engine
> - `agent` - [frida-agent.so](http://frida-agent.so/)

## The Bypass

### Strategy 1

1. Create a **fake maps file** without Frida entries
2. When anti-frida opens `/proc/self/maps`, redirect to our fake file

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

```
┌────────────────────────────────────────────────────────────────────┐
                    BYPASS FLOW                                      
├────────────────────────────────────────────────────────────────────┤
                                                                    
   Anti-Frida Code                                                  
                                                                   
         ▼                                                          
   openat("/proc/self/maps")                                        
                                                                   
         ▼                                                          
   ┌─────────────────────────────────────┐                         
        OUR FRIDA HOOK INTERCEPTS                                
                                                                 
     if (path contains "self/maps") {                            
         path = "/data/local/tmp/maps";                          
     }                                                           
   └─────────────────────────────────────┘                         
                                                                   
         ▼                                                          
   openat("/data/local/tmp/maps")  ← Redirected!                   
                                                                   
         ▼                                                          
   ┌─────────────────────────────────────┐                         
     FAKE MAPS FILE CONTENTS:                                    
     (No frida strings!)                                         
                                                                 
     7a1234000-7a1235000 /system/libc.so                         
     ... normal entries only ...                                 
   └─────────────────────────────────────┘                         
                                                                   
         ▼                                                          
   App searches for "frida" → NOT FOUND                             
                                                                   
         ▼                                                          
   App thinks: "No Frida detected"                                
                                                                    
└────────────────────────────────────────────────────────────────────┘

```

**Q: Why can't we just search by module and hook directly?**

> A: Because libantifrida.so doesn't exist in memory when our script starts. It's loaded later by the app at runtime.
>

**Q: Why Direct Syscall Hooking is Necessary?**

> Normal hooking by function name **won't work** because `libantifrida.so` uses **direct syscalls**, bypassing libc entirely!
>

**Q: Why not just hook by function name like `openat`, `read`, `close`?**

> A: Because anti-frida code doesn't call libc functions! It uses direct syscalls.
>

**Q: What's the difference?**

### Normal App (hookable)

```
App code → libc.so (openat function) → kernel syscall
              ↑
         Frida can hook here!
```

### Anti-Frida Code (NOT hookable by name)

```
App code → SVC #0 instruction (direct syscall) → kernel
              ↑
         No function to hook! Must hook the SVC instruction itself.
```

## Strategy 2: Renaming Frida Artifacts (frida → brida)

<https://github.com/frida/frida-core/issues/310>

Goal: evade basic Frida artifact checks (e.g. `/proc/pid/maps`, `/data/local/tmp/re.frida.server`) by patching the Android `frida-server` binary so all visible agent/server names become custom (`brida-bgent-*`).

## 1. Download and unpack frida-server

Pick the right version/arch and unpack:

`wget <https://github.com/frida/frida/releases/download/16.5.6/frida-server-16.5.6-android-arm64.xz> unxz frida-server-16.5.6-android-arm64.xz mv frida-server-16.5.6-android-arm64 frida-server chmod +x frida-server`

Quick recon of embedded strings:

`strings frida-server | grep -i 'frida-agent' strings frida-server | grep -i 're.frida.server'`

## 2. Python patcher (frida → brida-bgent)

```python
from pathlib import Path

IN_PATH  = Path("frida-server")
OUT_PATH = Path("brida-bgent-server")

REPLACEMENTS = {
    *# Concrete agent .so names*
    b"frida-agent-32.so":      b"brida-bgent-32.so",
    b"frida-agent-64.so":      b"brida-bgent-64.so",
    b"frida-agent-arm.so":     b"brida-bgent-arm.so",
    b"frida-agent-arm64.so":   b"brida-bgent-arm64.so",

    *# Generic template string*
    b"frida-agent-<arch>.so":  b"brida-bgent-<arch>.so",

    *# Container / helper names*
    b"frida-agent-container":  b"brida-bgent-container",

    *# Raw agent libs*
    b"libfrida-agent-raw.so":  b"libbrida-bgent-raw.so",

    *# Directory name*
    b"re.frida.server":        b"re.brida.server",
}

data = IN_PATH.read_bytes()

for orig, repl in REPLACEMENTS.items():
    if len(orig) != len(repl):
        raise ValueError(f"Length mismatch: {orig!r} vs {repl!r}")
    count = data.count(orig)
    if count == 0:
        print(f"[!] Pattern not found: {orig!r}")
        continue
    print(f"[+] Replacing {count} occurrence(s) of {orig!r} with {repl!r}")
    data = data.replace(orig, repl)

OUT_PATH.write_bytes(data)
OUT_PATH.chmod(0o755)
print(f"[+] Wrote patched server to {OUT_PATH}")`

```

Run:

`python3 brida-patch.py`

## 3. Verify patched artifacts

`strings brida-bgent-server | grep -i 'frida-agent' strings brida-bgent-server | grep -i 'brida-bgent' strings brida-bgent-server | grep -i 're.frida.server' strings brida-bgent-server | grep -i 're.brida.server'`

Expected: only the harmless error message still contains `frida-agent`, all real artifacts are `brida-bgent-*` and `re.brida.server`.

## 4. Deploy on device

`adb push brida-bgent-server /data/local/tmp/frida-server adb shell "chmod 755 /data/local/tmp/frida-server" adb shell "su -c /data/local/tmp/frida-server &"`

Attach from PC as usual (same frida CLI / version). On target app:

`bashadb shell "grep -i brida /proc/$(pidof <package>)/maps" adb shell "grep -i frida /proc/$(pidof <package>)/maps" adb shell "ls -R /data/local/tmp | grep -i brida"`

Now `/proc/pid/maps` and `/data/local/tmp` expose `brida-bgent-*.so` and `re.brida.server`, so naive Frida name-based detections on `frida-agent.so` / `re.frida.server` no longer fire.

---

# Check 3: libc Checksum-Based Detection

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
                          DETECTED!                            
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
                                                                    
   Frida replaced the first instructions with a TRAMPOLINE!         
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
> A: This code **does NOT bypass** the checksum check! It only **LOGS** when [libc.so](http://libc.so/) is being accessed. The backtrace shows the call chain - used for debugging/analysis to understand how the check works.
>

**Q: How did removing [libc.so](http://libc.so/) from maps bypass the checksum?**

> A: The checksum code relies on /proc/self/maps to find libc.so! By removing or renaming libc.so entries in the fake maps file:
>
> - The code can't find where libc is in memory
> - It can't get the file path to read from disk
> - **The check effectively becomes a no-op!**

## The Bypass

### Strategy

**Same fake maps file** used for Check 2, but also remove/rename `libc.so` entries!

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
    7. Frida modified memory → MISMATCH → DETECTED!               
   └─────────────────────────────────────────────────────────────┘ 
                                                                    
   WITH BYPASS (libc.so removed from fake maps):                    
   ┌─────────────────────────────────────────────────────────────┐ 
    1. Open /proc/self/maps → REDIRECTED to fake file            
    2. Find line containing "libc.so" → NOT FOUND!               
    3. Can't get address → Can't compute checksum                
    4. Check FAILS SILENTLY or SKIPS                             
    5. NO DETECTION!                                            
   └─────────────────────────────────────────────────────────────┘ 
                                                                    
   The checksum code TRUSTS /proc/self/maps to tell it where       
   libc is. We LIE to it, and it never checks the real libc!       
                                                                    
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
> | `call_constructor` | Library's init code runs | **Perfect timing!** |

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

                // NOW we can get the module info!
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
                                                                   
      ├──► do_dlopen hook triggers ──► We know it's coming!        
                                                                   
      ▼                                                             
  Library mapped to memory                                          
                                                                   
      ├──► call_constructor hook ──► NOW we hook syscalls!         
                                                                   
      ▼                                                             
  Library's anti-frida checks run ──► But we already hooked them!  
                                                                   
      ▼                                                             
  Checks bypassed!                                                
                                                                    
└────────────────────────────────────────────────────────────────────┘

```

---

# Why Direct Syscall Hooking is Necessary

## The Problem

Normal hooking by function name **won't work** because `libantifrida.so` uses **direct syscalls**, bypassing libc entirely!

## Questions & Answers

**Q: Why not just hook by function name like `openat`, `read`, `close`?**

> A: Because anti-frida code doesn't call libc functions! It uses direct syscalls.
>

**Q: What's the difference?**

### Normal App (hookable)

```
App code → libc.so (openat function) → kernel syscall
              ↑
         Frida can hook here!

```

### Anti-Frida Code (NOT hookable by name)

```
App code → SVC #0 instruction (direct syscall) → kernel
              ↑
         No function to hook! Must hook the SVC instruction itself.

```

### What the anti-frida code looks like

```c
// Normal way (Frida CAN hook this)
int fd = openat(AT_FDCWD, "/proc/self/maps", O_RDONLY);

// Anti-frida way (Frida CANNOT hook by name!)
int fd;
asm volatile(
    "mov x8, #56\\\\n"        // syscall number for openat
    "mov x0, %1\\\\n"         // dirfd argument
    "mov x1, %2\\\\n"         // pathname argument
    "mov x2, %3\\\\n"         // flags argument
    "svc #0\\\\n"             // <-- Direct syscall instruction!
    "mov %0, x0"           // return value
    : "=r"(fd)
    : "r"(AT_FDCWD), "r"("/proc/self/maps"), "r"(O_RDONLY)
);

```

## The Solution: Hook SVC Instructions Directly

### How syscallArray works

```jsx
const syscallArray = [
    {"addr":3868, "name":"openat", "sysnum":56},
    {"addr":4008, "name":"read",   "sysnum":63},
    {"addr":4924, "name":"close",  "sysnum":57},
    // ... more syscall locations
];

```

| Field | Meaning |
| --- | --- |
| `addr` | Offset in [libantifrida.so](http://libantifrida.so/) where `SVC #0` is located |
| `name` | Human-readable name (for us) |
| `sysnum` | Linux syscall number (what the kernel does) |

### Finding these addresses

The addresses were found using **Radare2** to search for all syscall instructions:

```bash
r2 libantifrida.so
[0x00000000]> /asj    # Search for all syscall instructions (JSON output)

```

### Visualization

```
┌────────────────────────────────────────────────────────────────────┐
                    libantifrida.so in memory                        
├────────────────────────────────────────────────────────────────────┤
                                                                    
  Base Address: 0x7500000000                                        
                                                                    
  Offset 0x0F1C (3868):                                             
  ┌──────────────────────────────────────────────────────────────┐ 
    mov x8, #56          ; syscall number = openat               
    mov x0, #AT_FDCWD    ; dirfd                                 
    mov x1, x19          ; pathname pointer                      
    mov x2, #0           ; flags                                 
    svc #0               ; ← WE HOOK HERE!                       
  └──────────────────────────────────────────────────────────────┘ 
                                                                    
  Offset 0x0FA8 (4008):                                             
  ┌──────────────────────────────────────────────────────────────┐ 
    mov x8, #63          ; syscall number = read                 
    mov x0, x20          ; fd                                    
    mov x1, x21          ; buffer                                
    mov x2, x22          ; count                                 
    svc #0               ; ← WE HOOK HERE!                       
  └──────────────────────────────────────────────────────────────┘ 
                                                                    
  ... more syscalls ...                                             
                                                                    
  Actual hook address = Base + Offset                               
  Example: 0x7500000000 + 0x0F1C = 0x7500000F1C                     
                                                                    
└────────────────────────────────────────────────────────────────────┘

```

### The Code

```jsx
function hook_svc(base_addr){
    var buff = "";

    const syscallArray = [
        {"addr":3868,"name":"openat","sysnum":56},
        {"addr":4008,"name":"read","sysnum":63},
        // ... more entries
    ];

    syscallArray.forEach(function(item) {
        // Convert decimal offset to pointer
        var addr = ptr('0x'+item.addr.toString(16));

        // Hook at: base_addr + offset
        Interceptor.attach(base_addr.add(addr), function(args){
            switch(item.sysnum){
                case 56:  // openat
                    // Check and modify file paths
                    break;
                case 63:  // read
                    // Monitor reads
                    break;
                // ... etc
            }
        });
    });
}

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

```

---
