---
title: "Brod & Co. — Android CTF Writeup (BrunnerCTF 2025)"
published: 2025-08-26
description: "Reverse engineering Brod & Co. from BrunnerCTF 2025: Flutter + native analysis, Frida↔Ghidra mapping, overflow confirmation, and pulling the flag via util_func_c(0x1337)."
image: "https://shared-brunnerctf-2025.nbg1.your-objectstorage.com/files/logo.png"
tags:
  [
    "android",
    "CTF",
    "frida",
    "reverse-engineering",
    "mobile",
    "writeup",
    "smali",
  ]
category: Writeups
lang: "en"
draft: false
---

# ( بِسْمِ اللَّـهِ الرَّحْمَـٰنِ الرَّحِيمِ )

:::caution
#FreePalestine
:::

# Brod & Co. — Android CTF Write-Up - BrunnerCTF 2025


---

## 1) Recon: it’s Flutter + native

From the APK:

* `AndroidManifest.xml` shows a standard Flutter `MainActivity`, no obvious networking components or custom services.
* App bundles three native libs:
  `lib/x86_64/libapp.so`, `lib/x86_64/libflutter.so`, `lib/x86_64/libnative.so`.

Logcat during coupon check:

```text
DEBUG: validateCoupon called with: 'test code'
DEBUG: _callNativeValidation called with: 'test code'
Native library loaded successfully
Main function: process_data_complete
VULNERABILITIES ACTIVE: Buffer overflow, weak crypto, format string
DEBUG: Native library returned for coupon validation: 'INVALID_COUPON'
```

When placing an order (with a long input):

```text
Order data length: 256 bytes
--------- beginning of crash
FORTIFY: strcpy: prevented 257-byte write into 256-byte buffer
Fatal signal 6 (SIGABRT)
```

Takeaway: the app calls into **`libnative.so`** for both validation and order handling. It even tells us vulnerable patterns exist.

---

## 2) Static: skim `libnative.so` in Ghidra

Useful exports I found:

```cpp
process_data_complete
util_func_a / b / c / d
hidden_encode_function / hidden_decrypt_function
get_client_version / version_info
force_data_preservation
test_all_functions
```

Two key functions (decompiled snippets I pulled):

* **Coupon/flag entry point**:

```c
char *process_data_complete(char *in) {
  if (strncmp(in, "COUPON:", 7) == 0) {
    return FUN_001023a0(in + 7) ? strdup("VALID_COUPON") : strdup("INVALID_COUPON");
  } else if (strncmp(in, "FLAG:", 5) == 0) {
    if (FUN_001023a0(in + 5)) {
      // build "FLAG|%s" using FUN_00103520()
    }
    return strdup("FLAG|INVALID_COUPON");
  } else {
    // default path uses FUN_00103520() to build "OK|%s"
  }
}
```

* **Secret builder** (what ultimately becomes the `%s` above):

```c
undefined * FUN_00103520(void) {
  // Mixes three embedded data blobs, rotates, XORs, permutes bits,
  // PRF-like rounds with constants 0xcafebabedeadbeef and 0x8765432112345678,
  // then copies only printable bytes into a global buffer and returns it.
  // First call lazily initializes a global; subsequent calls return the same string.
  return &DAT_00106090;
}
```

And the helper I later used:

```c
void *util_func_c(int x) {
  if (x == 0x1337) {
    char *s = FUN_00103520();
    return strcpy(malloc(strlen(s) + 1), s);
  }
  return NULL;
}
```

So: **`util_func_c(0x1337)` hands you a heap-allocated copy of the final secret string** that `process_data_complete()` would otherwise wrap as `OK|%s` or `FLAG|%s`.

---

## 3) Dynamic: confirm the overflow and its call site

I traced libc copies (safer Frida hooks) and reproduced the crash:

```js
=== __strcpy_chk hit ===
destlen=256 srclen=250
returnAddress=... module=libnative.so offset=0x1868  <-- callsite

=== __strcpy_chk hit ===
destlen=256 srclen=256
... Abort: FORTIFY: strcpy: prevented 257-byte write into 256-byte buffer
```

**Offset `0x1868`** is the `__strcpy_chk` return site inside `libnative.so` where the 256-byte limit triggers.

> [!NOTE]
> On Ghidra address translation: Frida gave module offset `0x1868`. In Ghidra, image base was `0x00100000`, so jump to `0x00101868`.

Around that address, my listing (function `FUN_00101820`) shows:

* `local_168` at `[rsp+0x160]` is the **256-byte dest buffer**.
* The vulnerable call:

```asm
mov [rsp+local_30], 0x100     ; destlen = 256
mov rdi, [rsp+local_28]       ; rdi = &local_168
mov rsi, [rsp+local_38]       ; rsi = input
mov rdx, [rsp+local_30]       ; rdx = 256
call __strcpy_chk             ; → aborts if srclen+1 > 256
```

* Then it copies into a bigger temp buffer, XORs each byte with `0xAA` (“weak crypto”), and finally heap-copies with `__strcpy_chk(..., -1)` (no check).

So the overflow is real, but FORTIFY blocks it. I **could** have bypassed that check with Frida and continued, but… I found something faster.

---

## 4) The fastest working PoC (unintended, I guess, but valid)

### Idea

Don’t fight validation or overflow. The native lib already exports a function that returns the final secret string: **`util_func_c(0x1337)`** → internally calls the secret builder and returns a heap string. Read it and print.

### PoC

`get_flag.js`:

```js
// frida -U -n dk.brunnerne.masterbaker -l get_flag.js
// or:  frida -U -f dk.brunnerne.masterbaker -l get_flag.js --no-pause

(function () {
  function waitForLib(name, cb) {
    const tryFind = function () {
      const m = Process.findModuleByName(name);
      if (m) return cb(m);
      setTimeout(tryFind, 100);
    };
    tryFind();
  }

  waitForLib("libnative.so", function (m) {
    console.log("[+] libnative.so base:", m.base);

    const util_func_c = Module.findExportByName("libnative.so", "util_func_c");
    if (!util_func_c) { console.log("[!] util_func_c not found"); return; }

    const freePtr = Module.findExportByName(null, "free");
    const UtilFuncC = new NativeFunction(util_func_c, "pointer", ["int"]);

    console.log("[*] Calling util_func_c(0x1337) ...");
    const p = UtilFuncC(0x1337);
    if (p.isNull()) { console.log("[!] util_func_c returned NULL"); return; }

    try {
      const s = Memory.readUtf8String(p);
      console.log("\n===== SECRET / FLAG STRING =====");
      console.log(s);
      console.log("================================\n");
    } catch (e) {
      console.log("[!] Failed to read string:", e);
    } finally {
      if (freePtr) new NativeFunction(freePtr, "void", ["pointer"])(p);
    }
  });
})();
```

#### How to run

* Run the script:

  ```bash
  frida -U -f dk.brunnerne.masterbaker -l get_flag.js
  ```

**Output:**

```js
[+] libnative.so base: 0x7xxx...
[*] Calling util_func_c(0x1337) ...

===== SECRET / FLAG STRING =====
brunner{wh0_kn3w_dart_c0u1d_h4nd13_C?!}
================================
```

 FLAG = `brunner{wh0_kn3w_dart_c0u1d_h4nd13_C?!}`

---

## 5) Line-by-line PoC explanation

* `waitForLib("libnative.so", cb)`
  Flutter loads libs lazily; this waits until `libnative.so` is mapped before continuing.

* `Module.findExportByName("libnative.so", "util_func_c")`
  Resolves the exported symbol **inside** the target library. No offsets, no gadget hunting.

* `new NativeFunction(util_func_c, "pointer", ["int"])`
  Wraps the C function: returns a pointer, takes one `int` parameter.

* `UtilFuncC(0x1337)`
  The magic value the library checks. If it matches, it calls `FUN_00103520()` and returns a heap-allocated C string (`char *`).

* `Memory.readUtf8String(p)`
  Reads the returned C string from target memory.

* `free(p)`
  Clean up the heap allocation (nice-to-have; not strictly required for a quick one-shot).

That’s it. No bypassing FORTIFY, no ROP chain, no coupon math.

---