---
title: "Challenge 01: FridaInTheMiddle"
published: 2025-11-15
description: "Bypassing iOS anti-frida/anti-hooking using only dynamic analysis"
image: "https://lwfiles.mycourse.app/66c35021da1fe6df974b8aee-public/b131e9be3ff9f80db6df645546c8cb2a.png"
category: "Mobile"
tags: ["ios", "frida", "swift", "anti-frida", "anti-hook", "dynamic-analysis", "mobile-exploitation"]
series:
    id: "8ksec-ios-challenges"
    order: 1
---

*( بِسْمِ اللَّـهِ الرَّحْمَـٰنِ الرَّحِيمِ )*

:::caution
FreePalestine
:::

---

## **Introduction**

This writeup covers the first challenge in the **8ksec iOS challenges** series.  
It’s an anti-Frida / anti-hook app that basically says:

> “If I see Frida running, I’m out.”

Most of these apps try connecting to common Frida ports like **27042** or **27043**.  
Sure, I *could* just change the Frida port on the device easy, effective but where’s the fun baby?

We have around **3 seconds** before the app closes, so that’s enough time to gamble with a Frida script and hope for the best. First step: see if it uses `socket`/`connect` and what ports it touches.

After a bunch of trial-and-error dealing with native crap (why is dealing with native binaries always pain??), I finally got a working hook. Also, why is **8** always better than **16**? :3

---

## **Step 1 — Checking for Frida Port Detection**

Here’s the script I used to check what port the app tries connecting to:

```javascript
/*
 * This version manually reads the port byte-by-byte to work around
 * the "TypeError: not a function" on .readU16BE().
 */

try {
    const connectPtr = Module.getExportByName(null, 'connect');

    if (!connectPtr) {
        throw new Error("Could not find 'connect' function.");
    }

    console.log("Found 'connect' at address: " + connectPtr);

    Interceptor.attach(connectPtr, {
       
        onEnter: function (args) {
            const sockAddrPtr = args[1];

            if (sockAddrPtr.isNull()) {
                console.log("[+] connect() called with null address.");
                return;
            }

            try {
                const portByte1 = sockAddrPtr.add(2).readU8();
                const portByte2 = sockAddrPtr.add(3).readU8();
                const port = (portByte1 << 8) | portByte2;

                console.log(`[+] connect() called. Port: ${port}`);

            } catch (e) {
                console.log(`[!] Failed to read port. Error: ${e.message}`);
            }
        },
        onLeave: function (retval) {
            console.log(`[-] connect() returned: ${retval}`);
        }
    });

} catch (err) {
    console.error("An error occurred:");
    console.error(err.stack);
}
````

### **Output**

```powershell
Spawning `com.8ksec.FridaInTheMiddle`...
Found 'connect' at address: 0x1d79c74c0
Spawned `com.8ksec.FridaInTheMiddle`. Resuming main thread!
[+] connect() called. Port: 27042
[-] connect() returned: 0x0
Process terminated
```

It terminates because we’re only observing — no bypass yet.
Okay, time to break things properly.

---

## **Step 2 — Patching the Frida Detection Port**

Now we modify the port before the app makes the connection.
Changing **27042 → 1337**, because of course.

```javascript
if (port === 27042) {
    console.log("[!] Frida detection port 27042 found. Patching...");
    
    const newPort = 1337;

    const newPortByte1 = (newPort >> 8) & 0xFF;
    const newPortByte2 = newPort & 0xFF;

    portPtr1.writeU8(newPortByte1);
    portPtr2.writeU8(newPortByte2);

    console.log(`[+] Patched port to: ${newPort}`);
}
```

### **Output After Combining It**

```powershell
[+] connect() called. Port: 27042
[!] Frida detection port 27042 found. Patching...
[+] Patched port to: 1337
[-] connect() returned: 0xffffffffffffffff
```

Port patched, return value adjusted, app thinks everything is fine.

The UI now shows:

* “No Frida detected”
* The intercept **FLAG** button

But clicking it?
Yeah, nothing.
We need to hook the function responsible for returning the flag.

---

## **Step 3 — Finding the Flag Function**

First, I enumerated loaded modules to find the interesting one.

```javascript
Process.enumerateModulesSync().forEach(m => {
    console.log(m.name, "->", m.path);
});
```

I found:

```
FridaInTheMiddle.debug.dylib
```

Load it:

```javascript
const moduleName = "FridaInTheMiddle.debug.dylib";
const mod = Process.findModuleByName(moduleName);
console.log("Found module: " + moduleName + " at " + mod.base);
```

---

## **Step 4 — Locating the Swift Symbol for dummyFunction**

```javascript
var syms = Module.enumerateSymbolsSync(moduleName);
var found = syms.filter(s => s.name && s.name.indexOf("dummyFunction") !== -1);

found.forEach(s => {
    console.log("name:", s.name, " address:", s.address);
});
```

### **Result**

```
name: $s16FridaInTheMiddle11ContentViewV13dummyFunction4flagySS_tF  
address: 0x102371d24
```

Okay. Found it. Time to poke it.

---

## **Step 5 — Hooking dummyFunction to Extract the Flag**

```javascript
Interceptor.attach(targetAddr, {
    onEnter: function (args) {
        console.log("[*] Swift function dummyFunction called!");

        const stringPtr = args[1];
        console.log("  args[1] (base pointer): " + stringPtr);

        const flagPtr = stringPtr.add(0x20);

        try {
            const flag = flagPtr.readUtf8String();
            console.log("\n[FLAG] => " + flag + "\n");
        } catch (e) {
            console.log("[!] Failed to read flag from offset 0x20.");
        }
    }
});
```

### **Output**

```
[FLAG] => CTF{you_evaded_frida_detection}
```

---

## **Final Combined Script**

```javascript


console.log("[Main] Script starting...");

// --- Part 1: connect() hook (Anti-Frida Bypass) ---
function hook_connect() {
    try {
        const connectPtr = Module.getExportByName(null, 'connect');
        if (!connectPtr) {
            console.log("[Connect] Could not find 'connect' function.");
            return;
        }
        console.log("[Connect] Found 'connect' at address: " + connectPtr);

        Interceptor.attach(connectPtr, {
            onEnter: function (args) {
                const sockAddrPtr = args[1];
                if (sockAddrPtr.isNull()) return;

                try {
                    const portPtr1 = sockAddrPtr.add(2);
                    const portPtr2 = sockAddrPtr.add(3);

                    const portByte1 = portPtr1.readU8();
                    const portByte2 = portPtr2.readU8();
                    const port = (portByte1 << 8) | portByte2;
                    
                    if (port === 27042) {
                        console.log("[Connect] Frida detection port 27042 found. Patching...");

                        const newPort = 1337;
                        const newPortByte1 = (newPort >> 8) & 0xFF;
                        const newPortByte2 = newPort & 0xFF;

                        portPtr1.writeU8(newPortByte1);
                        portPtr2.writeU8(newPortByte2);

                        console.log(`[Connect] Patched port to: ${newPort}`);
                    }
                } catch (e) {}
            }
        });
    } catch (err) {
        console.error("[Connect] Error: " + err.message);
    }
}

// --- Part 2: dummyFunction hook (Flag Reader) ---

let flagHooked = false;
const moduleName = "FridaInTheMiddle.debug.dylib";
const symbolName = "$s16FridaInTheMiddle11ContentViewV13dummyFunction4flagySS_tF";

function hook_flag_function() {
    if (flagHooked) return;

    try {
        const mod = Process.findModuleByName(moduleName);
        if (!mod) return;

        const targetAddr = Module.findExportByName(moduleName, symbolName);
        if (!targetAddr) {
            console.log("[Flag] Module found, but symbol not yet. Retrying...");
            return;
        }

        flagHooked = true;
        console.log(`[Flag] Found module: ${moduleName} at ${mod.base}`);
        console.log(`[Flag] Found symbol: '${symbolName}' at ${targetAddr}`);

        Interceptor.attach(targetAddr, {
            onEnter: function (args) {
                console.log("[Flag] Swift function dummyFunction called!");

                const stringPtr = args[1];
                const flagPtr = stringPtr.add(0x20);

                try {
                    const flag = flagPtr.readUtf8String();
                    console.log("\n[FLAG] => " + flag + "\n");
                } catch (e) {
                    console.log("[Flag] Failed to read flag.");
                }
            }
        });

    } catch (err) {
        console.error("[Flag] Error: " + err.message);
    }
}

// --- Main ---

hook_connect();

console.log("[Main] Starting poller for " + moduleName + "...");

const poller = setInterval(function() {
    hook_flag_function();

    if (flagHooked) {
        console.log("[Main] Poller found and hooked module. Stopping poller.");
        clearInterval(poller);
    }
}, 250);

```

Happy iOS hacking :3

---
