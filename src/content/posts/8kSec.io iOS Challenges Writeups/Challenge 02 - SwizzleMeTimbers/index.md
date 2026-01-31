---
title: "Challenge 02: SwizzleMeTimbers"
published: 2025-11-15
description: "A pirate-themed iOS app with a secret buried deep inside its view controller. A simple button reads “Unlock Treasure”, but it’s protected by a method that always returns false"
image: "https://lwfiles.mycourse.app/66c35021da1fe6df974b8aee-public/dfbf4fa3b4965aa2640566b2fddd7064.png"

tags: ["ios", "frida", "swift", "hook", "static-analysis", "mobile-exploitation", "reverse-engineering", "runtime"]
series:
    id: "8ksec-ios-challenges"
    order: 2
---

*( بِسْمِ اللَّـهِ الرَّحْمَـٰنِ الرَّحِيمِ )*

:::caution
FreePalestine
:::

---

# SwizzleMeTimbers - The Tale of the Magic Space

This writeup details the process of solving the `SwizzleMeTimbers` iOS CTF challenge. The goal was to bypass a button check to "Unlock Treasure." This challenge was a fantastic lesson in methodology, red herrings, and how a single, easily-missed character in a method name can be the entire puzzle.

## Part 1: Initial Recon - The "Unlock Treasure" Red Herring

The app presents a single button with the text "Unlock Treasure." The first logical step was to analyze this string in the binary using Ghidra. We quickly found the code responsible for it:

```c
; Loads the string "Unlock Treasure"
00005a00 20 00 00 f0   adrp      x0,0xc000
00005a04 00 98 30 91   add       x0=\>s\_Unlock\_Treasure\_0000cc26 ,x0,\#0xc26

; ...
; Creates a Swift String object from the literal
00005a14 dc 19 00 94   bl        \_$sSS21\_builtinStringLiteral17utf8CodeUnitCoun

; ...
; Bridges it to an Objective-C NSString
00005a1c c8 19 00 94   bl        \_$sSS10FoundationE19\_bridgeToObjectiveCSo8NSSt
00005a28 a8 03 18 f8   stur      x8,[x29 , \#local\_90 ]
```

By tracing the cross-references (XREFs) for the `local_90` variable where this string was stored, we found where it was being read:

```c
; Reads our "Unlock Treasure" string into x2
00005a34 a2 03 58 f8   ldur      x2,[x29 , \#local\_90 ]
; Reads the method name "setTitle:forState:" into x1
00005a40 01 79 46 f9   ldr       x1=\>s\_setTitle:forState:\_0000eb98 ,[x8, \#0xcf0]
; Calls [x0 setTitle:x2 forState:...]
00005a44 3f 1a 00 94   bl        \_objc\_msgSend
```

**Conclusion:** This was a dead end. The "Unlock Treasure" string was just a red herring used to set the button's UI label, not to check for a password.

## Part 2: Finding the Real Logic

When tapping the button, the app showed a popup with the text: "Nah, this ain't the pirate's path." This string was our new target.

Searching for "Nah" in Ghidra led us directly to the button's action method. This is where the real logic was:

```c
; --- This is the key check ---
; A function is called, and its result is in w0
00006550 7c 17 00 94   bl        \_objc\_msgSend
; tbz = Test Bit and Branch if Zero
; This is an IF statement: if (w0 == 0)
00006554 20 03 00 36   tbz       w0,\#0x0 ,LAB\_000065b8
; ------------------------------

; --- The "Success" Path (if w0 == 1) ---
00006564 00 00 32 91   add       x0=\>s\_Ye\_got\_it\_0000cc80 ,x0,\#0xc80
; ... calls function to show success popup ...
000065b4 1e 00 00 14   b         LAB\_0000662c

; --- The "Failure" Path (if w0 == 0) ---
LAB\_000065b8:
000065c0 00 d8 30 91   add       x0=\>s\_Nah\_0000cc36 ,x0,\#0xc36
000065ec 00 40 31 91   add       x0=\>s\_That\_ain\_t\_the\_pirate\_s\_path.\_0000cc50
; ... calls function to show "Nah" popup ...
00006638 c0 03 5f d6   ret
```

The entire challenge boiled down to one thing: **The `_objc_msgSend` at `00006550` calls a function. We need to make it return `1` (true) instead of `0` (false).**

The instructions just before `00006550` showed us what was being called:

```c
; Loads the object we are calling a method on
00006544 b4 83 1e f8   stur      x20 ,[x29 , \#local\_28 ]
; Loads the method name "\_9zB" into x1
0000654c 01 ad 46 f9   ldr       x1=\>s\_\_9zB\_0000dd4c ,[x8, \#0xd58 ]
; Calls [x20 \_9zB]
00006550 7c 17 00 94   bl        \_objc\_msgSend
```

The app was calling a method named `_9zB`. Tracing this led to the underlying Swift function, which was hardcoded to return `0`:

```c
; Function \_$s16SwizzleMeTimbers4Q9V0C4\_9zBSbyF
; Moves 0 into w8
000064b0 08 00 80 52   mov       w8,\#0x0
; w0 = w8 & 1 (so, 0 & 1 = 0)
000064b4 00 01 00 12   and       w0,w8,\#0x1
; Returns (with 0 in w0)
000064bc c0 03 5f d6   ret
```

## Part 3: The Rabbit Hole of the "SwizzleMeTimbers" Hint

The challenge name was the biggest hint: "SwizzleMeTimbers." The intended solution was to use Frida to perform "Method Swizzling" at runtime—to replace the function that returns `0` with one that returns `1`.

This is where the real challenge began. We tried multiple Frida scripts, and they all failed in confusing ways.

1. **Hooking the address:** `Interceptor.attach(baseAddr.add(0x64a4), ...)` failed. The hook never triggered, likely due to anti-hooking checks.

2. **Hooking the Swift name:** `Interceptor.attach(Module.findExportByName("_$s..."), ...)` failed. The function wasn't exported.

3. **Hooking the class method:** `Interceptor.attach(ObjC.classes.SwizzleMeTimbers.Q9V0["_9zB"].implementation, ...)` failed with `Could not find method`.

This was the "rabbit hole." We *knew* the class was `SwizzleMeTimbers.Q9V0` and the method was `_9zB`. Why couldn't Frida find it?

## Part 4: The "Aha!" Moment - The Magic Space

The breakthrough came from using Frida to **enumerate the class methods at runtime**:

```javascript
// find\_methods.js
const className = "SwizzleMeTimbers.Q9V0";
var methods = ObjC.classes[className].$ownMethods;
methods.forEach(function(methodName) {
console.log("  " + methodName);
});
```

The output was:

```powershell
Found 6 methods:
- viewDidLoad
- \_9zB
- t4G0
- initWithNibName:bundle:
- initWithCoder:
- .cxx\_destruct
```

This list was the key. We had been trying to hook `_9zB` or `-_9zB` (the standard prefix for an instance method). But the *actual, literal string* of the method name in the Objective-C runtime was:

**`"- _9zB"`**

It had **both** the instance method prefix (`-`) and a **space** before the name. We had missed the space. This subtle trick was the entire puzzle.

## Part 5: The Final Solution Script

With the *exact* name, we could write the final, simple script. We added a 1-second `setTimeout` to ensure the app had fully initialized before we tried to hook, solving the timing issue.

```javascript
const className = "SwizzleMeTimbers.Q9V0";
const targetMethod = "- \_9zB"; // The 100% correct name\!

console.log("Waiting 1 second for app to initialize...");

setTimeout(function() {
console.log("App should be ready. Hooking " + targetMethod + "...");

try {
    var methodToHook = ObjC.classes[className][targetMethod];
    if (!methodToHook) {
        throw new Error("Could not find method: " + targetMethod);
    }
    console.log("Found " + targetMethod + "! Attaching hook...");

    // Attach a simple hook to the target method
    Interceptor.attach(methodToHook.implementation, {
        
        // onLeave runs AFTER the original function
        onLeave: function(retval) {
            console.log("Hook on " + targetMethod + " triggered!");
            console.log("Original return value: " + retval);
            
            // --- THE SOLUTION ---
            // Change the return value from 0 to 1
            retval.replace(1);
            // --------------------------
            
            console.log("Changed return value to 1!");
        }
    });
    
    console.log("Successfully hooked " + targetMethod + ".");
    console.log("Ready for button tap!");

} catch (err) {
    console.log("Error during hooking: " + err.message);
}

}, 1000); // Wait 1 second

```

Running this script and tapping the button finally worked. The hook triggered, the return value was changed to `1`, and the app presented the "Ye got it" success message.

```powershell
[iOS Device::com.8ksec.SwizzleMeTimbers ]-> App should be ready. Hooking - _9zB...
Found - _9zB! Attaching hook...
Successfully hooked - _9zB.
Ready for button tap!
Hook on - _9zB triggered!
Original return value: 0x0
Changed return value to 1!
```

> Flag : CTF {{Swizle_mbers}}
---
