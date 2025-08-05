---
title: "Arab Wargames 2025 - Android Challenges Writeup"
published: 2025-08-05
description: "Comprehensive writeup for two Android reverse engineering challenges: Sacred Myth and Double Trouble"
image: "https://www.ascyberwargames.com/wp-content/uploads/2025/04/1920x1080-014-scaled.jpg"
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

```python
# Time to crack some ancient Android mysteries!
# Two challenges that think they're protected by the gods themselves
```

---

# Challenge 1 - The Sacred Myth - When Ancient Apps Meet Modern Hacking

## TL;DR - "I Don't Have Time for This!"

The app checks if you're at sacred coordinates (30.043801, 31.334688) at prophecy time (1754128800), but trusts everything the Android system tells it. We bypass this with Frida hooks.

---

## Understanding Our Target: The "Myth" App

So we've got this "ancient" Android app called "Myth" that supposedly holds some sacred secrets. Let me break down what this paranoid little app is trying to do:

### App Behavior Analysis

The app has multiple security checks. Here's what it's checking for:

1. **Location Verification**: Are you at the sacred coordinates?
2. **Time Verification**: Is it the prophecy moment?
3. **Anti-Debugging**: Are you trying to debug the app?
4. **Anti-Emulator**: Is this running on an emulator?
5. **Anti-Frida**: Is dynamic instrumentation present?

The app loads a native library called `libvault.so` that does the actual flag checking.

---

## Code Analysis: What We Need to Bypass

Let's look at the key protection mechanisms we discovered:

### 1. The Anti-Analysis Squad (Java Level)

```java
// In MainActivity.java (decompiled from smali)
private boolean checkDebugger() {
    // Checks if debugger is attached
    // Returns true if debugging detected
}

private boolean checkEmulator() {
    // Looks for emulator artifacts
    // Checks system properties, files, etc.
}

private boolean checkFrida() {
    // Searches for Frida processes
    // Scans /proc for suspicious stuff
}
```

**Why these are vulnerable**: These are just regular Java methods that Frida can hook easily.

### 2. The Space-Time Police (Location & Time)

```java
// Sacred coordinates hardcoded (rookie mistake!)
private static final double SACRED_LAT = 30.043801;
private static final double SACRED_LON = 31.334688;
private static final long TARGET_TIMESTAMP = 1754128800; // In seconds

public String getFlag(double lat, double lon, long time) {
    // Native call to libvault.so
    return nativeGetFlag(lat, lon, time);
}
```

**Why this is vulnerable**: The app trusts `System.currentTimeMillis()` and Android's location services completely.

### 3. The Native Bodyguard (libvault.so)

```c
// Native functions (found via reverse engineering)
FUN_00101270() // Anti-debug check #1
FUN_00101310() // Anti-debug check #2
FUN_001016a0() // Anti-emulator check
FUN_00101750() // Anti-frida check
```

**Why these are vulnerable**: They're exported with predictable names and we can patch them directly in memory.

---

## Exploitation Strategy: Divide and Conquer

Our approach is to disable the security systems one by one:

### 1. **Neutralize the Native Bodyguard**

First, we patch the native protection functions. We find libvault.so and patch its protection functions to always return "success":

```javascript
// Find and patch native protections
const mods = Process.enumerateModulesSync();
const vaultMod = mods.find((m) => m.name.toLowerCase().includes("vault"));

const exportsList = Module.enumerateExportsSync(vaultMod.name);
exportsList
  .filter((e) => /^FUN_00101(?:270|310|6a0|750)$/.test(e.name))
  .forEach((sym) => {
    // Replace with stub that returns 0 (success)
    Interceptor.replace(sym.address, new NativeCallback(() => 0, "int", []));
  });
```

### 2. **Time Manipulation**

Next, we control the time. Every time the app asks for the current time, we return the target timestamp:

```javascript
System.currentTimeMillis.implementation = () => {
  return 1754128800 * 1000; // Convert seconds to milliseconds
};
```

### 3. **Location Spoofing**

Then we spoof the GPS coordinates. When the app asks for location, we return the sacred coordinates:

```javascript
Location.getLatitude.implementation = () => 30.043801;
Location.getLongitude.implementation = () => 31.334688;
```

### 4. **Permission Bypass**

Finally, we bypass the permission system by making the app think we have all required permissions:

```javascript
CtxCompat.checkSelfPermission.implementation = function (ctx, perm) {
  if (perm.includes("LOCATION")) return 0; // PERMISSION_GRANTED
  return this.checkSelfPermission(ctx, perm);
};
```

---

## The Complete Exploit

Here's our final Frida script that combines all the bypasses:

```javascript
// solver.js - The Sacred Myth Destroyer
Java.perform(function () {
  console.log("[+] === MYTH CTF DYNAMIC BYPASS ===");

  // 1) Native Layer Exploitation - Disable the bodyguards
  const mods = Process.enumerateModulesSync();
  const vaultMod = mods.find((m) => m.name.toLowerCase().includes("vault"));
  if (!vaultMod) {
    console.error("[-] Could not find a module with 'vault' in its name!");
  } else {
    console.log("[+] Found native module:", vaultMod.name);

    // Directly patch anti-analysis functions at assembly level
    const exportsList = Module.enumerateExportsSync(vaultMod.name);
    exportsList
      .filter((e) => /^FUN_00101(?:270|310|6a0|750)$/.test(e.name))
      .forEach((sym) => {
        // Replace function with stub that always returns 0 (success)
        Interceptor.replace(
          sym.address,
          new NativeCallback(() => 0, "int", [])
        );
      });
  }

  // 2) System Call Interception - Prevent rage quit
  const exitPtr = Module.findExportByName(null, "exit");
  if (exitPtr) {
    Interceptor.replace(
      exitPtr,
      new NativeCallback(
        (code) => {
          console.log("[BYTESAFE] exit(" + code + ") suppressed");
          // Prevent app from terminating when detection triggers
        },
        "void",
        ["int"]
      )
    );
  }

  // 3) Space-Time Manipulation
  const SAC_LAT = 30.043801;
  const SAC_LON = 31.334688;
  const TARGET_S = 1754128800; // The chosen timestamp
  const targetMs = TARGET_S * 1000; // Convert to milliseconds

  const MainActivity = Java.use("asc.wargames.myth.MainActivity");
  const System = Java.use("java.lang.System");
  const Location = Java.use("android.location.Location");
  const LocMgr = Java.use("android.location.LocationManager");
  const CtxCompat = Java.use("androidx.core.content.ContextCompat");
  const ActCompat = Java.use("androidx.core.app.ActivityCompat");

  // ––– Anti-debug / emulator / frida bypasses
  MainActivity.checkDebugger.implementation = () => false;
  MainActivity.checkEmulator.implementation = () => false;
  MainActivity.checkFrida.implementation = () => false;

  // ––– Time spoof
  System.currentTimeMillis.implementation = () => {
    return targetMs;
  };

  // ––– Location spoof
  Location.getLatitude.implementation = () => SAC_LAT;
  Location.getLongitude.implementation = () => SAC_LON;
  LocMgr.getLastKnownLocation.overload("java.lang.String").implementation =
    function (provider) {
      const loc = Location.$new(provider);
      loc.setLatitude(SAC_LAT);
      loc.setLongitude(SAC_LON);
      loc.setTime(targetMs);
      loc.setAccuracy(1.0);
      console.log(`[LOC] getLastKnownLocation(${provider}) → spoofed`);
      return loc;
    };

  // ––– Permission spoofing
  CtxCompat.checkSelfPermission.implementation = function (ctx, perm) {
    if (perm.includes("LOCATION")) return 0;
    return this.checkSelfPermission(ctx, perm);
  };
  ActCompat.checkSelfPermission.overload(
    "android.content.Context",
    "java.lang.String"
  ).implementation = function (ctx, perm) {
    if (perm.includes("LOCATION")) return 0;
    return this.checkSelfPermission(ctx, perm);
  };

  // ––– Hook getFlag
  const jGetFlag = MainActivity.getFlag.overload("double", "double", "long");
  jGetFlag.implementation = function (lat, lon, timeArg) {
    console.log(`[FLAG] getFlag(${lat}, ${lon}, ${timeArg})`);
    const res = jGetFlag.call(this, SAC_LAT, SAC_LON, targetMs);
    console.log("[FLAG] →", res);
    return res;
  };

  // ––– Hook unlockMyth
  MainActivity.unlockMyth.implementation = function () {
    console.log("[HOOK] unlockMyth()");
    const f = this.getFlag(SAC_LAT, SAC_LON, targetMs);
    console.log("[HOOK] flag →", f);
  };

  console.log("[+] All hooks in place. Tap 'Unlock the Myth'!");
});
```

---

## Execution: The Moment of Truth

1. **Setup**: Install Frida and connect to your Android device/emulator
2. **Deploy**: Run the script while starting the Myth app:
   ```bash
   frida -U -l solver.js -f asc.wargames.myth
   ```
3. **Activate**: Tap the "Unlock the Myth" button in the app
4. **Victory**: After running our exploit, the flag is displayed in the frida console!

---

## The Flag: ASCWG{MY7H_15_0wn3d_by_7h3_0n3_wh0_574y3d_7h3_W17ch3r}

---

## Deep Dive Analysis - Questions that came across my mind :'D

### Q1: How did we identify all the protection mechanisms?

**Answer**: Through systematic static and dynamic analysis:

**Static Analysis**:

- Decompiled the APK using jadx or apktool
- Examined MainActivity.java for protection function calls
- Found references to libvault.so native library
- Identified hardcoded coordinates and timestamp values

**Dynamic Analysis**:

- Used Frida to hook Java methods and observe behavior
- Monitored native function calls and their return values
- Traced location and time API calls

### Q2: Why are the native protection functions so easily bypassed?

**Answer**: **Poor implementation choices by the developers**:

1. **Predictable export names**: Functions named `FUN_00101270` are auto-generated by disassemblers
2. **No obfuscation**: Functions are clearly visible in the export table
3. **Simple return values**: Functions just return 0/1 for success/failure

### Q3: How did we know the exact coordinates and timestamp to spoof?

**Answer**: **Hardcoded values found in the source code**:

```java
// Found in MainActivity.java (decompiled)
private static final double SACRED_LAT = 30.043801;
private static final double SACRED_LON = 31.334688;
private static final long TARGET_TIMESTAMP = 1754128800;
```

**Why this is a security flaw**:

- Hardcoding secrets in the app makes them discoverable through static analysis
- Any reverse engineer can extract these values
- The app should have fetched these from a secure server

### Q4: Why does Frida hooking work so effectively here?

**Answer**: **The app trusts the Android framework completely**:

1. **No hook detection**: App doesn't check if methods are being intercepted
2. **Framework reliance**: App calls standard Android APIs that Frida can easily hook
3. **No native verification**: Even though there's a native library, it still relies on Java-provided data

### Q5: What makes the location and time spoofing so trivial?

**Answer**: **Android's security model limitations**:

**Location Spoofing Works Because**:

```javascript
// App calls standard location APIs
Location.getLatitude.implementation = () => 30.043801;
Location.getLongitude.implementation = () => 31.334688;
```

**Time Spoofing Works Because**:

```javascript
// App trusts system time
System.currentTimeMillis.implementation = () => {
  return 1754128800 * 1000;
};
```

**Why this is vulnerable**:

- Apps cannot verify GPS authenticity without additional hardware
- System time can be manipulated by root access or framework hooking
- No cryptographic verification of location/time data

_"The myth was that the app was secure. The reality was that it trusted everyone!"_

---

# Challenge 2 - Double Trouble - When Intent Goes Wrong

## TL;DR - "UUID Generation Gone Wrong!"

The app generates a random UUID password but has a critical Intent handling bug that causes crashes on successful authentication. We fix the null Intent and extract the password via Smali modification.

---

## Understanding Our Target: The "Double Trouble" App

This challenge presents an Android app with a deceptively simple authentication mechanism that hides a critical flaw in its Intent handling system.

### App Behavior Analysis

The app implements multiple layers of "security":

1. **Dynamic Password Generation**: Creates a random UUID at runtime
2. **Password Validation**: Checks user input against generated password
3. **Launch Counter**: Tracks app launches for alternative access
4. **Intent Navigation**: Attempts to launch SecondActivity on success
5. **Crash on Success**: App crashes when correct password is entered (the bug!)

The main vulnerability lies in the Intent creation logic that passes `null` instead of the target activity class.

---

## Code Analysis: What We Need to Understand

Let's examine the key components and vulnerabilities we discovered:

### 1. The Password Generation System (MainActivity.smali)

```smali
# In MainActivity onCreate method:
invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;  # Generate UUID
move-result-object p1
invoke-virtual {p1}, Ljava/util/UUID;->toString()Ljava/lang/String;  # Convert to string
move-result-object p1
const/4 v0, 0x0      # Start index 0
const/16 v1, 0x14    # Length 20 (0x14 = 20 in decimal)
invoke-virtual {p1, v0, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;  # Take first 20 chars
move-result-object p1
iput-object p1, p0, Lcom/hacking/test/MainActivity;->v:Ljava/lang/String;  # Store in field 'v'
```

**Why this is exploitable**: The password is generated at runtime and stored in a predictable field that we can access through Smali modification.

### 2. The Broken Intent System (H0/a.smali)

```smali
# The problematic Intent creation
const/4 v1, 0x0  # NULL class - This is the bug!
new-instance v0, Landroid/content/Intent;
invoke-direct {v0, p1, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

# Should be:
const-class v1, Lcom/hacking/test/SecondActivity;
new-instance v0, Landroid/content/Intent;
invoke-direct {v0, p1, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
```

**Why this crashes**: Android cannot launch an Intent with a null target class, causing a NullPointerException.

### 3. The Counter Bypass Mechanism (SecondActivity.smali)

```smali
# In SecondActivity onCreate:
const/16 v0, 0x14           # Generate random number 1-20
invoke-virtual {p1, v0}, Ljava/util/Random;->nextInt(I)I
add-int/lit8 p1, p1, 0x1    # threshold = random(1-20)

# Get current launch count
const-string v2, "launch_count"
invoke-interface {v0, v2, v1}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I
move-result v3

# Check TWO conditions:
if-eqz v4, :cond_0          # If from_password is true, OR
if-lt v3, p1, :cond_1       # If launch_count >= threshold
    goto :goto_0            # Show secret (layout 0x7f0b001d)
else
    invoke-virtual {p0}, Landroid/app/Activity;->finish()V  # Close activity
```

**Why this exists**: Provides an alternative access method, but our Intent fix makes this unnecessary.

---

## Exploitation Strategy: Fix and Extract

Our approach combines static analysis with dynamic modification:

### 1. **Password Extraction via Logging**

We inject logging code right after password generation to capture the UUID:

**Code injection point**:

```smali
# Right after this line:
iput-object p1, p0, Lcom/hacking/test/MainActivity;->v:Ljava/lang/String;
# We can add our logging code here because 'p1' still contains the password
```

### 2. **Intent Fix**

Replace the null class reference with the correct SecondActivity class:

```smali
# Replace this line:
const/4 v1, 0x0

# With this:
const-class v1, Lcom/hacking/test/SecondActivity;
```

---

## Execution: The Step-by-Step Solution

1. **Decompile the APK**: Extract and examine the Smali files
2. **Identify the Bug**: Locate the null Intent creation in H0/a.smali
3. **Extract Password**: Add logging to MainActivity.smali to capture UUID
4. **Fix Intent**: Replace null with SecondActivity class reference
5. **Recompile**: Build the modified APK and install
6. **Execute**: Run app, read password from logs, enter it, and access SecondActivity and you will get the passowrd as image file.

---

## The Solution Files

### Modified MainActivity.smali (Password Logging)

```smali
# Add after password storage
iput-object p1, p0, Lcom/hacking/test/MainActivity;->v:Ljava/lang/String;

# Logging injection
const-string v2, "PASSWORD_DEBUG"
invoke-static {v2, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
```

### Modified H0/a.smali (Intent Fix)

```smali
# Replace the null Intent creation
const-class v1, Lcom/hacking/test/SecondActivity;  # Fixed line
new-instance v0, Landroid/content/Intent;
invoke-direct {v0, p1, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
```

---

## Deep Dive Analysis - Questions that came accross my mind :'D

### Q1: How did we know the UUID was the password?

**Answer**: By reading the MainActivity.smali code systematically:

```smali
# In MainActivity onCreate method:
invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;  # Generate UUID
move-result-object p1
invoke-virtual {p1}, Ljava/util/UUID;->toString()Ljava/lang/String;  # Convert to string
move-result-object p1
const/4 v0, 0x0      # Start index 0
const/16 v1, 0x14    # Length 20 (0x14 = 20 in decimal)
invoke-virtual {p1, v0, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;  # Take first 20 chars
move-result-object p1
iput-object p1, p0, Lcom/hacking/test/MainActivity;->v:Ljava/lang/String;  # Store in field 'v'
```

Then in H0/a.smali (click handler):

```smali
iget-object v1, p1, Lcom/hacking/test/MainActivity;->v:Ljava/lang/String;  # Get stored password
invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z  # Compare with input
```

**Methodology**:

- Reverse engineering requires following data flow
- We traced: UUID generation → substring → storage → comparison
- The field 'v' clearly holds the password for comparison

### Q2: How did we know we could read and print the UUID?

**Answer**: In Android/Java, we can modify any application's behavior by:

1. **Adding logging calls**: Android provides `Log.d()`, `Log.i()` functions
2. **Adding Toast messages**: `Toast.makeText()` for UI display
3. **Smali is modifiable**: Unlike compiled binaries, Smali is human-readable bytecode

**Why this works**:

- The UUID generation happens at runtime in onCreate()
- We can inject code RIGHT AFTER generation but BEFORE use
- Android logging system is always available to applications

### Q3: Is setting Intent to null a common practice?

**Answer**: **ABSOLUTELY NOT** - this is either:

1. **A bug in the original app** - developer forgot to specify target activity
2. **Intentional obfuscation** - to make reverse engineering harder
3. **Anti-tampering mechanism** - app designed to crash on "success"

**Normal Intent creation looks like**:

```smali
# Correct way:
const-class v1, Lcom/package/TargetActivity;
new-instance v0, Landroid/content/Intent;
invoke-direct {v0, p1, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

# What we found (WRONG):
const/4 v1, 0x0  # NULL class
new-instance v0, Landroid/content/Intent;
invoke-direct {v0, p1, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
```

**This is suspicious because**:

- No legitimate app would intentionally crash on successful authentication
- It suggests the challenge creator wanted to test our debugging skills

### Q4: How did we know changing null to SecondActivity would work?

**Answer**: **Logical deduction + file structure analysis**:

1. **File enumeration**: We saw `SecondActivity.smali` exists in the APK
2. **Intent analysis**: The Intent was setting `"from_password" = true` extra
3. **SecondActivity logic**: Reading SecondActivity.smali showed it checks for `"from_password"` extra
4. **Common Android patterns**: Activities are typically organized as flows

**Evidence from SecondActivity.smali**:

```smali
# SecondActivity checks for this exact extra:
const-string v5, "from_password"
invoke-virtual {v4, v5, v1}, Landroid/content/Intent;->getBooleanExtra(Ljava/lang/String;Z)Z
move-result v4
if-eqz v4, :cond_0  # If from_password is true, show secret
```

**Reasoning**: If the Intent sets `from_password=true`, and SecondActivity checks for this, then SecondActivity is clearly the intended destination.

### Q5: The Counter Mechanism Explained

**Answer**: The counter was a **secondary bypass mechanism**, but our fix made it irrelevant.

**How the counter works**:

```smali
# In SecondActivity onCreate:
const/16 v0, 0x14           # Generate random number 1-20
invoke-virtual {p1, v0}, Ljava/util/Random;->nextInt(I)I
add-int/lit8 p1, p1, 0x1    # threshold = random(1-20)

# Get current launch count
const-string v2, "launch_count"
invoke-interface {v0, v2, v1}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I
move-result v3

# Check TWO conditions:
if-eqz v4, :cond_0          # If from_password is true, OR
if-lt v3, p1, :cond_1       # If launch_count >= threshold
    goto :goto_0            # Show secret (layout 0x7f0b001d)
else
    invoke-virtual {p0}, Landroid/app/Activity;->finish()V  # Close activity
```

---

_"The trouble was doubled: random passwords AND broken navigation. But every bug is just another door waiting to be opened!"_
