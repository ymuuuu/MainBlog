---
title: "CyberAnime Web Challenge Writeup"
published: 2024-07-07
description: "This writeup details the steps taken to solve the CyberAnime Web Challenge on Cybertalents."
image: "https://miro.medium.com/v2/resize:fit:1400/format:webp/1*Bt2se2TrX7SoFY05Hwv6nw.png"
tags: ["web", "CTF", "pentest","cybersecurity","cybertalents","writeup"]
category: Writeups
lang: "en"
draft: false
---
# ( بِسْمِ اللَّـهِ الرَّحْمَـٰنِ الرَّحِيمِ )
:::caution
 #FreePalastine
:::
## Overview
This writeup details the steps taken to solve the **CyberAnime Web Challenge** on **Cybertalents**. The challenge involves bypassing JWT authentication to gain access as an admin and retrieve the flag.

---

## Step 1: Initial Reconnaissance
1. **Launch the Machine**: Start by launching the machine and accessing the provided URL.
2. **Login Attempt**: Try logging in with common credentials like `admin:admin`. This attempt fails, and there is nothing unusual in the source code.

---

## Step 2: Register an Account
1. **Register**: Register a new account using any credentials.
2. **Inspect POST Request**: Use **Burp Suite** to inspect the POST request sent during registration. The request redirects to `/home`.
![image.png](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*kdlLVgsyYgiZRP0OCoHi3Q.png)

---

## Step 3: Analyze Cookies
1. **SessionToken Cookie**: Inspect the `SessionToken` cookie using [jwt.io](https://jwt.io/).
2. **JWT Details**: The JWT uses the `RS256` algorithm. The `kid` (Key ID) is a random number, and the `jku` (JSON Web Key Set URL) points to `/.well-known/jwks.json`.
![image.png](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*gOV5n6myg2qAK6Z61YIs7A.png)
---

## Step 4: Access the JWKS Endpoint
1. **JWKS URL**: Access the JWKS URL:
> http://wcamxwl32pue3e6m873od00swzy0jk31drmetrzm-web.cybertalentslabs.com/.well-known/jwks.json
2. **Key Retrieval**: Confirm that the server returns a valid key.
![image.png](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*UUZek7-S8hOznng266-GdQ.png)
---

## Step 5: Exploit JWT Authentication via JKU Header Injection
1. **Objective**: Force the server to use a malicious JWKS URL to validate a forged JWT.
2. **Steps**:
- Generate a new RSA key pair using **Burp Suite's JWT Editor**.
- Copy the public key in JWK format.
- Host the malicious JWKS file on a server (e.g., Burp Collaborator or Exploit Server).
- Replace the `jku` parameter in the JWT header with the URL of the malicious JWKS file.
- Modify the `kid` parameter in the JWT header to match the `kid` of the malicious JWK.
- Change the `username` in the JWT payload to `admin`.
![image.png](https://miro.medium.com/v2/resize:fit:1180/format:webp/1*0e2_aZXX5nJMBZPjJxv1LA.png)
---

## Step 6: Craft and Sign the Malicious JWT
1. **JWK Format**:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "893d8f0b-061f-42c2-a4aa-5056e12b8ae7",
      "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw"
    }
  ]
}
```
2. **Sign the JWT: Use Burp Suite's JWT Editor to sign the JWT without modifying the header.**
![image.png](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*NtYGqp2yJvenKaf8lnjjdA.png)