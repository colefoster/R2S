# =============================================================================
# RSC Flight Format — Normal Server Action Request
# =============================================================================


# ---------------------------------------------------------------------------
# VARIANT A: text/plain — direct JS call with cross-chunk references
#
# Chunk "0" is always the argument list. "$1" is a reference to chunk 1.
# "$2:companyName" resolves chunk 2 and accesses the companyName key.
# Server reconstructs the full object graph before invoking the action.
#
# Decoded argument: { object: " company ", name: "Resecurity" }
#
# This path is SAFE — action ID is validated before the body is read.
# ---------------------------------------------------------------------------
POST {{host}}/
Next-Action: 6a3b9f2c1d8e4a7b0c5f2e9d3a6b8c1f4e7d0a3b
Content-Type: text/plain;charset=UTF-8

0:["$1"]
1:{"object":" company ","name":"$2:companyName"}
2:{"companyName":"Resecurity"}

HTTP *


# ---------------------------------------------------------------------------
# VARIANT B: multipart/form-data — same object graph, one chunk per field
#
# Each chunk becomes a named field. Field "0" is always the arg list.
# Server calls decodeReply() on the fields to rebuild the object graph.
#
# This path is VULNERABLE in 16.0.0–16.0.6 — decodeReply() runs
# on all fields BEFORE the action ID is validated.
# ---------------------------------------------------------------------------
POST {{host}}/
Next-Action: 6a3b9f2c1d8e4a7b0c5f2e9d3a6b8c1f4e7d0a3b
[MultipartFormData]
0: ["$1"]
1: {"object":" company ","name":"$2:companyName"}
2: {"companyName":"Resecurity"}

HTTP *
