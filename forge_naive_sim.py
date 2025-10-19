# forge_naive_sim.py  (simulation for lab demo)
import json, os

os.makedirs("artifacts/mitm", exist_ok=True)
with open("artifacts/mitm/data_naive.json") as f:
    j = json.load(f)

orig = j["body"]
# Simulate attacker appending a new field (is_admin)
forged = dict(orig)
forged["is_admin"] = True

# reuse original sig (simulation); in a real length-extension attack attacker would compute new sig
forged_obj = {"body": forged, "sig": j["sig"]}

with open("artifacts/mitm/data_naive_forged.json", "w") as f:
    json.dump(forged_obj, f, indent=2)

print("Wrote artifacts/mitm/data_naive_forged.json (simulation).")
