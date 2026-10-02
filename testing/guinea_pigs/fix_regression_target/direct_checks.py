"""The pre-fix and the fixed security_checks against the SAME live lab, side by side.

Run through run_direct_checks.sh, which mounts the pre-fix module at /old.
"""
import importlib.util, sys, requests
sys.path[:0] = ["/repo/recon", "/repo"]
from recon.helpers import security_checks as new

spec = importlib.util.spec_from_file_location("old_sc", "/old/security_checks.py")
old = importlib.util.module_from_spec(spec); spec.loader.exec_module(old)

A, B = "192.88.95.10", "192.88.95.20"
# port_scan exactly as naabu writes it (port_scan.py by_ip shape).
recon = {"port_scan": {
    "scan_metadata": {}, "by_host": {}, "all_ports": [22, 80, 443, 3306, 6379, 8080, 8443],
    "ip_to_hostnames": {}, "summary": {},
    "by_ip": {A: {"ip": A, "hostnames": [], "ports": [22, 80, 3306, 6379, 8080, 8443], "cdn": None, "is_cdn": False},
              B: {"ip": B, "hostnames": [], "ports": [443, 8080], "cdn": None, "is_cdn": False}}}}
on = {k: True for k in ("admin_port_exposed", "database_exposed", "redis_no_auth",
                        "kubernetes_api_exposed", "smtp_open_relay")}

def kinds(rs):
    return sorted((f["type"], f.get("ip") or f.get("matched_ip"), f.get("port"), f["severity"]) for f in rs)

print("== run_port_service_checks (the dead loop) ==")
print(" OLD:", kinds(old.run_port_service_checks(recon, on, timeout=5)))
print(" NEW:", kinds(new.run_port_service_checks(recon, on, timeout=5)))

print("== kubernetes on host B (word 'kind' trap, 443) ==")
print(" OLD:", old.check_kubernetes_api_exposed(B, timeout=5))
print(" NEW:", new.check_kubernetes_api_exposed(B, timeout=5, ports=[443]))

print("== ip_api_exposed on host A ==")
o = old.check_ip_api_exposed(A, timeout=5); n = new.check_ip_api_exposed(A, timeout=5)
print(" OLD:", (o or {}).get("severity"), (o or {}).get("name"))
print(" NEW:", (n or {}).get("severity"), (n or {}).get("name"))

print("== session cookies on host B ==")
pick = lambda rs: sorted((f["type"], f["cookie_name"]) for f in rs)
print(" OLD:", pick(old.check_session_cookies(B, timeout=5)))
print(" NEW:", pick(new.check_session_cookies(B, timeout=5)))
