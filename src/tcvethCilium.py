from bcc import BPF
import argparse
import ipaddress
from pyroute2 import IPRoute
import pyroute2
import json
import os


# convert ipv4 to hexadecimal, to pass later to bpf program
def ipv4_to_hex(ip: str) -> str:
    value = int(ipaddress.IPv4Address(ip))
    return f"0x{value:08X}"

#apply configuration, if specified in the --config flag (which is passed as first arg)
import json
from typing import Dict, Tuple, List, Any

# apply configuration, if specified in the --config flag (which is passed as first arg)
def apply_config(
    path: str,
    interfaces: list,
    src_ifindex: int,
    src_ip: str,
    svcip: str,
    dst_ip_map: Dict[int, str],
) -> Tuple[List[Any], str, int, str, Dict[int, str]]:
    if not path:
        return interfaces, src_ip, src_ifindex, svcip, dst_ip_map

    with open(path, "r") as f:
        cfg = json.load(f)

    if isinstance(cfg.get("interfaces"), list) and cfg["interfaces"]:
        interfaces = cfg["interfaces"]

    if isinstance(cfg.get("src_ip"), str) and cfg["src_ip"]:
        src_ip = cfg["src_ip"]

    if isinstance(cfg.get("svcip"), str) and cfg["svcip"]:
        svcip = cfg["svcip"]

    # accept int or numeric string
    if "src_ifindex" in cfg and cfg["src_ifindex"] not in (None, ""):
        try:
            src_ifindex = int(cfg["src_ifindex"])
        except (TypeError, ValueError):
            pass

    cfg_dst = cfg.get("dst_ip")
    if isinstance(cfg_dst, dict) and cfg_dst:
        new_map: Dict[int, str] = {}
        for k, v in cfg_dst.items():
            if not isinstance(v, str) or not v:
                continue
            try:
                ifindex_key = int(k)
            except (TypeError, ValueError):
                continue
            new_map[ifindex_key] = v

        if new_map:
            dst_ip_map = new_map

    return interfaces, src_ip, src_ifindex, svcip, dst_ip_map


def cleanup():
    print("\n[*] Detaching TC and cleaning up...")

    try:
        # 删除 ingress filters（两个 parent）
        for idx in indexes:
            ipr.tc("del-filter", "bpf", idx, ":1", parent="ffff:fff2")
    except Exception:
        pass

    # try:
    #     ipr.tc("del-filter", "bpf", idx, ":1", parent="ffff:fff3")
    #     ipr.tc("del-filter", "bpf", idx1, ":1", parent="ffff:fff3")
    #     ipr.tc("del-filter", "bpf", idx2, ":1", parent="ffff:fff3")
    # except Exception:
    #     pass

    try:
        # 删除 clsact qdisc
        for idx in indexes:
            ipr.tc("del", "clsact", idx)
    except Exception:
        pass


    print("[✓] Cleanup done.")
    
ipr = IPRoute()


# if a config file is provided, ignore the upper variables and inject the new ones. Else, the variables wont change.
parser = argparse.ArgumentParser()
parser.add_argument("--config", "-c", help="Path to JSON config file", default=None)
parser.add_argument(
    "--cni",
    help="Which CNI plugin: cilium or flannel",
    choices=["cilium", "flannel"],
    required=True,
)
args = parser.parse_args()

# cilium => vpeer=1, flannel => vpeer=0
vpeer = 1 if args.cni == "cilium" else 0

interfaces, src_ifindex, svcs = apply_config(args.config)
interfaces = list(dict.fromkeys(interfaces))

# derive two destinations from dict
dst_items = sorted(dst_ip_map.items(), key=lambda kv: kv[0])
if len(dst_items) < 2:
    raise ValueError("dst_ip must contain at least two entries: {ifindex: ip}")

(dst_ifindex1, new_dst_ip1), (dst_ifindex2, new_dst_ip2) = dst_items[0], dst_items[1]
indexes = []
#inject configuration parameters as cflags in bpf program
cflags = [
    f"-DSRC_IP={ipv4_to_hex(src_ip)}",
    f"-DSRCIF={int(src_ifindex)}",
    f"-DSVCIP={ipv4_to_hex(svcip)}",
    f"-DNEW_DST_IP={ipv4_to_hex(new_dst_ip1)}",
    f"-DDSTIFINDEX={int(dst_ifindex1)}",
    f"-DNEW_DST_IP2={ipv4_to_hex(new_dst_ip2)}",
    f"-DDSTIFINDEX2={int(dst_ifindex2)}",
]

# Ensure the interface exists
try:
    for ifname in interfaces:
        indexes.append(ipr.link_lookup(ifname=ifname)[0])
except IndexError:
   print(f"Error: Interface {interfaces} not found. Is it created?")
   exit(1)

# Ensure clsact qdisc is added only once
try:
    for idx in indexes:
        ipr.tc("add", "clsact", idx)
  
except Exception as e:
    print(f"clsact qdisc already exists: {e}")

# Attach to veth0 using TC
try:

    # enabled calling the script from outside directory
    here = os.path.dirname(os.path.abspath(__file__))
    c_file = os.path.join(here, "tcveth.c")
    b = BPF(src_file = c_file, cflags=cflags, debug=0)
    # TODO: Add automatically later
   # backend_set = b["backend_set"]
   # backend_set[backend_set.Key(0x0A000132)] = backend_set.Leaf(1)  # 10.0.1.110
   # backend_set[backend_set.Key(0x0A00012A)] = backend_set.Leaf(1)  # 10.0.1.42

    fn = b.load_func("redirect_service", BPF.SCHED_CLS)
    for idx in indexes:
        ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1, direct_action=True)


    print(f"BPF attached to {interfaces} - SCHED_CLS: OK")
    print("Waiting for packets... Press Ctrl+C to stop.")
    b.trace_print()
finally:
   cleanup()
