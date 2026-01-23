from bcc import BPF
import socket
import struct
from typing import Optional
import argparse
import ipaddress
from pyroute2 import IPRoute
import pyroute2
import json
import os
import ctypes as ct
from typing import Dict, Tuple, List, Any


def ipv4_to_be32(ip: str) -> int:
    # network byte order u32, matches iphdr->daddr / bpf_htonl() usage in your BPF code
    return struct.unpack("!I", socket.inet_aton(ip))[0]

class BackendPair(ct.Structure):
    _fields_ = [
        ("size", ct.c_uint32),
        ("ips", ct.c_uint32 * 4),
    ]

# apply configuration, if specified in the --config flag (which is passed as first arg)
def apply_config(path: Optional[str]) -> Tuple[List[str], int, dict]:
    # defaults (must be defined somewhere)
    interfaces = ["veth0"]
    svc_dict: Dict[str, List[List[Any]]] = {}
    ip_ifidx_dict: Dict[int, int] = {}

    if not path:
        return interfaces, svc_dict, ip_ifidx_dict

    with open(path, "r") as f:
        cfg = json.load(f)

    if isinstance(cfg.get("interfaces"), list) and cfg["interfaces"]:
        interfaces = cfg["interfaces"]

    if isinstance(cfg.get("svcip"), dict) and cfg["svcip"]:
        svc_dict = cfg["svcip"]

    if isinstance(cfg.get("podIfIdx"), dict) and cfg["podIfIdx"]:
        ip_ifidx_dict = cfg["podIfIdx"]

    return interfaces, svc_dict, ip_ifidx_dict


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

interfaces, svcs, ip_ifidx_dict = apply_config(args.config)
interfaces = list(dict.fromkeys(interfaces))


indexes = []
#inject configuration parameters as cflags in bpf program
cflags = [
    f"-DSRCVPEER={vpeer}",

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
    svc_backends = b.get_table("svc_backends", keytype=ct.c_uint32, leaftype=BackendPair)
    print(svcs)
    for k,v in svcs.items():
        svc_key = ct.c_uint32(ipv4_to_be32(k))
        leaf = BackendPair()
        leaf.size = len(v)
        for i in range(len(v)):
            leaf.ips[i] = ipv4_to_be32(v[i])
        svc_backends[svc_key] = leaf
    podIfIdx = b.get_table("podIfIdx", keytype=ct.c_uint32, leaftype=ct.c_uint32)
    for k,v in ip_ifidx_dict.items():
        podIfIdx_key = ct.c_uint32(ipv4_to_be32(k))
        podIfIdx_val = ct.c_uint32(v)
        podIfIdx[podIfIdx_key] = podIfIdx_val

    fn = b.load_func("redirect_service", BPF.SCHED_CLS)
    for idx in indexes:
        ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1, direct_action=True)


    print(f"BPF attached to {interfaces} - SCHED_CLS: OK")
    print("Waiting for packets... Press Ctrl+C to stop.")
    b.trace_print()
finally:
   cleanup()

