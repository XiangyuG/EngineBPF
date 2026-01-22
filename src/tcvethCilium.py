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
# convert ipv4 to hexadecimal, to pass later to bpf program

class BackendPair(ct.Structure):
    _fields_ = [
        ("dst1", ct.c_uint32),
        ("ifindex1", ct.c_uint32),
        ("dst2", ct.c_uint32),
        ("ifindex2", ct.c_uint32),
    ]
#apply configuration, if specified in the --config flag (which is passed as first arg)

# apply configuration, if specified in the --config flag (which is passed as first arg)
def apply_config(path: Optional[str]) -> Tuple[List[str], int, dict]:
    # defaults (must be defined somewhere)
    interfaces = ["veth0"]
    src_ifindex = 2
    svc_dict: Dict[str, List[List[Any]]] = {}

    if not path:
        return interfaces, src_ifindex, svc_dict

    with open(path, "r") as f:
        cfg = json.load(f)

    if isinstance(cfg.get("interfaces"), list) and cfg["interfaces"]:
        interfaces = cfg["interfaces"]

    if "src_ifindex" in cfg and cfg["src_ifindex"] not in (None, ""):
        src_ifindex = int(cfg["src_ifindex"])

    if isinstance(cfg.get("svcip"), dict) and cfg["svcip"]:
        svc_dict = cfg["svcip"]
        

    return interfaces,  src_ifindex, svc_dict


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


indexes = []
#inject configuration parameters as cflags in bpf program
cflags = [
    f"-DSRCIF={int(src_ifindex)}",
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
    for k,v in svcs.items():
        new_dst_ip1 = v[0][1]
        new_dst_ip2 = v[1][1]
        dst_ifindex1 = v[0][0]
        dst_ifindex2 = v[1][0]
        svc_key = ct.c_uint32(ipv4_to_be32(k))
    
        leaf = BackendPair(
            dst1=ipv4_to_be32(new_dst_ip1),
            ifindex1=int(dst_ifindex1),
            dst2=ipv4_to_be32(new_dst_ip2),
            ifindex2=int(dst_ifindex2),
        )
        svc_backends[svc_key] = leaf
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
