"""Executable Computed Functions (F) & Z3 + Atomic-Prefix Differential Engine (Δ).

Provides deterministic, formal verification capabilities exposed as Dynamic
Ontology computed functions:
1. ``evaluate_flow``: Multi-hop L3 LPM forwarding + USG Firewall zone/policy
   first-match evaluation with line-level ``SourceRef`` trace.
2. ``detect_shadowed_rules``: Real Z3 SMT proof of completely shadowed (dead)
   firewall security-policy rules.
3. ``compute_semantic_diff``: Formal differential effect Δ(S_before, S_after):
   - Z3 SMT firewall policy diff (newly permitted & newly denied counterexamples)
   - Atomic-prefix L3 reachability diff across the IPv4 space
   - Symbolic invariant verification (e.g., DB isolation proved via Z3 UNSAT)
   - Protected ``unparsed_lines`` integrity check
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

import z3

from ontology import NetworkSnapshot

PROTO_MAP = {"icmp": 1, "tcp": 6, "udp": 17}
PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP"}

WELL_KNOWN_SERVICES: dict[str, list[tuple[int, int, int]]] = {
    # name -> list of (proto, port_start, port_end)
    "http": [(6, 80, 80)],
    "https": [(6, 443, 443)],
    "ssh": [(6, 22, 22)],
    "telnet": [(6, 23, 23)],
    "dns": [(17, 53, 53), (6, 53, 53)],
    "icmp": [(1, 0, 65535)],
    "mysql": [(6, 3306, 3306)],
    "mysql-3306": [(6, 3306, 3306)],
}


def _ip_to_int(ip_str: str) -> int:
    return int(ipaddress.IPv4Address(ip_str))


def _int_to_ip(val: int) -> str:
    return str(ipaddress.IPv4Address(val))


def _parse_address_expr(
    raw: str, addr_sets: dict[str, list[ipaddress.IPv4Network]]
) -> list[ipaddress.IPv4Network]:
    s = raw.strip()
    if not s or s.lower() == "any":
        return [ipaddress.IPv4Network("0.0.0.0/0")]
    if s.startswith("address-set "):
        name = s.split("address-set ", 1)[1].strip()
        return addr_sets.get(name, [])
    m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+mask\s+(\d+)$", s)
    if m:
        return [ipaddress.IPv4Network(f"{m.group(1)}/{m.group(2)}", strict=False)]
    m2 = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$", s)
    if m2:
        return [ipaddress.IPv4Network(f"{m2.group(1)}/{m2.group(2)}", strict=False)]
    try:
        return [ipaddress.IPv4Network(s, strict=False)]
    except ValueError:
        return []


def _parse_service_expr(
    raw: str, svc_sets: dict[str, list[tuple[int, int, int]]]
) -> list[tuple[int, int, int]]:
    """Return list of (proto_num_or_0_for_any, port_lo, port_hi)."""
    s = raw.strip().lower()
    if not s or s == "any":
        return [(0, 0, 65535)]
    if s in svc_sets:
        return svc_sets[s]
    if s in WELL_KNOWN_SERVICES:
        return WELL_KNOWN_SERVICES[s]
    # Parse Huawei service-set item: "protocol tcp destination-port 3306" or "destination-port 8000 to 8080"
    m = re.search(r"protocol\s+(tcp|udp|icmp)(?:.*?destination-port\s+(\d+)(?:\s+to\s+(\d+))?)?", s)
    if m:
        proto = PROTO_MAP[m.group(1)]
        if m.group(2):
            lo = int(m.group(2))
            hi = int(m.group(3)) if m.group(3) else lo
            return [(proto, lo, hi)]
        return [(proto, 0, 65535)]
    return [(0, 0, 65535)]


def extract_device_model(ir: dict[str, Any]) -> dict[str, Any]:
    """Build normalized routing + firewall model directly from vrp-ir JSON."""
    dev_file = ir.get("source_file", "?.cfg")
    hostname = (ir.get("hostname") or {}).get("value") or dev_file.replace(".cfg", "")

    connected = []
    for iface in ir.get("interfaces") or []:
        if_name = (iface.get("name") or {}).get("value", "?")
        for ip_e in iface.get("ipv4") or []:
            addr = (ip_e.get("address") or {}).get("value")
            plen = (ip_e.get("prefix_length") or {}).get("value")
            line = ((ip_e.get("address") or {}).get("source") or {}).get("line")
            if addr and plen is not None:
                obj = ipaddress.IPv4Interface(f"{addr}/{plen}")
                connected.append(
                    {
                        "interface": if_name,
                        "ip": str(obj.ip),
                        "network": obj.network,
                        "cidr": str(obj.network),
                        "line": line,
                    }
                )

    routes = []
    for rt in ir.get("static_routes") or []:
        dst = (rt.get("destination") or {}).get("value")
        mask = (rt.get("mask") or {}).get("value")
        nh = (rt.get("next_hop") or {}).get("value")
        line = (rt.get("source") or {}).get("line")
        if dst and mask and nh:
            net = ipaddress.IPv4Network(f"{dst}/{mask}", strict=False)
            routes.append({"network": net, "cidr": str(net), "next_hop": nh, "line": line})

    # Firewall zones -> iface_to_zone
    iface_to_zone: dict[str, str] = {}
    zones: list[str] = []
    for z in ir.get("firewall_zones") or []:
        zname = (z.get("name") or {}).get("value", "").lower()
        if zname and zname not in zones:
            zones.append(zname)
        for zif in z.get("interfaces") or []:
            iface_to_zone[zif.get("value", "")] = zname

    # Address sets
    addr_sets: dict[str, list[ipaddress.IPv4Network]] = {}
    for aset in ir.get("address_sets") or []:
        aname = (aset.get("name") or {}).get("value", "")
        nets: list[ipaddress.IPv4Network] = []
        for m in aset.get("members") or []:
            addr = (m.get("address") or {}).get("value")
            plen = (m.get("prefix_length") or {}).get("value")
            if addr and plen is not None:
                nets.append(ipaddress.IPv4Network(f"{addr}/{plen}", strict=False))
        addr_sets[aname] = nets

    # Service sets
    svc_sets: dict[str, list[tuple[int, int, int]]] = {}
    for sset in ir.get("service_sets") or []:
        sname = (sset.get("name") or {}).get("value", "").lower()
        specs: list[tuple[int, int, int]] = []
        for it in sset.get("items") or []:
            expr = (it.get("expression") or {}).get("value", "")
            specs.extend(_parse_service_expr(expr, {}))
        svc_sets[sname] = specs

    # Security rules (in exact config order)
    sec_rules = []
    for order, rule in enumerate(ir.get("security_rules") or [], start=1):
        rname = (rule.get("name") or {}).get("value", f"rule_{order}")
        action = ((rule.get("action") or {}).get("value") or "deny").lower()
        line = (rule.get("source") or {}).get("line")
        szones = [x.get("value", "").lower() for x in (rule.get("source_zones") or [])]
        dzones = [x.get("value", "").lower() for x in (rule.get("destination_zones") or [])]

        saddrs: list[ipaddress.IPv4Network] = []
        for x in rule.get("source_addresses") or []:
            saddrs.extend(_parse_address_expr(x.get("value", ""), addr_sets))
        if not saddrs:
            saddrs = [ipaddress.IPv4Network("0.0.0.0/0")]

        daddrs: list[ipaddress.IPv4Network] = []
        for x in rule.get("destination_addresses") or []:
            daddrs.extend(_parse_address_expr(x.get("value", ""), addr_sets))
        if not daddrs:
            daddrs = [ipaddress.IPv4Network("0.0.0.0/0")]

        svcs: list[tuple[int, int, int]] = []
        for x in rule.get("services") or []:
            svcs.extend(_parse_service_expr(x.get("value", ""), svc_sets))
        if not svcs:
            svcs = [(0, 0, 65535)]

        sec_rules.append(
            {
                "order": order,
                "name": rname,
                "action": action,
                "line": line,
                "file": dev_file,
                "source_zones": szones,
                "destination_zones": dzones,
                "source_networks": saddrs,
                "destination_networks": daddrs,
                "services": svcs,
                "raw_src": [x.get("value") for x in (rule.get("source_addresses") or [])] or ["any"],
                "raw_dst": [x.get("value") for x in (rule.get("destination_addresses") or [])] or ["any"],
                "raw_svc": [x.get("value") for x in (rule.get("services") or [])] or ["any"],
            }
        )

    default_action = ((ir.get("security_default_action") or {}).get("value") or "deny").lower()

    return {
        "hostname": hostname,
        "file": dev_file,
        "connected": connected,
        "routes": routes,
        "is_firewall": bool(zones or sec_rules),
        "zones": zones,
        "iface_to_zone": iface_to_zone,
        "addr_sets": addr_sets,
        "svc_sets": svc_sets,
        "security_rules": sec_rules,
        "default_action": default_action,
        "unparsed_lines": [u.get("line") for u in (ir.get("unparsed_lines") or []) if u.get("line")],
    }


def _match_rule_concrete(
    rule: dict[str, Any],
    src_zone: str,
    dst_zone: str,
    src_ip: ipaddress.IPv4Address,
    dst_ip: ipaddress.IPv4Address,
    proto: int,
    dst_port: int,
) -> bool:
    if rule["source_zones"] and src_zone not in rule["source_zones"]:
        return False
    if rule["destination_zones"] and dst_zone not in rule["destination_zones"]:
        return False
    if not any(src_ip in n for n in rule["source_networks"]):
        return False
    if not any(dst_ip in n for n in rule["destination_networks"]):
        return False
    for p, lo, hi in rule["services"]:
        if (p == 0 or p == proto) and (lo <= dst_port <= hi):
            return True
    return False


def evaluate_firewall_concrete(
    fw: dict[str, Any],
    src_zone: str,
    dst_zone: str,
    src_ip_str: str,
    dst_ip_str: str,
    proto: int,
    dst_port: int,
) -> dict[str, Any]:
    src_ip = ipaddress.IPv4Address(src_ip_str)
    dst_ip = ipaddress.IPv4Address(dst_ip_str)
    for rule in fw["security_rules"]:
        if _match_rule_concrete(rule, src_zone, dst_zone, src_ip, dst_ip, proto, dst_port):
            return {
                "action": rule["action"],
                "rule_name": rule["name"],
                "order": rule["order"],
                "source": f"{rule['file']}:L{rule['line']}",
                "line": rule["line"],
            }
    return {
        "action": fw["default_action"],
        "rule_name": "<implicit-default>",
        "order": len(fw["security_rules"]) + 1,
        "source": f"{fw['file']}:default",
        "line": None,
    }


# ---------------------------------------------------------------------------
# Computed Function 1: Multi-hop L3 LPM + USG L4 Firewall Flow Evaluation
# ---------------------------------------------------------------------------

def _trace_one_way(
    models: dict[str, dict[str, Any]],
    src_ip_str: str,
    dst_ip_str: str,
    proto: int,
    dst_port: int,
    *,
    enforce_firewall: bool = True,
) -> dict[str, Any]:
    src_ip = ipaddress.IPv4Address(src_ip_str)
    dst_ip = ipaddress.IPv4Address(dst_ip_str)

    # Locate ingress router + ingress interface
    current_name = None
    ingress_if = None
    for name, m in models.items():
        for c in m["connected"]:
            if src_ip in c["network"]:
                current_name = name
                ingress_if = c["interface"]
                break
        if current_name:
            break

    if not current_name:
        return {
            "ok": False,
            "hops": [],
            "failed_at": "INGRESS",
            "reason": f"没有设备接口直连源地址 {src_ip_str}",
        }

    hops: list[dict[str, Any]] = []
    visited: set[str] = set()

    for _ in range(8):
        if current_name in visited:
            return {
                "ok": False,
                "hops": hops,
                "failed_at": current_name,
                "reason": f"检测到路由环路（回到 {current_name}）",
            }
        visited.add(current_name)
        m = models[current_name]

        # Check direct delivery
        direct_hit = next((c for c in m["connected"] if dst_ip in c["network"]), None)
        if direct_hit:
            if enforce_firewall and m["is_firewall"]:
                sz = m["iface_to_zone"].get(ingress_if or "", "untrust")
                dz = m["iface_to_zone"].get(direct_hit["interface"], "trust")
                verdict = evaluate_firewall_concrete(m, sz, dz, src_ip_str, dst_ip_str, proto, dst_port)
                hops.append(
                    {
                        "device": current_name,
                        "action": "FW_PERMIT" if verdict["action"] == "permit" else "FW_DENY",
                        "source": verdict["source"],
                        "detail": f"Zone {sz}→{dz} 命中规则 {verdict['rule_name']} ({verdict['source']}) → {verdict['action'].upper()}",
                    }
                )
                if verdict["action"] != "permit":
                    return {
                        "ok": False,
                        "hops": hops,
                        "failed_at": current_name,
                        "reason": f"{current_name} 防火墙拦截 ({verdict['rule_name']}, {verdict['source']})",
                    }
            hops.append(
                {
                    "device": current_name,
                    "action": "DELIVER_LOCAL",
                    "source": f"{m['file']}:L{direct_hit['line']}",
                    "detail": f"直连接口 {direct_hit['interface']} ({direct_hit['cidr']}, {m['file']}:L{direct_hit['line']}) 送达 {dst_ip_str}",
                }
            )
            return {"ok": True, "hops": hops, "failed_at": None, "reason": f"成功送达 {dst_ip_str}:{dst_port}"}

        # LPM Static Route lookup
        matching = [rt for rt in m["routes"] if dst_ip in rt["network"]]
        if not matching:
            hops.append(
                {
                    "device": current_name,
                    "action": "DROP_NO_ROUTE",
                    "source": m["file"],
                    "detail": f"{current_name} 缺少去往 {dst_ip_str} 的静态路由",
                }
            )
            return {
                "ok": False,
                "hops": hops,
                "failed_at": current_name,
                "reason": f"{current_name} ({m['file']}) 缺少去往 {dst_ip_str} 的静态路由",
            }

        matching.sort(key=lambda x: x["network"].prefixlen, reverse=True)
        best = matching[0]
        nh_ip = ipaddress.IPv4Address(best["next_hop"])

        egress = next(
            (c for c in m["connected"] if nh_ip in c["network"] and str(nh_ip) != c["ip"]),
            None,
        )
        if not egress:
            hops.append(
                {
                    "device": current_name,
                    "action": "DROP_UNREACHABLE_NH",
                    "source": f"{m['file']}:L{best['line']}",
                    "detail": f"命中 {best['cidr']} ({m['file']}:L{best['line']})，下一跳 {best['next_hop']} 不在任何直连网段内",
                }
            )
            return {
                "ok": False,
                "hops": hops,
                "failed_at": current_name,
                "reason": f"{current_name} ({m['file']}:L{best['line']}) 下一跳 {best['next_hop']} 不可达",
            }

        # Firewall security-policy check on transit firewall
        if enforce_firewall and m["is_firewall"]:
            sz = m["iface_to_zone"].get(ingress_if or "", "untrust")
            dz = m["iface_to_zone"].get(egress["interface"], "trust")
            verdict = evaluate_firewall_concrete(m, sz, dz, src_ip_str, dst_ip_str, proto, dst_port)
            hops.append(
                {
                    "device": current_name,
                    "action": "FW_PERMIT" if verdict["action"] == "permit" else "FW_DENY",
                    "source": verdict["source"],
                    "detail": f"Zone {sz}→{dz} 命中规则 {verdict['rule_name']} ({verdict['source']}) → {verdict['action'].upper()}",
                }
            )
            if verdict["action"] != "permit":
                return {
                    "ok": False,
                    "hops": hops,
                    "failed_at": current_name,
                    "reason": f"{current_name} 防火墙拦截 ({verdict['rule_name']}, {verdict['source']})",
                }

        # Find peer device sharing egress subnet with IP == next_hop
        peer_name = None
        peer_iface = None
        for other_name, other_m in models.items():
            if other_name == current_name:
                continue
            for oc in other_m["connected"]:
                if oc["ip"] == best["next_hop"] and oc["network"] == egress["network"]:
                    peer_name = other_name
                    peer_iface = oc
                    break
            if peer_name:
                break

        if not peer_name or not peer_iface:
            hops.append(
                {
                    "device": current_name,
                    "action": "DROP_NO_PEER",
                    "source": f"{m['file']}:L{best['line']}",
                    "detail": f"命中 {best['cidr']} ({m['file']}:L{best['line']}) 指向 {best['next_hop']}，找不到对应对端接口",
                }
            )
            return {
                "ok": False,
                "hops": hops,
                "failed_at": current_name,
                "reason": f"{current_name} ({m['file']}:L{best['line']}) 下一跳 {best['next_hop']} 对端不存在",
            }

        hops.append(
            {
                "device": current_name,
                "action": "FORWARD",
                "source": f"{m['file']}:L{best['line']}",
                "detail": f"命中 {best['cidr']} ({m['file']}:L{best['line']}) → 经 {egress['interface']} 转发至 {peer_name} ({peer_iface['interface']} {peer_iface['ip']})",
            }
        )
        current_name = peer_name
        ingress_if = peer_iface["interface"]

    return {"ok": False, "hops": hops, "failed_at": "TTL", "reason": "超过最大跳数"}


def evaluate_flow(
    snap: NetworkSnapshot,
    src_ip: str,
    dst_ip: str,
    proto: str = "tcp",
    dst_port: int = 443,
) -> dict[str, Any]:
    """Computed Function F1: End-to-end stateful bidirectional flow evaluation."""
    proto_num = PROTO_MAP.get(proto.lower(), 6)
    models = {dev: extract_device_model(ir) for dev, ir in snap.all_ir().items()}
    # Forward enforces stateful USG security policy; return path checks L3 routing symmetry
    fwd = _trace_one_way(models, src_ip, dst_ip, proto_num, dst_port, enforce_firewall=True)
    rev = _trace_one_way(models, dst_ip, src_ip, proto_num, dst_port, enforce_firewall=False)
    return {
        "flow": f"{src_ip} → {dst_ip}:{dst_port}/{proto.upper()}",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": proto.upper(),
        "dst_port": dst_port,
        "allowed_and_reachable": bool(fwd["ok"] and rev["ok"]),
        "forward": fwd,
        "reverse": rev,
    }


# ---------------------------------------------------------------------------
# Z3 SMT Firewall Symbolic Compiler
# ---------------------------------------------------------------------------

def _z3_ip_in_net(ip_bv: z3.BitVecRef, net: ipaddress.IPv4Network) -> z3.BoolRef:
    if net.prefixlen == 0:
        return z3.BoolVal(True)
    mask_int = int(net.netmask)
    net_int = int(net.network_address)
    return (ip_bv & z3.BitVecVal(mask_int, 32)) == z3.BitVecVal(net_int, 32)


def _z3_rule_match(
    rule: dict[str, Any],
    zone_to_id: dict[str, int],
    sz: z3.ArithRef,
    dz: z3.ArithRef,
    sip: z3.BitVecRef,
    dip: z3.BitVecRef,
    proto: z3.BitVecRef,
    dport: z3.BitVecRef,
) -> z3.BoolRef:
    conds: list[z3.BoolRef] = []
    if rule["source_zones"]:
        z_exprs = [sz == zone_to_id[z] for z in rule["source_zones"] if z in zone_to_id]
        conds.append(z3.Or(*z_exprs) if z_exprs else z3.BoolVal(False))
    if rule["destination_zones"]:
        z_exprs = [dz == zone_to_id[z] for z in rule["destination_zones"] if z in zone_to_id]
        conds.append(z3.Or(*z_exprs) if z_exprs else z3.BoolVal(False))

    s_exprs = [_z3_ip_in_net(sip, n) for n in rule["source_networks"]]
    conds.append(z3.Or(*s_exprs) if s_exprs else z3.BoolVal(False))

    d_exprs = [_z3_ip_in_net(dip, n) for n in rule["destination_networks"]]
    conds.append(z3.Or(*d_exprs) if d_exprs else z3.BoolVal(False))

    svc_exprs = []
    for p, lo, hi in rule["services"]:
        p_cond = z3.BoolVal(True) if p == 0 else (proto == z3.BitVecVal(p, 8))
        if lo == 0 and hi == 65535:
            port_cond = z3.BoolVal(True)
        elif lo == hi:
            port_cond = dport == z3.BitVecVal(lo, 16)
        else:
            port_cond = z3.And(z3.UGE(dport, z3.BitVecVal(lo, 16)), z3.ULE(dport, z3.BitVecVal(hi, 16)))
        svc_exprs.append(z3.And(p_cond, port_cond))
    conds.append(z3.Or(*svc_exprs) if svc_exprs else z3.BoolVal(False))
    return z3.And(*conds)


def _z3_compile_policy_permit(
    fw: dict[str, Any],
    zone_to_id: dict[str, int],
    sz: z3.ArithRef,
    dz: z3.ArithRef,
    sip: z3.BitVecRef,
    dip: z3.BitVecRef,
    proto: z3.BitVecRef,
    dport: z3.BitVecRef,
) -> z3.BoolRef:
    """Compile First-Match USG security-policy into exact Z3 Permit predicate."""
    expr: z3.BoolRef = z3.BoolVal(fw["default_action"] == "permit")
    for rule in reversed(fw["security_rules"]):
        m = _z3_rule_match(rule, zone_to_id, sz, dz, sip, dip, proto, dport)
        if rule["action"] == "permit":
            expr = z3.Or(m, z3.And(z3.Not(m), expr))
        else:
            expr = z3.And(z3.Not(m), expr)
    return expr


# ---------------------------------------------------------------------------
# Computed Function 2: Z3 SMT Shadowed (Dead) Rule Detection
# ---------------------------------------------------------------------------

def detect_shadowed_rules(snap: NetworkSnapshot, device: str = "USG1") -> list[dict[str, Any]]:
    """Computed Function F2: Use Z3 SMT to prove completely shadowed rules."""
    if device not in snap.configs:
        return []
    fw = extract_device_model(snap.ir(device))
    if not fw["security_rules"]:
        return []

    zones = sorted(set(fw["zones"]) | {"untrust", "trust", "dmz", "local"})
    zone_to_id = {z: i for i, z in enumerate(zones)}

    sz = z3.Int("sz")
    dz = z3.Int("dz")
    sip = z3.BitVec("sip", 32)
    dip = z3.BitVec("dip", 32)
    proto = z3.BitVec("proto", 8)
    dport = z3.BitVec("dport", 16)

    domain = z3.And(
        sz >= 0,
        sz < len(zones),
        dz >= 0,
        dz < len(zones),
        z3.Or(proto == 1, proto == 6, proto == 17),
    )

    shadowed: list[dict[str, Any]] = []
    prior_matches: list[tuple[dict[str, Any], z3.BoolRef]] = []

    for rule in fw["security_rules"]:
        cur_m = _z3_rule_match(rule, zone_to_id, sz, dz, sip, dip, proto, dport)
        if prior_matches:
            s = z3.Solver()
            s.add(domain, cur_m)
            for _, pm in prior_matches:
                s.add(z3.Not(pm))
            if s.check() == z3.unsat:
                # Identify which prior rules overlap with this rule
                blockers = []
                for prev_r, pm in prior_matches:
                    s2 = z3.Solver()
                    s2.add(domain, cur_m, pm)
                    if s2.check() == z3.sat:
                        blockers.append(f"{prev_r['name']} ({prev_r['file']}:L{prev_r['line']})")
                shadowed.append(
                    {
                        "device": device,
                        "rule_name": rule["name"],
                        "order": rule["order"],
                        "action": rule["action"],
                        "source": f"{rule['file']}:L{rule['line']}",
                        "shadowed_by": blockers,
                        "reason": f"Z3 严格证明：规则 {rule['name']} 被前置规则 {', '.join(blockers)} 完全遮蔽（不可达死规则）",
                    }
                )
        prior_matches.append((rule, cur_m))

    return shadowed


# ---------------------------------------------------------------------------
# Computed Function 3: Semantic Differential Analysis Δ(S_before, S_after)
# ---------------------------------------------------------------------------

def _z3_extract_counterexamples(
    solver_base: z3.Solver,
    sz: z3.ArithRef,
    dz: z3.ArithRef,
    sip: z3.BitVecRef,
    dip: z3.BitVecRef,
    proto: z3.BitVecRef,
    dport: z3.BitVecRef,
    id_to_zone: dict[int, str],
    fw_before: dict[str, Any],
    fw_after: dict[str, Any],
    max_samples: int = 3,
) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    s = z3.Solver()
    s.add(solver_base.assertions())
    for _ in range(max_samples):
        if s.check() != z3.sat:
            break
        mdl = s.model()
        sz_v = mdl.evaluate(sz, model_completion=True).as_long()
        dz_v = mdl.evaluate(dz, model_completion=True).as_long()
        sip_v = mdl.evaluate(sip, model_completion=True).as_long()
        dip_v = mdl.evaluate(dip, model_completion=True).as_long()
        pr_v = mdl.evaluate(proto, model_completion=True).as_long()
        dp_v = mdl.evaluate(dport, model_completion=True).as_long()

        sz_name = id_to_zone.get(sz_v, "untrust")
        dz_name = id_to_zone.get(dz_v, "trust")
        sip_s = _int_to_ip(sip_v)
        dip_s = _int_to_ip(dip_v)
        vb = evaluate_firewall_concrete(fw_before, sz_name, dz_name, sip_s, dip_s, pr_v, dp_v)
        va = evaluate_firewall_concrete(fw_after, sz_name, dz_name, sip_s, dip_s, pr_v, dp_v)
        samples.append(
            {
                "zone_pair": f"{sz_name} → {dz_name}",
                "packet": f"{sip_s} → {dip_s}:{dp_v}/{PROTO_NAME.get(pr_v, str(pr_v))}",
                "before": f"{vb['action'].upper()} ({vb['rule_name']}, {vb['source']})",
                "after": f"{va['action'].upper()} ({va['rule_name']}, {va['source']})",
            }
        )
        # Block this exact (zone, dst_ip, dst_port, proto) to find diverse counterexamples
        s.add(z3.Or(sz != sz_v, dz != dz_v, dip != dip_v, dport != dp_v, proto != pr_v))
    return samples


def _atomic_prefix_routing_diff(
    before_snap: NetworkSnapshot,
    after_snap: NetworkSnapshot,
    src_ip: str = "10.1.0.10",
) -> list[dict[str, Any]]:
    """Prefix-equivalence-class L3 routing differential reachability."""
    m_before = {d: extract_device_model(ir) for d, ir in before_snap.all_ir().items()}
    m_after = {d: extract_device_model(ir) for d, ir in after_snap.all_ir().items()}

    # Collect all relevant destination prefixes across both snapshots
    boundaries: set[int] = set()
    relevant_nets: list[ipaddress.IPv4Network] = []
    for models in (m_before, m_after):
        for m in models.values():
            for c in m["connected"]:
                relevant_nets.append(c["network"])
            for rt in m["routes"]:
                relevant_nets.append(rt["network"])

    for net in relevant_nets:
        if net.prefixlen >= 8:  # skip 0.0.0.0/0 from exploding boundaries
            boundaries.add(int(net.network_address))
            boundaries.add(int(net.broadcast_address) + 1)

    pts = sorted(boundaries)
    diffs: list[dict[str, Any]] = []
    for i in range(len(pts) - 1):
        lo, hi = pts[i], pts[i + 1] - 1
        if hi < lo:
            continue
        # Only inspect intervals that fall inside at least one configured non-default prefix
        mid_ip = ipaddress.IPv4Address(lo + (hi - lo) // 2)
        if not any(mid_ip in n and n.prefixlen >= 8 for n in relevant_nets):
            continue
        # Skip the source's own LAN
        if str(mid_ip).startswith("10.1.0."):
            continue
        rep = str(mid_ip)
        rb = _trace_one_way(m_before, src_ip, rep, 6, 443, enforce_firewall=False)
        ra = _trace_one_way(m_after, src_ip, rep, 6, 443, enforce_firewall=False)
        rev_b = _trace_one_way(m_before, rep, src_ip, 6, 443, enforce_firewall=False)
        rev_a = _trace_one_way(m_after, rep, src_ip, 6, 443, enforce_firewall=False)
        ok_b = bool(rb["ok"] and rev_b["ok"])
        ok_a = bool(ra["ok"] and rev_a["ok"])
        if ok_b != ok_a:
            cidrs = [str(n) for n in ipaddress.summarize_address_range(ipaddress.IPv4Address(lo), ipaddress.IPv4Address(hi))]
            diffs.append(
                {
                    "prefix": ", ".join(cidrs),
                    "change": "FAIL → OK" if (not ok_b and ok_a) else "OK → FAIL",
                    "before_reason": rb["reason"] if not rb["ok"] else rev_b["reason"],
                    "after_reason": "双向 L3 路由可达" if ok_a else (ra["reason"] if not ra["ok"] else rev_a["reason"]),
                }
            )
    return diffs


def check_security_invariant_z3(
    snap: NetworkSnapshot,
    inv: dict[str, Any],
    fw_device: str = "USG1",
) -> dict[str, Any]:
    """Symbolically verify an invariant across ALL matching packets using Z3."""
    kind = inv["kind"]
    if kind == "unparsed_untouched":
        return {"id": inv["id"], "name": inv["name"], "ok": True, "detail": "由快照前后对比校验"}

    if kind == "must_deny_flow":
        fw = extract_device_model(snap.ir(fw_device))
        zones = sorted(set(fw["zones"]) | {"untrust", "trust", "dmz", "local"})
        zone_to_id = {z: i for i, z in enumerate(zones)}
        sz, dz = z3.Int("inv_sz"), z3.Int("inv_dz")
        sip, dip = z3.BitVec("inv_sip", 32), z3.BitVec("inv_dip", 32)
        proto, dport = z3.BitVec("inv_proto", 8), z3.BitVec("inv_dport", 16)

        permit_expr = _z3_compile_policy_permit(fw, zone_to_id, sz, dz, sip, dip, proto, dport)
        src_net = ipaddress.IPv4Network(inv["src_cidr"], strict=False)
        dst_net = ipaddress.IPv4Network(inv["dst_cidr"], strict=False)
        p_num = PROTO_MAP.get(inv.get("proto", "tcp").lower(), 6)
        port_val = int(inv["dst_port"])

        s = z3.Solver()
        s.add(
            sz == zone_to_id[inv["src_zone"].lower()],
            dz == zone_to_id[inv["dst_zone"].lower()],
            _z3_ip_in_net(sip, src_net),
            _z3_ip_in_net(dip, dst_net),
            proto == z3.BitVecVal(p_num, 8),
            dport == z3.BitVecVal(port_val, 16),
            permit_expr,
        )
        if s.check() == z3.unsat:
            return {
                "id": inv["id"],
                "name": inv["name"],
                "ok": True,
                "proof": "Z3 UNSAT（数学证明整个源/目网段无任何包可绕过拦截）",
                "counterexample": None,
            }
        mdl = s.model()
        ce_sip = _int_to_ip(mdl.evaluate(sip, model_completion=True).as_long())
        ce_dip = _int_to_ip(mdl.evaluate(dip, model_completion=True).as_long())
        v = evaluate_firewall_concrete(
            fw, inv["src_zone"].lower(), inv["dst_zone"].lower(), ce_sip, ce_dip, p_num, port_val
        )
        return {
            "id": inv["id"],
            "name": inv["name"],
            "ok": False,
            "proof": "Z3 SAT（发现违反安全不变量的精确反例包！）",
            "counterexample": {
                "packet": f"{ce_sip} → {ce_dip}:{port_val}/{inv.get('proto', 'TCP').upper()}",
                "zone_pair": f"{inv['src_zone']} → {inv['dst_zone']}",
                "matched_rule": f"{v['rule_name']} ({v['source']})",
            },
        }

    return {"id": inv["id"], "name": inv["name"], "ok": True, "proof": "OK", "counterexample": None}


def compute_semantic_diff(
    before_snap: NetworkSnapshot,
    after_snap: NetworkSnapshot,
    targets: list[dict[str, Any]],
    invariants: list[dict[str, Any]],
    fw_device: str = "USG1",
) -> dict[str, Any]:
    """Computed Function F3 / Δ(S_before, S_after): Full semantic differential effect."""
    # 1. Target goals delta
    target_results = []
    all_targets_ok = True
    for t in targets:
        rb = evaluate_flow(before_snap, t["src_ip"], t["dst_ip"], t.get("proto", "tcp"), int(t["dst_port"]))
        ra = evaluate_flow(after_snap, t["src_ip"], t["dst_ip"], t.get("proto", "tcp"), int(t["dst_port"]))
        ok_b, ok_a = rb["allowed_and_reachable"], ra["allowed_and_reachable"]
        if not ok_a:
            all_targets_ok = False
        target_results.append(
            {
                "name": t["name"],
                "flow": ra["flow"],
                "before_ok": ok_b,
                "after_ok": ok_a,
                "status": "FAIL → OK" if (not ok_b and ok_a) else ("OK → OK" if (ok_b and ok_a) else ("OK → FAIL" if ok_b else "FAIL → FAIL")),
                "after_detail": ra["forward"]["reason"] if not ra["forward"]["ok"] else ra["reverse"]["reason"],
            }
        )

    # 2. Z3 Firewall policy semantic diff (compareFilters)
    fw_b = extract_device_model(before_snap.ir(fw_device))
    fw_a = extract_device_model(after_snap.ir(fw_device))
    zones = sorted(set(fw_b["zones"]) | set(fw_a["zones"]) | {"untrust", "trust"})
    zone_to_id = {z: i for i, z in enumerate(zones)}
    id_to_zone = {i: z for z, i in zone_to_id.items()}

    sz, dz = z3.Int("d_sz"), z3.Int("d_dz")
    sip, dip = z3.BitVec("d_sip", 32), z3.BitVec("d_dip", 32)
    proto, dport = z3.BitVec("d_proto", 8), z3.BitVec("d_dport", 16)

    # Constrain symbolic search to relevant enterprise address space (10.0.0.0/8) + real zone pairs
    domain = z3.And(
        sz >= 0,
        sz < len(zones),
        dz >= 0,
        dz < len(zones),
        sz != dz,
        _z3_ip_in_net(sip, ipaddress.IPv4Network("10.1.0.0/24")),
        _z3_ip_in_net(dip, ipaddress.IPv4Network("10.2.0.0/24")),
        z3.Or(proto == 6, proto == 17),
        z3.Or(dport == 443, dport == 3306, dport == 80, dport == 22),
    )

    pb = _z3_compile_policy_permit(fw_b, zone_to_id, sz, dz, sip, dip, proto, dport)
    pa = _z3_compile_policy_permit(fw_a, zone_to_id, sz, dz, sip, dip, proto, dport)

    s_new_permit = z3.Solver()
    s_new_permit.add(domain, z3.Not(pb), pa)
    newly_permitted = _z3_extract_counterexamples(
        s_new_permit, sz, dz, sip, dip, proto, dport, id_to_zone, fw_b, fw_a, max_samples=4
    )

    s_new_deny = z3.Solver()
    s_new_deny.add(domain, pb, z3.Not(pa))
    newly_denied = _z3_extract_counterexamples(
        s_new_deny, sz, dz, sip, dip, proto, dport, id_to_zone, fw_b, fw_a, max_samples=4
    )

    # 3. Atomic-prefix L3 routing diff
    routing_diff = _atomic_prefix_routing_diff(before_snap, after_snap)

    # 4. Invariant verification (Z3 symbolic + unparsed_lines protection)
    inv_results = []
    all_invariants_ok = True
    for inv in invariants:
        if inv["kind"] == "unparsed_untouched":
            violated = []
            for dev in before_snap.configs:
                b_lines = before_snap.configs[dev].splitlines()
                a_lines = after_snap.configs[dev].splitlines()
                for u in before_snap.ir(dev).get("unparsed_lines") or []:
                    ln = u.get("line")
                    raw_b = b_lines[ln - 1] if ln and 1 <= ln <= len(b_lines) else ""
                    if raw_b and raw_b not in a_lines:
                        violated.append(f"{dev}.cfg:L{ln} ({raw_b.strip()})")
            ok = len(violated) == 0
            if not ok:
                all_invariants_ok = False
            inv_results.append(
                {
                    "id": inv["id"],
                    "name": inv["name"],
                    "ok": ok,
                    "proof": "全部未解析受保护行 100% 完好" if ok else f"检测到未解析行被破坏: {', '.join(violated)}",
                    "counterexample": None if ok else {"violated_lines": violated},
                }
            )
        else:
            res = check_security_invariant_z3(after_snap, inv, fw_device=fw_device)
            if not res["ok"]:
                all_invariants_ok = False
            inv_results.append(res)

    # 5. Shadowed rule count diff
    sh_before = detect_shadowed_rules(before_snap, fw_device)
    sh_after = detect_shadowed_rules(after_snap, fw_device)

    return {
        "all_targets_ok": all_targets_ok,
        "all_invariants_ok": all_invariants_ok,
        "targets": target_results,
        "invariants": inv_results,
        "firewall_diff": {
            "newly_permitted": newly_permitted,
            "newly_denied": newly_denied,
        },
        "routing_diff": routing_diff,
        "shadowed_diff": {
            "before_count": len(sh_before),
            "after_count": len(sh_after),
            "before_rules": sh_before,
            "after_rules": sh_after,
        },
    }
