"""Dynamic Network Ontology Semantic Layer (C, R) + Copy-on-Write Sandbox.

Builds a cross-device semantic graph directly from real ``vrp_ir.parse_text()``
outputs for Huawei VRP routers and USG firewalls, dereferencing string foreign
keys (VRF, FirewallZone, AddressSet, ServiceSet, shared Subnets/Links) into
first-class graph relations while preserving exact ``SourceRef(file:line)`` and
protected ``unparsed_lines``.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vrp_ir import parse_text


def _clean_paths(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in ("file", "source_file") and isinstance(v, str):
                out[k] = Path(v).name
            else:
                out[k] = _clean_paths(v)
        return out
    if isinstance(obj, list):
        return [_clean_paths(x) for x in obj]
    return obj


@dataclass
class NetworkSnapshot:
    """Immutable-style Copy-on-Write snapshot of multi-device Huawei configs."""

    configs: dict[str, str]
    _ir_cache: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)
    _graph_cache: dict[str, Any] | None = field(default=None, repr=False)

    def fork(self) -> NetworkSnapshot:
        """Create an isolated in-memory branch for What-if action exploration."""
        return NetworkSnapshot(configs=dict(self.configs))

    def with_config(self, device: str, new_text: str) -> NetworkSnapshot:
        dev = device.strip().upper()
        updated = dict(self.configs)
        updated[dev] = new_text if new_text.endswith("\n") else new_text + "\n"
        return NetworkSnapshot(configs=updated)

    def ir(self, device: str) -> dict[str, Any]:
        dev = device.strip().upper()
        if dev not in self._ir_cache:
            raw = self.configs[dev]
            parsed = parse_text(raw, filename=f"{dev}.cfg").to_dict()
            self._ir_cache[dev] = _clean_paths(parsed)
        return self._ir_cache[dev]

    def all_ir(self) -> dict[str, dict[str, Any]]:
        return {dev: self.ir(dev) for dev in self.configs}

    def ontology_graph(self) -> dict[str, Any]:
        if self._graph_cache is None:
            self._graph_cache = build_ontology_graph(self)
        return self._graph_cache


def build_ontology_graph(snap: NetworkSnapshot) -> dict[str, Any]:
    """Lift multi-device vrp-ir JSON into a cross-device Dynamic Ontology graph."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_ids: set[str] = set()

    def add_node(nid: str, ntype: str, label: str, **props: Any) -> None:
        if nid not in node_ids:
            node_ids.add(nid)
            nodes.append({"id": nid, "type": ntype, "label": label, "props": props})

    def add_edge(src: str, rel: str, dst: str, **props: Any) -> None:
        edges.append({"source": src, "relation": rel, "target": dst, "props": props})

    subnet_members: dict[str, list[tuple[str, str, str]]] = {}  # cidr -> [(dev, iface_id, ip)]

    for dev, ir in snap.all_ir().items():
        dev_id = f"dev:{dev}"
        is_fw = bool(ir.get("firewall_zones") or ir.get("security_rules"))
        add_node(
            dev_id,
            "Firewall" if is_fw else "Router",
            (ir.get("hostname") or {}).get("value") or dev,
            device=dev,
            file=f"{dev}.cfg",
            role="USG Firewall" if is_fw else "VRP Router",
            unparsed_count=len(ir.get("unparsed_lines") or []),
        )

        # Interfaces & Subnets
        iface_map: dict[str, str] = {}
        for iface in ir.get("interfaces") or []:
            if_name = (iface.get("name") or {}).get("value", "?")
            if_id = f"if:{dev}:{if_name}"
            iface_map[if_name] = if_id
            ips = []
            for ip_e in iface.get("ipv4") or []:
                addr = (ip_e.get("address") or {}).get("value")
                plen = (ip_e.get("prefix_length") or {}).get("value")
                line = ((ip_e.get("address") or {}).get("source") or {}).get("line")
                if addr and plen is not None:
                    ip_obj = ipaddress.IPv4Interface(f"{addr}/{plen}")
                    cidr = str(ip_obj.network)
                    ips.append(f"{addr}/{plen}")
                    sub_id = f"subnet:{cidr}"
                    add_node(sub_id, "Subnet", cidr, cidr=cidr)
                    add_edge(if_id, "CONNECTED_TO", sub_id, ip=addr, line=line)
                    subnet_members.setdefault(cidr, []).append((dev, if_id, addr))
            add_node(
                if_id,
                "Interface",
                f"{dev}.{if_name.replace('GigabitEthernet', 'GE')}",
                device=dev,
                name=if_name,
                ips=ips,
                description=(iface.get("description") or {}).get("value"),
                source=f"{dev}.cfg:L{(iface.get('source') or {}).get('line')}",
            )
            add_edge(dev_id, "HAS_INTERFACE", if_id)

        # Static Routes
        for idx, rt in enumerate(ir.get("static_routes") or []):
            dst = (rt.get("destination") or {}).get("value")
            mask = (rt.get("mask") or {}).get("value")
            nh = (rt.get("next_hop") or {}).get("value")
            line = (rt.get("source") or {}).get("line")
            if dst and mask and nh:
                net = str(ipaddress.IPv4Network(f"{dst}/{mask}", strict=False))
                rt_id = f"route:{dev}:L{line}:{idx}"
                add_node(
                    rt_id,
                    "StaticRoute",
                    f"{net} → {nh}",
                    device=dev,
                    cidr=net,
                    next_hop=nh,
                    source=f"{dev}.cfg:L{line}",
                )
                add_edge(dev_id, "HAS_ROUTE", rt_id)
                sub_id = f"subnet:{net}"
                if sub_id in node_ids:
                    add_edge(rt_id, "ROUTES_TO", sub_id)

        # Firewall Zones (dereferencing string interface names -> Interface nodes)
        zone_ids: dict[str, str] = {}
        for z in ir.get("firewall_zones") or []:
            zname = (z.get("name") or {}).get("value", "?")
            z_id = f"zone:{dev}:{zname}"
            zone_ids[zname] = z_id
            add_node(
                z_id,
                "FirewallZone",
                f"zone:{zname}",
                device=dev,
                name=zname,
                priority=(z.get("priority") or {}).get("value"),
                source=f"{dev}.cfg:L{(z.get('source') or {}).get('line')}",
            )
            add_edge(dev_id, "HAS_ZONE", z_id)
            for zif in z.get("interfaces") or []:
                iname = zif.get("value")
                if iname in iface_map:
                    add_edge(iface_map[iname], "IN_ZONE", z_id, line=(zif.get("source") or {}).get("line"))

        # AddressSets & ServiceSets
        addr_set_ids: dict[str, str] = {}
        for aset in ir.get("address_sets") or []:
            aname = (aset.get("name") or {}).get("value", "?")
            a_id = f"addrset:{dev}:{aname}"
            addr_set_ids[aname] = a_id
            members = []
            for m in aset.get("members") or []:
                addr = (m.get("address") or {}).get("value")
                plen = (m.get("prefix_length") or {}).get("value")
                if addr and plen is not None:
                    members.append(f"{addr}/{plen}")
                elif m.get("expression"):
                    members.append(m["expression"].get("value"))
            add_node(
                a_id,
                "AddressSet",
                f"addr-set:{aname}",
                device=dev,
                name=aname,
                members=members,
                source=f"{dev}.cfg:L{(aset.get('source') or {}).get('line')}",
            )
            add_edge(dev_id, "DEFINES_ADDR_SET", a_id)

        svc_set_ids: dict[str, str] = {}
        for sset in ir.get("service_sets") or []:
            sname = (sset.get("name") or {}).get("value", "?")
            s_id = f"svcset:{dev}:{sname}"
            svc_set_ids[sname] = s_id
            items = [(it.get("expression") or {}).get("value") for it in (sset.get("items") or [])]
            add_node(
                s_id,
                "ServiceSet",
                f"svc-set:{sname}",
                device=dev,
                name=sname,
                items=items,
                source=f"{dev}.cfg:L{(sset.get('source') or {}).get('line')}",
            )
            add_edge(dev_id, "DEFINES_SVC_SET", s_id)

        # Security Rules (dereferencing zone / address-set / service-set names)
        for order, rule in enumerate(ir.get("security_rules") or [], start=1):
            rname = (rule.get("name") or {}).get("value", f"rule_{order}")
            action = (rule.get("action") or {}).get("value", "deny")
            line = (rule.get("source") or {}).get("line")
            r_id = f"secrule:{dev}:{rname}"
            add_node(
                r_id,
                "SecurityRule",
                f"#{order} {rname} ({action.upper()})",
                device=dev,
                order=order,
                name=rname,
                action=action,
                source=f"{dev}.cfg:L{line}",
            )
            add_edge(dev_id, "HAS_SECURITY_RULE", r_id, order=order)
            for sz in rule.get("source_zones") or []:
                zn = sz.get("value")
                if zn in zone_ids:
                    add_edge(r_id, "SRC_ZONE", zone_ids[zn])
            for dz in rule.get("destination_zones") or []:
                zn = dz.get("value")
                if zn in zone_ids:
                    add_edge(r_id, "DST_ZONE", zone_ids[zn])
            for da in (rule.get("source_addresses") or []) + (rule.get("destination_addresses") or []):
                val = da.get("value", "")
                if val.startswith("address-set "):
                    aname = val.split("address-set ", 1)[1].strip()
                    if aname in addr_set_ids:
                        add_edge(r_id, "USES_ADDR_SET", addr_set_ids[aname])
            for sv in rule.get("services") or []:
                val = sv.get("value", "")
                if val in svc_set_ids:
                    add_edge(r_id, "USES_SVC_SET", svc_set_ids[val])

        # Protected unparsed_lines (Explicit Partial Grounding Frame)
        raw_lines = snap.configs[dev].splitlines()
        for u in ir.get("unparsed_lines") or []:
            ln = u.get("line")
            if ln:
                u_id = f"unparsed:{dev}:L{ln}"
                text = raw_lines[ln - 1].strip() if 1 <= ln <= len(raw_lines) else ""
                add_node(
                    u_id,
                    "ProtectedUnparsed",
                    f"🛡 {dev}.cfg:L{ln}",
                    device=dev,
                    line=ln,
                    raw_text=text,
                    source=f"{dev}.cfg:L{ln}",
                )
                add_edge(dev_id, "PROTECTS_UNPARSED", u_id)

    # Infer cross-device L3 Links from shared Subnets
    for cidr, members in subnet_members.items():
        if len(members) >= 2:
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    dev_a, if_a, ip_a = members[i]
                    dev_b, if_b, ip_b = members[j]
                    if dev_a != dev_b:
                        add_edge(if_a, "L3_LINK", if_b, subnet=cidr, peer_ips=f"{ip_a} <-> {ip_b}")

    # Summary counts by type
    type_counts: dict[str, int] = {}
    for n in nodes:
        type_counts[n["type"]] = type_counts.get(n["type"], 0) + 1

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "by_type": type_counts,
        },
    }
