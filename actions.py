"""Structured Semantic Actions (A) with Preconditions & VRP Lowering.

Replaces raw blind text edits with typed ontology actions that:
1. Enforce explicit Preconditions (including hard protection of ``unparsed_lines``).
2. Execute inside an isolated Copy-on-Write ``NetworkSnapshot`` (zero disk side-effects).
3. Lower cleanly into minimal Huawei VRP CLI diffs with line-level ``SourceRef``.
"""
from __future__ import annotations

import difflib
import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from ontology import NetworkSnapshot


@dataclass
class ActionResult:
    ok: bool
    action_type: str
    device: str
    summary: str
    snapshot: NetworkSnapshot
    diff: str = ""
    changed_lines: int = 0
    error: str | None = None
    blocked_by_guardrail: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "action_type": self.action_type,
            "device": self.device,
            "summary": self.summary,
            "diff": self.diff,
            "changed_lines": self.changed_lines,
            "error": self.error,
            "blocked_by_guardrail": self.blocked_by_guardrail,
        }


def _unified_diff(device: str, old_text: str, new_text: str) -> tuple[str, int]:
    diff_lines = list(
        difflib.unified_diff(
            old_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"a/{device}.cfg",
            tofile=f"b/{device}.cfg",
            n=2,
        )
    )
    changed = sum(
        1
        for ln in diff_lines
        if (ln.startswith("+") and not ln.startswith("+++"))
        or (ln.startswith("-") and not ln.startswith("---"))
    )
    return "".join(diff_lines), changed


def _find_security_rule_span(lines: list[str], rule_name: str) -> tuple[int, int] | None:
    """Return 0-indexed [start, end) line span of ``rule name <rule_name>`` inside security-policy."""
    in_sec = False
    start = None
    for i, raw in enumerate(lines):
        s = raw.strip()
        if s == "security-policy":
            in_sec = True
            continue
        if in_sec and raw and not raw[0].isspace():
            if start is not None:
                return (start, i)
            in_sec = False
            continue
        if not in_sec:
            continue
        m = re.match(r"^\s+rule\s+name\s+(\S+)\s*$", raw)
        if m:
            if start is not None:
                return (start, i)
            if m.group(1) == rule_name:
                start = i
    if start is not None:
        return (start, len(lines))
    return None


def _is_unparsed_line(snap: NetworkSnapshot, device: str, line_number: int) -> bool:
    ir = snap.ir(device)
    unp = {u.get("line") for u in (ir.get("unparsed_lines") or []) if u.get("line")}
    return line_number in unp


def execute_action(snap: NetworkSnapshot, action: dict[str, Any]) -> ActionResult:
    """Execute one structured semantic action on a forked Copy-on-Write snapshot."""
    atype = str(action.get("type", "")).strip()
    dev = str(action.get("device", "")).strip().upper()
    if dev not in snap.configs:
        return ActionResult(False, atype, dev, f"未知设备 {dev}", snap, error=f"设备 {dev} 不在本体中")

    old_text = snap.configs[dev]
    lines = old_text.splitlines()

    if atype == "FixStaticRouteNextHop":
        line_no = int(action["line_number"])
        new_nh = str(action["new_next_hop"]).strip()
        try:
            ipaddress.IPv4Address(new_nh)
        except ValueError:
            return ActionResult(False, atype, dev, "非法下一跳 IP", snap, error=f"无效 IPv4 地址: {new_nh}")

        if _is_unparsed_line(snap, dev, line_no):
            return ActionResult(
                False,
                atype,
                dev,
                f"拦截：试图修改受保护未解析行 {dev}.cfg:L{line_no}",
                snap,
                error=f"Action Precondition 拦截：{dev}.cfg:L{line_no} 位于 vrp-ir 的 unparsed_lines 受保护帧内，禁止修改。",
                blocked_by_guardrail=True,
            )
        if line_no < 1 or line_no > len(lines):
            return ActionResult(False, atype, dev, "行号越界", snap, error=f"行号 L{line_no} 超出范围")
        old_line = lines[line_no - 1]
        parts = old_line.strip().split()
        if len(parts) < 5 or parts[0] != "ip" or parts[1] != "route-static":
            return ActionResult(False, atype, dev, "目标行不是静态路由", snap, error=f"L{line_no} 不是 ip route-static")
        parts[4] = new_nh
        new_lines = list(lines)
        new_lines[line_no - 1] = " ".join(parts)
        new_text = "\n".join(new_lines) + "\n"
        diff, cnt = _unified_diff(dev, old_text, new_text)
        return ActionResult(
            True,
            atype,
            dev,
            f"修复 {dev}.cfg:L{line_no} 静态路由下一跳 → {new_nh}",
            snap.with_config(dev, new_text),
            diff=diff,
            changed_lines=cnt,
        )

    if atype == "AddStaticRoute":
        dst = str(action["destination"]).strip()
        mask = str(action["mask"]).strip()
        nh = str(action["next_hop"]).strip()
        try:
            ipaddress.IPv4Network(f"{dst}/{mask}", strict=False)
            ipaddress.IPv4Address(nh)
        except ValueError as e:
            return ActionResult(False, atype, dev, "路由参数非法", snap, error=str(e))
        route_cmd = f"ip route-static {dst} {mask} {nh}"
        new_lines = list(lines)
        # Insert right before trailing '#' or 'return' or 'ospf' to keep unparsed lines untouched
        insert_idx = len(new_lines)
        for i in range(len(new_lines) - 1, -1, -1):
            st = new_lines[i].strip()
            if st in ("#", "return") or st.startswith("ospf "):
                insert_idx = i
            else:
                break
        new_lines.insert(insert_idx, route_cmd)
        new_text = "\n".join(new_lines) + "\n"
        diff, cnt = _unified_diff(dev, old_text, new_text)
        return ActionResult(
            True,
            atype,
            dev,
            f"在 {dev}.cfg 新增静态路由 {dst}/{mask} → {nh}",
            snap.with_config(dev, new_text),
            diff=diff,
            changed_lines=cnt,
        )

    if atype == "InsertSecurityRule":
        before_rule = str(action["before_rule"]).strip()
        rname = str(action["rule_name"]).strip()
        sz = str(action["src_zone"]).strip()
        dz = str(action["dst_zone"]).strip()
        saddr = str(action.get("src_addr", "")).strip()
        daddr = str(action.get("dst_addr", "")).strip()
        svc = str(action.get("service", "")).strip()
        raction = str(action.get("action", "permit")).strip().lower()

        span = _find_security_rule_span(lines, before_rule)
        if not span:
            return ActionResult(False, atype, dev, "未找到插入锚点规则", snap, error=f"未在 {dev}.cfg 找到规则 {before_rule}")
        block = [f" rule name {rname}", f"  source-zone {sz}", f"  destination-zone {dz}"]
        if saddr and saddr.lower() != "any":
            block.append(f"  source-address {saddr}")
        if daddr and daddr.lower() != "any":
            block.append(f"  destination-address {daddr}")
        if svc and svc.lower() != "any":
            block.append(f"  service {svc}")
        block.append(f"  action {raction}")

        new_lines = list(lines)
        new_lines[span[0] : span[0]] = block
        new_text = "\n".join(new_lines) + "\n"
        diff, cnt = _unified_diff(dev, old_text, new_text)
        return ActionResult(
            True,
            atype,
            dev,
            f"在 {dev}.cfg 规则 {before_rule} 之前插入 {rname} ({raction.upper()})",
            snap.with_config(dev, new_text),
            diff=diff,
            changed_lines=cnt,
        )

    if atype == "ModifySecurityRuleAction":
        rname = str(action["rule_name"]).strip()
        new_act = str(action["new_action"]).strip().lower()
        if new_act not in ("permit", "deny"):
            return ActionResult(False, atype, dev, "非法动作", snap, error=f"不支持 action={new_act}")
        span = _find_security_rule_span(lines, rname)
        if not span:
            return ActionResult(False, atype, dev, "未找到目标规则", snap, error=f"未找到规则 {rname}")
        new_lines = list(lines)
        replaced = False
        for idx in range(span[0], span[1]):
            if re.match(r"^\s+action\s+(permit|deny)\s*$", new_lines[idx]):
                new_lines[idx] = f"  action {new_act}"
                replaced = True
                break
        if not replaced:
            new_lines.insert(span[1], f"  action {new_act}")
        new_text = "\n".join(new_lines) + "\n"
        diff, cnt = _unified_diff(dev, old_text, new_text)
        return ActionResult(
            True,
            atype,
            dev,
            f"将 {dev}.cfg 规则 {rname} 的动作改为 {new_act.upper()}",
            snap.with_config(dev, new_text),
            diff=diff,
            changed_lines=cnt,
        )

    if atype == "DeleteSecurityRule":
        rname = str(action["rule_name"]).strip()
        span = _find_security_rule_span(lines, rname)
        if not span:
            return ActionResult(False, atype, dev, "未找到目标规则", snap, error=f"未找到规则 {rname}")
        new_lines = list(lines)
        del new_lines[span[0] : span[1]]
        new_text = "\n".join(new_lines) + "\n"
        diff, cnt = _unified_diff(dev, old_text, new_text)
        return ActionResult(
            True,
            atype,
            dev,
            f"删除 {dev}.cfg 遮蔽/冗余规则 {rname} (L{span[0] + 1}-L{span[1]})",
            snap.with_config(dev, new_text),
            diff=diff,
            changed_lines=cnt,
        )

    if atype == "ModifyProtectedLineAttempt":
        line_no = int(action["line_number"])
        if _is_unparsed_line(snap, dev, line_no):
            return ActionResult(
                False,
                atype,
                dev,
                f"🛡 护栏硬拦截：禁止修改未解析行 {dev}.cfg:L{line_no}",
                snap,
                error=f"Action Precondition 拦截：{dev}.cfg:L{line_no} 被 vrp-ir 标记为 unparsed_lines（Protected Frame），动态本体禁止触碰未覆盖协议配置。",
                blocked_by_guardrail=True,
            )
        return ActionResult(False, atype, dev, "该行不是未解析行", snap, error="Target line is not in unparsed_lines")

    return ActionResult(False, atype, dev, f"未知 Action 类型: {atype}", snap, error=f"Unsupported action type: {atype}")


def execute_plan_in_sandbox(
    base_snap: NetworkSnapshot,
    actions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Run a multi-step Action sequence inside an isolated CoW snapshot branch."""
    cur = base_snap.fork()
    step_results: list[dict[str, Any]] = []
    total_changed = 0
    for act in actions:
        res = execute_action(cur, act)
        step_results.append(res.to_dict())
        if not res.ok:
            return {
                "ok": False,
                "blocked_by_guardrail": res.blocked_by_guardrail,
                "error": res.error,
                "steps": step_results,
                "final_snapshot": cur,
                "total_changed_lines": total_changed,
                "combined_diff": "",
            }
        cur = res.snapshot
        total_changed += res.changed_lines

    # Compute clean combined diff across all devices from base_snap -> cur
    diffs = []
    for dev in base_snap.configs:
        if base_snap.configs[dev] != cur.configs[dev]:
            d_str, _ = _unified_diff(dev, base_snap.configs[dev], cur.configs[dev])
            diffs.append(d_str)

    return {
        "ok": True,
        "blocked_by_guardrail": False,
        "error": None,
        "steps": step_results,
        "final_snapshot": cur,
        "total_changed_lines": total_changed,
        "combined_diff": "\n".join(diffs),
    }
