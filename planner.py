"""Diff-Guided Multi-Branch Sandbox Planner & 3 Killer Huawei Scenarios.

Demonstrates the core value of Executable Dynamic Network Ontology over
traditional Pure-LLM / Static-KG / Naive-ReAct approaches across 3 scenarios
on a 3-device Huawei topology (R1 — USG1 Firewall — R2):
  1. security_conflict : Security vs Connectivity conflict (blocks DB leak via Z3 diff!)
  2. coupled_3dev      : 3-device L3 routing + L4 firewall coupled multi-fault
  3. shadow_optimize   : Z3 shadowed-rule detection + minimal-cost optimization
"""
from __future__ import annotations

import time
from typing import Any

from actions import execute_plan_in_sandbox
from functions import compute_semantic_diff, detect_shadowed_rules, evaluate_flow
from ontology import NetworkSnapshot

# ---------------------------------------------------------------------------
# 3-Device Huawei VRP + USG Firewall Scenarios
# Topology:
#   Web/Untrust (10.1.0.10) -- [GE0/0/0] R1 [GE0/0/1 192.168.12.1/30]
#                           == [GE0/0/1 192.168.12.2/30] USG1 (untrust -> trust) [GE0/0/2 192.168.23.1/30]
#                           == [GE0/0/1 192.168.23.2/30] R2 [GE0/0/0 10.2.0.1/24]
#                           -- App-Server (10.2.0.10:443) & DB-Server (10.2.0.20:3306)
# ---------------------------------------------------------------------------

SCENARIOS: dict[str, dict[str, Any]] = {
    "security_conflict": {
        "id": "security_conflict",
        "name": "场景 1：安全与连通冲突（防修 A 坏 B）",
        "badge": "Z3 反例拦截",
        "summary": "打通 Web (10.1.0.10) → App (10.2.0.10:443)，但严禁放通 Untrust → DB (10.2.0.20:3306)，且严禁触碰 R1 末尾未解析的 OSPF 行。",
        "goal_text": "打通 Web (10.1.0.10) 访问 App-Server (10.2.0.10:443/TCP)，同时保证数据库隔离（Untrust 严禁访问 10.2.0.20:3306/TCP），且不得修改未解析的 OSPF 配置行。",
        "targets": [
            {
                "name": "Web → App-Server (HTTPS 443)",
                "src_ip": "10.1.0.10",
                "dst_ip": "10.2.0.10",
                "proto": "tcp",
                "dst_port": 443,
            }
        ],
        "invariants": [
            {
                "id": "inv_db_isolation",
                "kind": "must_deny_flow",
                "name": "安全不变量：严禁 Untrust 访问 DB (10.2.0.20:3306/TCP)",
                "src_zone": "untrust",
                "dst_zone": "trust",
                "src_cidr": "10.1.0.0/24",
                "dst_cidr": "10.2.0.20/32",
                "proto": "tcp",
                "dst_port": 3306,
            },
            {
                "id": "inv_unparsed",
                "kind": "unparsed_untouched",
                "name": "边界不变量：vrp-ir 未解析受保护行（OSPF）零修改",
            },
        ],
        "configs": {
            "R1": """!Software Version V800R012C10SPC300
sysname R1
#
interface GigabitEthernet0/0/0
 description TO-WEB-UNTRUST
 ip address 10.1.0.1 255.255.255.0
interface GigabitEthernet0/0/1
 description LINK-TO-USG1
 ip address 192.168.12.1 255.255.255.252
#
ip route-static 10.2.0.0 255.255.255.0 192.168.12.99
#
ospf 1 router-id 1.1.1.1
""",
            "USG1": """!Software Version V500R005C20SPC300
sysname USG1
#
interface GigabitEthernet0/0/1
 description LINK-TO-R1-UNTRUST
 ip address 192.168.12.2 255.255.255.252
interface GigabitEthernet0/0/2
 description LINK-TO-R2-TRUST
 ip address 192.168.23.1 255.255.255.252
#
ip route-static 10.1.0.0 255.255.255.0 192.168.12.1
ip route-static 10.2.0.0 255.255.255.0 192.168.23.2
#
firewall zone untrust
 set priority 5
 add interface GigabitEthernet0/0/1
firewall zone trust
 set priority 85
 add interface GigabitEthernet0/0/2
#
ip address-set app-servers type object
 address 0 10.2.0.10 mask 32
ip address-set db-servers type object
 address 0 10.2.0.20 mask 32
ip service-set mysql-3306 type object
 service 0 protocol tcp destination-port 3306
#
security-policy
 rule name deny-untrust-all
  source-zone untrust
  destination-zone trust
  source-address 10.1.0.0 mask 24
  destination-address 10.2.0.0 mask 24
  action deny
 rule name default-deny
  action deny
#
return
""",
            "R2": """!Software Version V800R012C10SPC300
sysname R2
#
interface GigabitEthernet0/0/1
 description LINK-TO-USG1
 ip address 192.168.23.2 255.255.255.252
interface GigabitEthernet0/0/0
 description TO-APP-AND-DB
 ip address 10.2.0.1 255.255.255.0
#
ip route-static 10.1.0.0 255.255.255.0 192.168.23.1
#
""",
        },
        "candidate_plans": [
            {
                "id": "branch_naive_permit",
                "title": "分支 A（传统偷懒方案：直接放宽防火墙规则）",
                "source_tag": "模拟纯 LLM / 裸 ReAct 常见失误",
                "rationale": "修复 R1.cfg:L11 下一跳，同时直接把 USG1 的 deny-untrust-all 改为 permit 以快速打通业务。",
                "actions": [
                    {"type": "FixStaticRouteNextHop", "device": "R1", "line_number": 11, "new_next_hop": "192.168.12.2"},
                    {"type": "ModifySecurityRuleAction", "device": "USG1", "rule_name": "deny-untrust-all", "new_action": "permit"},
                ],
            },
            {
                "id": "branch_unparsed_touch",
                "title": "分支 B（越界方案：试图改写未解析 OSPF 区块）",
                "source_tag": "验证 Partial Grounding 护栏",
                "rationale": "试图直接改动 R1.cfg:L13 的 ospf 进程行（vrp-ir 标记为 unparsed_lines）。",
                "actions": [
                    {"type": "ModifyProtectedLineAttempt", "device": "R1", "line_number": 13, "new_content": "# removed ospf"},
                ],
            },
            {
                "id": "branch_optimal_minimal",
                "title": "分支 C（动态本体最优规划：精准修路由 + 最小权限 HTTPS 放行）",
                "source_tag": "Diff-Guided Planner 推荐",
                "rationale": "精确修复 R1.cfg:L11 下一跳，并在 USG1 的 deny-untrust-all 之前插入仅放行 10.1.0.10 → address-set app-servers (https) 的最小权限规则。",
                "actions": [
                    {"type": "FixStaticRouteNextHop", "device": "R1", "line_number": 11, "new_next_hop": "192.168.12.2"},
                    {
                        "type": "InsertSecurityRule",
                        "device": "USG1",
                        "before_rule": "deny-untrust-all",
                        "rule_name": "allow-web-to-app",
                        "src_zone": "untrust",
                        "dst_zone": "trust",
                        "src_addr": "10.1.0.10 mask 32",
                        "dst_addr": "address-set app-servers",
                        "service": "https",
                        "action": "permit",
                    },
                ],
            },
        ],
    },
    "coupled_3dev": {
        "id": "coupled_3dev",
        "name": "场景 2：跨 3 设备 L3+L4 耦合故障",
        "badge": "多步联合规划",
        "summary": "同时存在 R1 下一跳错误 + USG1 策略拦截 + R2 缺少回程路由，单点修复均无法连通，需跨 3 台设备联合规划。",
        "goal_text": "排查并修复 R1 + USG1 + R2 三台设备的耦合故障，使 Web (10.1.0.10) 与 App-Server (10.2.0.10:443/TCP) 双向互通，且保持 DB (10.2.0.20:3306) 隔离。",
        "targets": [
            {
                "name": "Web → App-Server (HTTPS 443)",
                "src_ip": "10.1.0.10",
                "dst_ip": "10.2.0.10",
                "proto": "tcp",
                "dst_port": 443,
            }
        ],
        "invariants": [
            {
                "id": "inv_db_isolation",
                "kind": "must_deny_flow",
                "name": "安全不变量：严禁 Untrust 访问 DB (10.2.0.20:3306/TCP)",
                "src_zone": "untrust",
                "dst_zone": "trust",
                "src_cidr": "10.1.0.0/24",
                "dst_cidr": "10.2.0.20/32",
                "proto": "tcp",
                "dst_port": 3306,
            },
            {
                "id": "inv_unparsed",
                "kind": "unparsed_untouched",
                "name": "边界不变量：vrp-ir 未解析受保护行零修改",
            },
        ],
        "configs": {
            "R1": """!Software Version V800R012C10SPC300
sysname R1
#
interface GigabitEthernet0/0/0
 description TO-WEB-UNTRUST
 ip address 10.1.0.1 255.255.255.0
interface GigabitEthernet0/0/1
 description LINK-TO-USG1
 ip address 192.168.12.1 255.255.255.252
#
ip route-static 10.2.0.0 255.255.255.0 192.168.12.88
#
ospf 1 router-id 1.1.1.1
""",
            "USG1": """!Software Version V500R005C20SPC300
sysname USG1
#
interface GigabitEthernet0/0/1
 description LINK-TO-R1-UNTRUST
 ip address 192.168.12.2 255.255.255.252
interface GigabitEthernet0/0/2
 description LINK-TO-R2-TRUST
 ip address 192.168.23.1 255.255.255.252
#
ip route-static 10.1.0.0 255.255.255.0 192.168.12.1
ip route-static 10.2.0.0 255.255.255.0 192.168.23.2
#
firewall zone untrust
 set priority 5
 add interface GigabitEthernet0/0/1
firewall zone trust
 set priority 85
 add interface GigabitEthernet0/0/2
#
ip address-set app-servers type object
 address 0 10.2.0.10 mask 32
ip address-set db-servers type object
 address 0 10.2.0.20 mask 32
ip service-set mysql-3306 type object
 service 0 protocol tcp destination-port 3306
#
security-policy
 rule name protect-db
  source-zone untrust
  destination-zone trust
  destination-address address-set db-servers
  service mysql-3306
  action deny
 rule name default-deny
  action deny
#
return
""",
            "R2": """!Software Version V800R012C10SPC300
sysname R2
#
interface GigabitEthernet0/0/1
 description LINK-TO-USG1
 ip address 192.168.23.2 255.255.255.252
interface GigabitEthernet0/0/0
 description TO-APP-AND-DB
 ip address 10.2.0.1 255.255.255.0
#
""",
        },
        "candidate_plans": [
            {
                "id": "branch_l3_only",
                "title": "分支 A（局部修复：仅修 R1 + R2 路由，忽略防火墙）",
                "source_tag": "单层视角（未收敛）",
                "rationale": "只修复 L3 路由，没有同步处理 USG1 的 L4 安全策略。",
                "actions": [
                    {"type": "FixStaticRouteNextHop", "device": "R1", "line_number": 11, "new_next_hop": "192.168.12.2"},
                    {"type": "AddStaticRoute", "device": "R2", "destination": "10.1.0.0", "mask": "255.255.255.0", "next_hop": "192.168.23.1"},
                ],
            },
            {
                "id": "branch_fwd_only",
                "title": "分支 B（单向修复：修 R1 + USG1，遗漏 R2 回程路由）",
                "source_tag": "忽略双向对称性",
                "rationale": "只打通正向路径，遗漏了 R2 回程静态路由。",
                "actions": [
                    {"type": "FixStaticRouteNextHop", "device": "R1", "line_number": 11, "new_next_hop": "192.168.12.2"},
                    {
                        "type": "InsertSecurityRule",
                        "device": "USG1",
                        "before_rule": "default-deny",
                        "rule_name": "allow-web-to-app",
                        "src_zone": "untrust",
                        "dst_zone": "trust",
                        "src_addr": "10.1.0.10 mask 32",
                        "dst_addr": "address-set app-servers",
                        "service": "https",
                        "action": "permit",
                    },
                ],
            },
            {
                "id": "branch_joint_3dev",
                "title": "分支 C（跨 3 设备联合规划：R1 + USG1 + R2 三步精准闭环）",
                "source_tag": "Diff-Guided Planner 推荐",
                "rationale": "沿动态本体拓扑一次定位 3 处故障：修 R1 下一跳、在 USG1 插入最小权限 HTTPS 规则、为 R2 补齐回程路由。",
                "actions": [
                    {"type": "FixStaticRouteNextHop", "device": "R1", "line_number": 11, "new_next_hop": "192.168.12.2"},
                    {
                        "type": "InsertSecurityRule",
                        "device": "USG1",
                        "before_rule": "default-deny",
                        "rule_name": "allow-web-to-app",
                        "src_zone": "untrust",
                        "dst_zone": "trust",
                        "src_addr": "10.1.0.10 mask 32",
                        "dst_addr": "address-set app-servers",
                        "service": "https",
                        "action": "permit",
                    },
                    {"type": "AddStaticRoute", "device": "R2", "destination": "10.1.0.0", "mask": "255.255.255.0", "next_hop": "192.168.23.1"},
                ],
            },
        ],
    },
    "shadow_optimize": {
        "id": "shadow_optimize",
        "name": "场景 3：策略遮蔽检测与最小代价优化",
        "badge": "Z3 遮蔽 + 最优规划",
        "summary": "USG1 历史宽泛规则 legacy-block-web 完全遮蔽了下方的 allow-web-to-app；对比“顶部重复加规则”与“清理遮蔽规则”的最优代价规划。",
        "goal_text": "恢复 Web (10.1.0.10) 到 App-Server (10.2.0.10:443/TCP) 互通，确保 DB (10.2.0.20:3306) 仍被拦截，并消除防火墙策略遮蔽（最小化配置冗余）。",
        "targets": [
            {
                "name": "Web → App-Server (HTTPS 443)",
                "src_ip": "10.1.0.10",
                "dst_ip": "10.2.0.10",
                "proto": "tcp",
                "dst_port": 443,
            }
        ],
        "invariants": [
            {
                "id": "inv_db_isolation",
                "kind": "must_deny_flow",
                "name": "安全不变量：严禁 Untrust 访问 DB (10.2.0.20:3306/TCP)",
                "src_zone": "untrust",
                "dst_zone": "trust",
                "src_cidr": "10.1.0.0/24",
                "dst_cidr": "10.2.0.20/32",
                "proto": "tcp",
                "dst_port": 3306,
            },
            {
                "id": "inv_unparsed",
                "kind": "unparsed_untouched",
                "name": "边界不变量：vrp-ir 未解析受保护行零修改",
            },
        ],
        "configs": {
            "R1": """!Software Version V800R012C10SPC300
sysname R1
#
interface GigabitEthernet0/0/0
 description TO-WEB-UNTRUST
 ip address 10.1.0.1 255.255.255.0
interface GigabitEthernet0/0/1
 description LINK-TO-USG1
 ip address 192.168.12.1 255.255.255.252
#
ip route-static 10.2.0.0 255.255.255.0 192.168.12.2
#
ospf 1 router-id 1.1.1.1
""",
            "USG1": """!Software Version V500R005C20SPC300
sysname USG1
#
interface GigabitEthernet0/0/1
 description LINK-TO-R1-UNTRUST
 ip address 192.168.12.2 255.255.255.252
interface GigabitEthernet0/0/2
 description LINK-TO-R2-TRUST
 ip address 192.168.23.1 255.255.255.252
#
ip route-static 10.1.0.0 255.255.255.0 192.168.12.1
ip route-static 10.2.0.0 255.255.255.0 192.168.23.2
#
firewall zone untrust
 set priority 5
 add interface GigabitEthernet0/0/1
firewall zone trust
 set priority 85
 add interface GigabitEthernet0/0/2
#
ip address-set app-servers type object
 address 0 10.2.0.10 mask 32
ip address-set db-servers type object
 address 0 10.2.0.20 mask 32
ip service-set mysql-3306 type object
 service 0 protocol tcp destination-port 3306
#
security-policy
 rule name legacy-block-web
  source-zone untrust
  destination-zone trust
  source-address 10.1.0.0 mask 24
  destination-address 10.2.0.0 mask 24
  action deny
 rule name allow-web-to-app
  source-zone untrust
  destination-zone trust
  source-address 10.1.0.10 mask 32
  destination-address address-set app-servers
  service https
  action permit
 rule name protect-db
  source-zone untrust
  destination-zone trust
  destination-address address-set db-servers
  service mysql-3306
  action deny
 rule name default-deny
  action deny
#
return
""",
            "R2": """!Software Version V800R012C10SPC300
sysname R2
#
interface GigabitEthernet0/0/1
 description LINK-TO-USG1
 ip address 192.168.23.2 255.255.255.252
interface GigabitEthernet0/0/0
 description TO-APP-AND-DB
 ip address 10.2.0.1 255.255.255.0
#
ip route-static 10.1.0.0 255.255.255.0 192.168.23.1
#
""",
        },
        "candidate_plans": [
            {
                "id": "branch_top_duplicate",
                "title": "分支 A（传统打补丁：顶部追加重复规则）",
                "source_tag": "可行但次优（遗留死规则）",
                "rationale": "不分析历史规则遮蔽，直接在策略最顶部再插一条重复的 allow-web-https-v2。",
                "actions": [
                    {
                        "type": "InsertSecurityRule",
                        "device": "USG1",
                        "before_rule": "legacy-block-web",
                        "rule_name": "allow-web-https-v2",
                        "src_zone": "untrust",
                        "dst_zone": "trust",
                        "src_addr": "10.1.0.10 mask 32",
                        "dst_addr": "address-set app-servers",
                        "service": "https",
                        "action": "permit",
                    }
                ],
            },
            {
                "id": "branch_delete_blocker",
                "title": "分支 B（动态本体最优规划：删除遮蔽旧规则，激活原合法规则）",
                "source_tag": "Z3 遮蔽分析 + 代价最优",
                "rationale": "Z3 检出 legacy-block-web 完全遮蔽了 allow-web-to-app；删除该阻塞旧规则后，原有 allow-web-to-app 自动生效，且 Z3 严格证明下方 protect-db + default-deny 仍 100% 保护数据库。",
                "actions": [
                    {"type": "DeleteSecurityRule", "device": "USG1", "rule_name": "legacy-block-web"},
                ],
            },
        ],
    },
}


def evaluate_candidate_branch(
    base_snap: NetworkSnapshot,
    scenario: dict[str, Any],
    plan: dict[str, Any],
) -> dict[str, Any]:
    """Run one candidate branch in CoW sandbox and compute full semantic diff + planning score."""
    t0 = time.time()
    exec_res = execute_plan_in_sandbox(base_snap, plan["actions"])
    if not exec_res["ok"]:
        return {
            "id": plan["id"],
            "title": plan["title"],
            "source_tag": plan.get("source_tag", "Candidate"),
            "rationale": plan.get("rationale", ""),
            "actions": plan["actions"],
            "steps": exec_res["steps"],
            "verdict": "BLOCKED_PRECONDITION" if exec_res["blocked_by_guardrail"] else "INVALID",
            "verdict_label": "🛡 前置护栏硬拦截（unparsed_lines 保护）" if exec_res["blocked_by_guardrail"] else "⛔ 动作执行失败",
            "error": exec_res["error"],
            "score": -999,
            "changed_lines": 0,
            "diff": "",
            "semantic_diff": None,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "final_configs": None,
        }

    after_snap = exec_res["final_snapshot"]
    sdiff = compute_semantic_diff(base_snap, after_snap, scenario["targets"], scenario["invariants"])

    # Deterministic multi-objective planning score:
    #   +100 if all targets satisfied
    #   -500 if ANY invariant violated (hard prune)
    #   -15 per shadowed dead rule remaining
    #   -2 per changed config line (minimal diff preference)
    shadow_after = sdiff["shadowed_diff"]["after_count"]
    changed = exec_res["total_changed_lines"]

    if not sdiff["all_invariants_ok"]:
        verdict = "PRUNED_INVARIANT"
        verdict_label = "❌ Z3 差分拦截回滚（违背安全不变量）"
        score = -500 - changed
    elif not sdiff["all_targets_ok"]:
        verdict = "PRUNED_INCOMPLETE"
        verdict_label = "⚠️ 目标未达成（剪枝）"
        score = -100 - changed
    else:
        verdict = "FEASIBLE"
        verdict_label = "✅ 零副作用可行方案"
        score = 100 - (shadow_after * 15) - (changed * 2)

    return {
        "id": plan["id"],
        "title": plan["title"],
        "source_tag": plan.get("source_tag", "Candidate"),
        "rationale": plan.get("rationale", ""),
        "actions": plan["actions"],
        "steps": exec_res["steps"],
        "verdict": verdict,
        "verdict_label": verdict_label,
        "error": None,
        "score": score,
        "changed_lines": changed,
        "diff": exec_res["combined_diff"],
        "semantic_diff": sdiff,
        "elapsed_ms": int((time.time() - t0) * 1000),
        "final_configs": after_snap.configs,
    }


def run_diff_guided_planner(base_snap: NetworkSnapshot, scenario: dict[str, Any]) -> dict[str, Any]:
    """Explore all candidate branches in isolated CoW sandboxes and select optimal plan."""
    t0 = time.time()
    branches = [evaluate_candidate_branch(base_snap, scenario, p) for p in scenario["candidate_plans"]]

    feasible = [b for b in branches if b["verdict"] == "FEASIBLE"]
    best = max(feasible, key=lambda x: x["score"]) if feasible else None

    for b in branches:
        if best and b["id"] == best["id"]:
            b["selected"] = True
            b["verdict"] = "OPTIMAL_SELECTED"
            b["verdict_label"] = "🏆 最优方案（零副作用 + 最低代价）"
        else:
            b["selected"] = False
            if b["verdict"] == "FEASIBLE":
                b["verdict_label"] = "🟡 可行但次优（存在死规则/更高改动代价）"

    return {
        "scenario_id": scenario["id"],
        "elapsed_ms": int((time.time() - t0) * 1000),
        "branch_count": len(branches),
        "pruned_count": sum(1 for b in branches if not b["selected"] and b["verdict"] != "FEASIBLE"),
        "selected_branch_id": best["id"] if best else None,
        "branches": branches,
    }


def run_ablation_benchmark() -> dict[str, Any]:
    """Run live comparison across all 3 scenarios: Naive vs Single-Check vs Dynamic Ontology."""
    rows = []
    for sc in SCENARIOS.values():
        snap = NetworkSnapshot(configs=dict(sc["configs"]))
        plan_res = run_diff_guided_planner(snap, sc)
        branches = plan_res["branches"]

        # Branch 0 represents Naive/Traditional strategy in each scenario; Best represents Ours
        naive_b = branches[0]
        ours_b = next((b for b in branches if b["selected"]), branches[-1])

        naive_sd = naive_b["semantic_diff"]
        ours_sd = ours_b["semantic_diff"]

        rows.append(
            {
                "scenario_id": sc["id"],
                "scenario_name": sc["name"],
                "naive": {
                    "target_ok": bool(naive_sd and naive_sd["all_targets_ok"]),
                    "invariant_ok": bool(naive_sd and naive_sd["all_invariants_ok"]),
                    "shadowed_after": naive_sd["shadowed_diff"]["after_count"] if naive_sd else None,
                    "changed_lines": naive_b["changed_lines"],
                    "note": naive_b["verdict_label"],
                },
                "ours": {
                    "target_ok": bool(ours_sd and ours_sd["all_targets_ok"]),
                    "invariant_ok": bool(ours_sd and ours_sd["all_invariants_ok"]),
                    "shadowed_after": ours_sd["shadowed_diff"]["after_count"] if ours_sd else 0,
                    "changed_lines": ours_b["changed_lines"],
                    "elapsed_ms": plan_res["elapsed_ms"],
                    "note": ours_b["verdict_label"],
                },
            }
        )

    n = len(rows)
    return {
        "scenarios": rows,
        "summary": {
            "naive_target_rate": f"{sum(1 for r in rows if r['naive']['target_ok'])}/{n}",
            "naive_zero_regression_rate": f"{sum(1 for r in rows if r['naive']['target_ok'] and r['naive']['invariant_ok'])}/{n}",
            "naive_zero_shadow_rate": f"{sum(1 for r in rows if r['naive']['target_ok'] and r['naive']['invariant_ok'] and r['naive']['shadowed_after'] == 0)}/{n}",
            "ours_target_rate": f"{sum(1 for r in rows if r['ours']['target_ok'])}/{n}",
            "ours_zero_regression_rate": f"{sum(1 for r in rows if r['ours']['target_ok'] and r['ours']['invariant_ok'])}/{n}",
            "ours_zero_shadow_rate": f"{sum(1 for r in rows if r['ours']['target_ok'] and r['ours']['invariant_ok'] and r['ours']['shadowed_after'] == 0)}/{n}",
        },
    }
