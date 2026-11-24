"""FastAPI Server for Huawei Executable Dynamic Network Ontology Workbench (Port 18894).

Provides:
- Real-time vrp-ir parsing & Dynamic Ontology Graph (C, R)
- Executable Computed Functions (F): multi-hop L3+L4 flow evaluation & Z3 shadowed-rule proofs
- Structured Semantic Actions (A) with Copy-on-Write sandbox & unparsed_lines guardrails
- Formal Z3 + Atomic-Prefix Differential Analysis (Δ) & Diff-Guided Multi-Branch Planner
- Live Ablation Benchmark comparing Traditional vs Executable Dynamic Ontology
- Optional BYOK LLM Action Proposer: feed any LLM proposal into the Z3 Diff Sandbox!
"""
from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from functions import (
    check_security_invariant_z3,
    detect_shadowed_rules,
    evaluate_flow,
)
from ontology import NetworkSnapshot
from planner import (
    SCENARIOS,
    evaluate_candidate_branch,
    run_ablation_benchmark,
    run_diff_guided_planner,
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
WORKSPACE_DIR = BASE_DIR / "workspace"
WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)


class AppState:
    def __init__(self) -> None:
        self.scenario_id: str = "security_conflict"
        self.snapshot: NetworkSnapshot = NetworkSnapshot(configs={})
        self.last_plan: dict[str, Any] | None = None
        self.committed_branch_id: str | None = None
        self.load_scenario("security_conflict")

    def load_scenario(self, scenario_id: str) -> None:
        sc = SCENARIOS[scenario_id]
        self.scenario_id = scenario_id
        self.snapshot = NetworkSnapshot(configs=dict(sc["configs"]))
        self.last_plan = None
        self.committed_branch_id = None
        self._sync_disk()

    def commit_configs(self, configs: dict[str, str], branch_id: str | None = None) -> None:
        self.snapshot = NetworkSnapshot(configs=dict(configs))
        self.committed_branch_id = branch_id
        self._sync_disk()

    def _sync_disk(self) -> None:
        for dev, txt in self.snapshot.configs.items():
            (WORKSPACE_DIR / f"{dev}.cfg").write_text(txt, encoding="utf-8")


STATE = AppState()


def build_ui_state() -> dict[str, Any]:
    sc = SCENARIOS[STATE.scenario_id]
    snap = STATE.snapshot

    target_checks = [
        {
            "name": t["name"],
            **evaluate_flow(snap, t["src_ip"], t["dst_ip"], t.get("proto", "tcp"), int(t["dst_port"])),
        }
        for t in sc["targets"]
    ]

    # Also evaluate DB probe concretely so topology/UI can display live status
    db_probe = evaluate_flow(snap, "10.1.0.10", "10.2.0.20", "tcp", 3306)

    inv_checks = []
    for inv in sc["invariants"]:
        if inv["kind"] == "unparsed_untouched":
            # Compare against initial scenario unparsed lines
            init_snap = NetworkSnapshot(configs=dict(sc["configs"]))
            violated = []
            for dev in init_snap.configs:
                b_lines = init_snap.configs[dev].splitlines()
                a_lines = snap.configs[dev].splitlines()
                for u in init_snap.ir(dev).get("unparsed_lines") or []:
                    ln = u.get("line")
                    raw = b_lines[ln - 1] if ln and 1 <= ln <= len(b_lines) else ""
                    if raw and raw not in a_lines:
                        violated.append(f"{dev}.cfg:L{ln}")
            inv_checks.append(
                {
                    "id": inv["id"],
                    "name": inv["name"],
                    "ok": len(violated) == 0,
                    "proof": "vrp-ir 未解析受保护行 100% 完好" if not violated else f"被破坏: {', '.join(violated)}",
                    "counterexample": None if not violated else {"violated": violated},
                }
            )
        else:
            inv_checks.append(check_security_invariant_z3(snap, inv, fw_device="USG1"))

    shadowed = detect_shadowed_rules(snap, "USG1")

    return {
        "active_scenario": STATE.scenario_id,
        "committed_branch_id": STATE.committed_branch_id,
        "scenario": {
            "id": sc["id"],
            "name": sc["name"],
            "badge": sc["badge"],
            "summary": sc["summary"],
            "goal_text": sc["goal_text"],
        },
        "scenarios": [
            {"id": s["id"], "name": s["name"], "badge": s["badge"], "summary": s["summary"]}
            for s in SCENARIOS.values()
        ],
        "configs": snap.configs,
        "ir": snap.all_ir(),
        "ontology_graph": snap.ontology_graph(),
        "functions": {
            "targets": target_checks,
            "db_probe": db_probe,
            "invariants": inv_checks,
            "shadowed_rules": shadowed,
        },
        "last_plan": _strip_plan_configs(STATE.last_plan) if STATE.last_plan else None,
    }


def _strip_plan_configs(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        **plan,
        "branches": [{k: v for k, v in b.items() if k != "final_configs"} for b in plan["branches"]],
    }


app = FastAPI(title="Huawei Executable Dynamic Network Ontology Workbench")


class CustomActionReq(BaseModel):
    title: str = "自定义沙箱实验分支"
    actions: list[dict[str, Any]] = Field(default_factory=list)


class LlmProposeReq(BaseModel):
    instruction: str
    base_url: str = "https://api.deepseek.com/v1"
    model: str = "deepseek-chat"


@app.get("/api/state")
def api_state():
    return build_ui_state()


@app.post("/api/scenario/{scenario_id}")
def api_load_scenario(scenario_id: str):
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown scenario")
    STATE.load_scenario(scenario_id)
    return build_ui_state()


@app.post("/api/plan/run")
def api_run_plan():
    sc = SCENARIOS[STATE.scenario_id]
    # Always run sandbox planning from clean scenario base (or current state if uncommitted)
    base_snap = NetworkSnapshot(configs=dict(sc["configs"]))
    STATE.snapshot = base_snap
    STATE.committed_branch_id = None
    STATE._sync_disk()
    STATE.last_plan = run_diff_guided_planner(base_snap, sc)
    return build_ui_state()


@app.post("/api/plan/commit/{branch_id}")
def api_commit_branch(branch_id: str):
    if not STATE.last_plan:
        raise HTTPException(status_code=400, detail="请先运行动态本体沙箱规划")
    branch = next((b for b in STATE.last_plan["branches"] if b["id"] == branch_id), None)
    if not branch:
        raise HTTPException(status_code=404, detail="Branch not found")
    if not branch.get("final_configs"):
        raise HTTPException(status_code=400, detail="该分支被前置护栏拦截，无法提交")
    STATE.commit_configs(branch["final_configs"], branch_id=branch_id)
    return build_ui_state()


@app.post("/api/sandbox/evaluate")
def api_sandbox_evaluate(req: CustomActionReq):
    sc = SCENARIOS[STATE.scenario_id]
    plan_obj = {
        "id": f"custom_{int(asyncio.get_event_loop().time()) if False else 1}",
        "title": req.title,
        "source_tag": "沙箱即时推演",
        "rationale": "用户/LLM 提交的自定义结构化 Action 序列，在内存沙箱中经 Z3 差分评估。",
        "actions": req.actions,
    }
    res = evaluate_candidate_branch(STATE.snapshot, sc, plan_obj)
    if STATE.last_plan is None:
        STATE.last_plan = {
            "scenario_id": sc["id"],
            "elapsed_ms": res["elapsed_ms"],
            "branch_count": 1,
            "pruned_count": 0 if res["verdict"] == "FEASIBLE" else 1,
            "selected_branch_id": None,
            "branches": [res],
        }
    else:
        STATE.last_plan["branches"].append(res)
        STATE.last_plan["branch_count"] = len(STATE.last_plan["branches"])
    return {
        "branch": {k: v for k, v in res.items() if k != "final_configs"},
        "state": build_ui_state(),
    }


@app.get("/api/benchmark")
def api_benchmark():
    return run_ablation_benchmark()


def _call_llm_json(api_key: str, base_url: str, model: str, prompt: str) -> dict[str, Any]:
    raw_url = (base_url or "https://api.deepseek.com/v1").strip().rstrip("/")
    parsed = urllib.parse.urlparse(raw_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Base URL 必须以 http:// 或 https:// 开头")
    endpoint = raw_url if raw_url.endswith("/chat/completions") else f"{raw_url}/chat/completions"

    payload = {
        "model": model,
        "temperature": 0.1,
        "messages": [
            {
                "role": "system",
                "content": (
                    "你是一个华为网络规划提案生成器。请严格只输出一个 JSON 对象（不要 markdown 代码块），"
                    "格式为 {\"title\": \"简短方案名\", \"rationale\": \"提案理由\", \"actions\": [...] }。\n"
                    "支持的 Action Schema：\n"
                    "1. {\"type\":\"FixStaticRouteNextHop\",\"device\":\"R1|R2|USG1\",\"line_number\":11,\"new_next_hop\":\"192.168.12.2\"}\n"
                    "2. {\"type\":\"AddStaticRoute\",\"device\":\"R1|R2|USG1\",\"destination\":\"10.1.0.0\",\"mask\":\"255.255.255.0\",\"next_hop\":\"192.168.23.1\"}\n"
                    "3. {\"type\":\"InsertSecurityRule\",\"device\":\"USG1\",\"before_rule\":\"deny-untrust-all\",\"rule_name\":\"allow-web-to-app\",\"src_zone\":\"untrust\",\"dst_zone\":\"trust\",\"src_addr\":\"10.1.0.10 mask 32\",\"dst_addr\":\"address-set app-servers\",\"service\":\"https\",\"action\":\"permit\"}\n"
                    "4. {\"type\":\"ModifySecurityRuleAction\",\"device\":\"USG1\",\"rule_name\":\"deny-untrust-all\",\"new_action\":\"permit|deny\"}\n"
                    "5. {\"type\":\"DeleteSecurityRule\",\"device\":\"USG1\",\"rule_name\":\"legacy-block-web\"}\n"
                ),
            },
            {"role": "user", "content": prompt},
        ],
    }
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"LLM API HTTP {e.code}: {e.read().decode('utf-8', errors='replace')[:300]}") from e

    content = (((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
    if content.startswith("```"):
        content = content.strip("`").split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    return json.loads(content)


@app.post("/api/llm/propose")
async def api_llm_propose(
    req: LlmProposeReq,
    x_llm_api_key: str | None = Header(default=None, alias="X-LLM-API-Key"),
):
    api_key = (x_llm_api_key or "").strip()
    if not api_key:
        raise HTTPException(status_code=400, detail="请先点击右上角填写你自己的 API Key（BYOK），或直接使用免 Key 的「运行动态本体沙箱规划」。")

    sc = SCENARIOS[STATE.scenario_id]
    snap = STATE.snapshot
    ctx = (
        f"当前场景：{sc['name']}\n目标：{sc['goal_text']}\n用户指令：{req.instruction}\n\n"
        f"当前配置（带行号）：\n"
        + "\n\n".join(
            f"=== {dev}.cfg ===\n"
            + "\n".join(f"L{i + 1}: {ln}" for i, ln in enumerate(txt.splitlines()))
            for dev, txt in snap.configs.items()
        )
    )
    try:
        proposal = await asyncio.to_thread(_call_llm_json, api_key, req.base_url, req.model, ctx)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM 提案生成失败: {e}")

    branch_id = f"llm_{abs(hash(req.instruction)) % 100000}"
    plan_obj = {
        "id": branch_id,
        "title": f"🤖 LLM 实时提案：{proposal.get('title', '自定义方案')}",
        "source_tag": f"BYOK LLM ({req.model}) → Z3 沙箱校验",
        "rationale": proposal.get("rationale", ""),
        "actions": proposal.get("actions") or [],
    }
    res = evaluate_candidate_branch(snap, sc, plan_obj)
    res["selected"] = False
    if STATE.last_plan is None:
        STATE.last_plan = {
            "scenario_id": sc["id"],
            "elapsed_ms": res["elapsed_ms"],
            "branch_count": 1,
            "pruned_count": 0 if res["verdict"] == "FEASIBLE" else 1,
            "selected_branch_id": None,
            "branches": [res],
        }
    else:
        STATE.last_plan["branches"].insert(0, res)
        STATE.last_plan["branch_count"] = len(STATE.last_plan["branches"])

    return {
        "branch": {k: v for k, v in res.items() if k != "final_configs"},
        "state": build_ui_state(),
    }


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))
