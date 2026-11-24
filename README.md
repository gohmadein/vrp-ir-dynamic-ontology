# vrp-ir Dynamic Network Ontology Prototype · 华为可执行动态网络本体原型

面向华为 VRP 路由器与 USG 防火墙的 **可执行动态网络本体（Executable Dynamic Network Ontology）** 可行性验证原型，形式化定义为六元组：

$$\mathcal{O}_{\text{dyn}} = \langle \mathcal{C},\ \mathcal{R},\ \mathcal{F},\ \mathcal{A},\ \mathcal{I},\ \Delta \rangle$$

核心目标：将真实 [**vrp-ir**](https://github.com/zynovexllc/vrp-ir) 解析器构建为语义层，将连通性与策略遮蔽验证封装为可执行计算函数（**LPM + Z3 SMT**），将配置修改封装为带前置护栏的结构化 **Action**，并通过 **Copy-on-Write 沙箱 + 形式化语义差分（$\Delta$）** 实现反例剪枝与最优规划。

## ✨ 核心能力

1. **语义层（`ontology.py` · $\mathcal{C}, \mathcal{R}$ + CoW 沙箱）**
   - 直接调用真实 `vrp_ir.parse_text()` 解析 3 设备（`R1` 路由器 — `USG1` 防火墙 — `R2` 路由器）配置；
   - 将字符串外键解引用为跨设备语义边（`L3_LINK`、`IN_ZONE`、`SRC_ZONE`、`DST_ZONE`、`USES_ADDR_SET`、`USES_SVC_SET`、`ROUTES_TO`）；
   - 将 `vrp-ir` 识别的 `unparsed_lines` 显式建模为受保护帧（`ProtectedUnparsed`），并支持零磁盘副作用的内存快照分叉 `fork()`。
2. **可执行计算函数与形式化差分引擎（`functions.py` · $\mathcal{F}, \mathcal{I}, \Delta$）**
   - `evaluate_flow()`：多跳 L3 最长前缀匹配（LPM）+ USG 防火墙安全域与首匹配策略追踪；
   - `detect_shadowed_rules()`：基于 **Z3 SMT** 严格证明被前置规则完全遮蔽的不可达死规则；
   - `compute_semantic_diff()`：基于 **Z3 策略差分 + 原子网段切分（Prefix Equivalence Classes）** 计算变更前后的新增放通/阻断反例、L3 路由可达性变化、以及安全不变量的形式化验证（`Z3 UNSAT` 证明安全 / `Z3 SAT` 给出精确反例包与 `SourceRef` 行号）。
3. **结构化语义动作与护栏（`actions.py` · $\mathcal{A}$）**
   - 封装 `FixStaticRouteNextHop`、`AddStaticRoute`、`InsertSecurityRule`、`ModifySecurityRuleAction`、`DeleteSecurityRule`；
   - 前置条件硬性拦截对 `unparsed_lines`（如未解析 OSPF 区块）的任何修改，并将语义动作下推编译（Lowering）为最小化华为 VRP Diff。
4. **差分引导多分支规划与实时消融对比（`planner.py` + `server.py`）**
   - 内置 3 个典型华为对比场景（安全与连通冲突、跨 3 设备 L3+L4 耦合故障、策略遮蔽检测与最小代价优化）；
   - 核心规划与 Z3 差分完全本地毫秒级运行（**无需 API Key**）；同时预留可选 **BYOK LLM 提案口**，可将任意 OpenAI 兼容模型生成的候选 Action 送入 Z3 沙箱验真。

## 📊 3 场景实测对比结果（真实 `vrp-ir` + `Z3`）

| 指标 | 传统方案（无差分 / 单层修复 / 顶部补丁） | 可执行动态本体（Sandbox + Z3 差分规划） |
|---|---|---|
| 目标连通率 | 2/3 | **3/3** |
| 零副作用率（目标达成且零安全回归） | 1/3 | **3/3** |
| 最优无死规则率（零回归且零策略遮蔽） | 0/3 | **3/3** |

## 🚀 快速启动

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 18894
```

打开浏览器访问 `http://127.0.0.1:18894/`：
- 切换顶部 3 个场景，点击 **「🧠 运行动态本体沙箱规划」** 体验 Z3 反例拦截、未解析行护栏与最优方案择优；
- 切换 **「🕸 动态本体语义图 (C, R)」** 查看跨设备实体与解引用关系；
- 点击右上角 **「📊 传统 vs 动态本体评测」** 实时运行全场景对比。

## 📁 项目结构

```text
.
├── ontology.py         # 语义层 (C, R)：vrp-ir 跨设备语义图构建 + Copy-on-Write 快照沙箱
├── functions.py        # 计算函数 (F) 与差分引擎 (Δ)：L3/L4 追踪 + Z3 策略遮蔽 + Z3/原子网段差分
├── actions.py          # 结构化动作 (A)：前置护栏（保护 unparsed_lines）+ 华为 VRP Diff 下推编译
├── planner.py          # 差分引导多分支规划器 + 3 个华为场景 + 实时消融评测
├── server.py           # FastAPI 后端与可选 BYOK LLM 提案接口
├── static/             # 交互式动态本体工作台前端
├── requirements.txt
└── .gitignore
```
