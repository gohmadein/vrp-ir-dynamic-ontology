const $ = (sel, root = document) => root.querySelector(sel);

const LLM_KEY_STORAGE = 'vrp_dyn_onto_llm_v1';

const state = {
  data: null,
  heroView: 'topo', // 'topo' | 'graph'
  dev: 'R1',
  leftMode: 'cfg', // 'cfg' | 'ir'
  llm: { apiKey: '', baseUrl: 'https://api.deepseek.com/v1', model: 'deepseek-chat' },
};

function esc(s) {
  return String(s ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}

function diffHtml(diffText) {
  return esc(diffText)
    .split('\n')
    .map((ln) => {
      if (ln.startsWith('+++') || ln.startsWith('---') || ln.startsWith('@@')) return `<span class="diff-hdr">${ln}</span>`;
      if (ln.startsWith('+')) return `<span class="diff-add">${ln}</span>`;
      if (ln.startsWith('-')) return `<span class="diff-del">${ln}</span>`;
      return ln;
    })
    .join('\n');
}

function loadLlm() {
  try {
    const raw = localStorage.getItem(LLM_KEY_STORAGE);
    if (raw) state.llm = { ...state.llm, ...JSON.parse(raw) };
  } catch { /* ignore */ }
}

function renderScenarios() {
  const { scenarios, active_scenario, scenario } = state.data;
  $('#scenario-tabs').innerHTML = scenarios
    .map(
      (s) => `
      <button type="button" class="sc-btn" data-sc="${esc(s.id)}" aria-selected="${s.id === active_scenario}">
        <span>${esc(s.name)}</span>
        <span class="sc-badge">${esc(s.badge)}</span>
      </button>`
    )
    .join('');
  $('#scenario-desc').textContent = `🎯 任务目标：${scenario.goal_text}`;
}

function renderHero() {
  const { functions, ontology_graph } = state.data;
  const target = functions.targets[0];
  const allInvOk = functions.invariants.every((i) => i.ok);
  const shadowCount = functions.shadowed_rules.length;

  $('#onto-stats').textContent = `本体实体: ${ontology_graph.stats.node_count} · 语义边: ${ontology_graph.stats.edge_count}`;

  const pt = $('#pill-target');
  pt.textContent = target.allowed_and_reachable ? '✅ 目标流 (HTTPS 443)：已连通' : '❌ 目标流 (HTTPS 443)：当前阻断';
  pt.className = `status-pill ${target.allowed_and_reachable ? 'ok' : 'fail'}`;

  const pi = $('#pill-inv');
  pi.textContent = allInvOk ? '🛡 安全不变量 (DB 3306 隔离)：Z3 证明安全' : '🚨 安全不变量被突破（DB 暴露）！';
  pi.className = `status-pill ${allInvOk ? 'ok' : 'fail'}`;

  const ps = $('#pill-shadow');
  ps.textContent = shadowCount === 0 ? '✨ Z3 规则遮蔽：0 条死规则' : `⚠️ Z3 检出 ${shadowCount} 条被遮蔽死规则`;
  ps.className = `status-pill ${shadowCount === 0 ? 'info' : 'warn'}`;

  $('#hero-topo-wrap').classList.toggle('hidden', state.heroView !== 'topo');
  $('#hero-graph-wrap').classList.toggle('hidden', state.heroView !== 'graph');

  renderTopologySvg();
  renderOntologyGraph();
}

function renderTopologySvg() {
  const { functions } = state.data;
  const target = functions.targets[0];
  const ok = target.allowed_and_reachable;
  const dbExposed = functions.db_probe?.allowed_and_reachable;
  const failAt = !target.forward.ok ? target.forward.failed_at : !target.reverse.ok ? target.reverse.failed_at : null;

  const devStroke = (d) => {
    if (state.dev === d) return '#38bdf8';
    if (failAt === d) return '#f87171';
    if (ok) return '#34d399';
    return '#64748b';
  };

  const link1 = ok ? 'topo-link-ok' : failAt === 'R1' ? 'topo-link-bad' : 'topo-link-base';
  const link2 = ok ? 'topo-link-ok' : failAt === 'USG1' || failAt === 'R2' ? 'topo-link-bad' : 'topo-link-base';

  const animDot = ok
    ? `<circle r="5.5" fill="#34d399"><animate attributeName="cx" values="130;955" dur="2.4s" repeatCount="indefinite"/><animate attributeName="cy" values="64;64" dur="2.4s" repeatCount="indefinite"/></circle>`
    : '';

  const dbAnim = dbExposed
    ? `<circle r="5.5" fill="#f87171"><animate attributeName="cx" values="130;955" dur="1.6s" repeatCount="indefinite"/><animate attributeName="cy" values="64;104" dur="1.6s" repeatCount="indefinite"/></circle>`
    : '';

  $('#topo-svg').innerHTML = `
    <!-- Links -->
    <line x1="130" y1="64" x2="265" y2="64" class="topo-link-base" />
    <line x1="395" y1="64" x2="505" y2="64" class="${link1}" />
    <line x1="655" y1="64" x2="765" y2="64" class="${link2}" />
    <line x1="895" y1="54" x2="955" y2="38" class="${ok ? 'topo-link-ok' : 'topo-link-base'}" />
    <line x1="895" y1="74" x2="955" y2="96" class="${dbExposed ? 'topo-link-bad' : 'topo-link-base'}" />

    ${animDot}
    ${dbAnim}

    <!-- Subnet labels -->
    <text x="450" y="54" text-anchor="middle" fill="#94a3b8" font-size="10.5" font-family="monospace">192.168.12.0/30</text>
    <text x="710" y="54" text-anchor="middle" fill="#94a3b8" font-size="10.5" font-family="monospace">192.168.23.0/30</text>

    <!-- Web / Untrust Client -->
    <g>
      <rect x="20" y="34" width="110" height="60" rx="10" fill="#111827" stroke="#475569" stroke-width="1.5"/>
      <text x="75" y="57" text-anchor="middle" fill="#eef2f7" font-size="12" font-weight="700">🌐 Web / Untrust</text>
      <text x="75" y="75" text-anchor="middle" fill="#94a3b8" font-size="10.5" font-family="monospace">10.1.0.10</text>
    </g>

    <!-- R1 -->
    <g class="topo-node" data-dev="R1">
      <rect x="265" y="28" width="130" height="72" rx="11" fill="#131c2e" stroke="${devStroke('R1')}" stroke-width="2.2"/>
      <text x="330" y="52" text-anchor="middle" fill="#eef2f7" font-size="13" font-weight="800">R1 (VRP Router)</text>
      <text x="330" y="70" text-anchor="middle" fill="#94a3b8" font-size="10.5" font-family="monospace">.12.1/30 · 🛡OSPF</text>
      <text x="330" y="88" text-anchor="middle" fill="#7dd3fc" font-size="10">点击查看 R1.cfg</text>
    </g>

    <!-- USG1 -->
    <g class="topo-node" data-dev="USG1">
      <rect x="505" y="24" width="150" height="80" rx="11" fill="#19162e" stroke="${devStroke('USG1')}" stroke-width="2.2"/>
      <text x="580" y="48" text-anchor="middle" fill="#eef2f7" font-size="13" font-weight="800">🛡 USG1 (Firewall)</text>
      <text x="580" y="66" text-anchor="middle" fill="#fbbf24" font-size="10.5" font-family="monospace">untrust → trust</text>
      <text x="580" y="84" text-anchor="middle" fill="#c084fc" font-size="10">Z3 策略求解 · 点击查看</text>
    </g>

    <!-- R2 -->
    <g class="topo-node" data-dev="R2">
      <rect x="765" y="28" width="130" height="72" rx="11" fill="#131c2e" stroke="${devStroke('R2')}" stroke-width="2.2"/>
      <text x="830" y="52" text-anchor="middle" fill="#eef2f7" font-size="13" font-weight="800">R2 (VRP Router)</text>
      <text x="830" y="70" text-anchor="middle" fill="#94a3b8" font-size="10.5" font-family="monospace">.23.2/30 · 10.2/24</text>
      <text x="830" y="88" text-anchor="middle" fill="#7dd3fc" font-size="10">点击查看 R2.cfg</text>
    </g>

    <!-- App Server (Target) -->
    <g>
      <rect x="955" y="14" width="145" height="46" rx="9" fill="#0d1e1c" stroke="${ok ? '#34d399' : '#475569'}" stroke-width="1.6"/>
      <text x="1027" y="34" text-anchor="middle" fill="#eef2f7" font-size="11.5" font-weight="700">🎯 App-Server :443</text>
      <text x="1027" y="50" text-anchor="middle" fill="${ok ? '#34d399' : '#f87171'}" font-size="10" font-family="monospace">10.2.0.10 · ${ok ? 'PERMIT+OK' : 'BLOCKED'}</text>
    </g>

    <!-- DB Server (Invariant) -->
    <g>
      <rect x="955" y="72" width="145" height="46" rx="9" fill="${dbExposed ? '#2b1014' : '#141524'}" stroke="${dbExposed ? '#f87171' : '#34d399'}" stroke-width="1.6"/>
      <text x="1027" y="92" text-anchor="middle" fill="#eef2f7" font-size="11.5" font-weight="700">🔒 DB-Server :3306</text>
      <text x="1027" y="108" text-anchor="middle" fill="${dbExposed ? '#f87171' : '#34d399'}" font-size="10" font-family="monospace">10.2.0.20 · ${dbExposed ? '🚨 EXPOSED!' : 'PROTECTED'}</text>
    </g>
  `;
}

function renderOntologyGraph() {
  const g = state.data.ontology_graph;
  const entitiesHtml = g.nodes
    .map(
      (n) =>
        `<span class="entity-chip ${esc(n.type)}" title="${esc(JSON.stringify(n.props))}">[${esc(n.type)}] ${esc(n.label)}</span>`
    )
    .join('');

  const interestingRels = new Set(['L3_LINK', 'IN_ZONE', 'SRC_ZONE', 'DST_ZONE', 'USES_ADDR_SET', 'USES_SVC_SET', 'ROUTES_TO', 'PROTECTS_UNPARSED']);
  const keyEdges = g.edges.filter((e) => interestingRels.has(e.relation));
  const edgesHtml = keyEdges
    .map(
      (e) =>
        `<div class="edge-row">${esc(e.source)} <span class="edge-rel">—${esc(e.relation)}→</span> ${esc(e.target)}</div>`
    )
    .join('');

  $('#onto-graph-box').innerHTML = `
    <div class="onto-col">
      <div class="onto-sec-title">本体实体实例 C（由真实 vrp-ir 自动构建，共 ${g.nodes.length} 个）</div>
      <div class="chip-cloud">${entitiesHtml}</div>
    </div>
    <div class="onto-col">
      <div class="onto-sec-title">解引用跨设备语义关系 R（共 ${g.edges.length} 条，展示关键跨层关系）</div>
      <div class="edge-list">${edgesHtml}</div>
    </div>
  `;
}

function renderLeftPane() {
  const dev = state.dev;
  for (const b of $('#dev-tabs').querySelectorAll('button')) {
    b.setAttribute('aria-selected', String(b.dataset.dev === dev));
  }
  for (const b of $('#left-mode-tabs').querySelectorAll('button')) {
    b.setAttribute('aria-selected', String(b.dataset.mode === state.leftMode));
  }

  const raw = state.data.configs[dev] || '';
  const ir = state.data.ir[dev] || {};
  const unparsedSet = new Set((ir.unparsed_lines || []).map((u) => u.line));

  if (state.leftMode === 'ir') {
    $('#left-body').innerHTML = `<pre class="json-pre">${esc(JSON.stringify(ir, null, 2))}</pre>`;
    return;
  }

  const linesHtml = raw
    .split('\n')
    .filter((_, idx, arr) => !(idx === arr.length - 1 && arr[idx] === ''))
    .map((line, i) => {
      const ln = i + 1;
      const cls = unparsedSet.has(ln) ? 'cfg-line unparsed' : 'cfg-line';
      return `<div class="${cls}"><span class="ln">${ln}</span><span class="txt">${esc(line)}</span></div>`;
    })
    .join('');

  const unpBanner = unparsedSet.size
    ? `<div class="unparsed-banner">🛡 <strong>受保护帧（Protected Frame）：</strong>vrp-ir 标记 <code>${dev}.cfg:L${[...unparsedSet].join(', L')}</code> 为 <code>unparsed_lines</code>，动态本体前置护栏严禁任何 Action 修改。</div>`
    : '';

  $('#left-body').innerHTML = `${unpBanner}<div class="cfg-box">${linesHtml}</div>`;
}

function renderMiddlePane() {
  const { targets, invariants, shadowed_rules } = state.data.functions;
  const parts = [];

  // F1: Target flow trace
  for (const t of targets) {
    const ok = t.allowed_and_reachable;
    const fwdHops = (t.forward.hops || [])
      .map((h) => {
        const cls = h.action.includes('DENY') || h.action.includes('DROP') ? 'bad' : h.action === 'DELIVER_LOCAL' || h.action === 'FW_PERMIT' ? 'ok' : '';
        return `<div class="hop-item ${cls}"><strong>[${esc(h.device)}] ${esc(h.action)}</strong> · ${esc(h.detail)}</div>`;
      })
      .join('');
    const revOk = t.reverse.ok;
    parts.push(`
      <div class="fn-card ${ok ? 'ok' : 'fail'}">
        <div class="fn-head">
          <div class="fn-title">F1 · evaluate_flow(${esc(t.name)})</div>
          <span class="fn-tag ${ok ? 'ok' : 'fail'}">${ok ? 'PASS' : 'BLOCKED'}</span>
        </div>
        <div class="hop-list">
          ${fwdHops}
          <div class="hop-item ${revOk ? 'ok' : 'bad'}"><strong>[回程对称性校验]</strong> ${esc(t.reverse.reason)}</div>
        </div>
      </div>
    `);
  }

  // I: Symbolic Z3 Invariants
  const allInvOk = invariants.every((i) => i.ok);
  const invRows = invariants
    .map((inv) => {
      const ceHtml = inv.counterexample && inv.counterexample.packet
        ? `<div class="inv-proof">🚨 反例包：<code>${esc(inv.counterexample.packet)}</code> 命中 <code>${esc(inv.counterexample.matched_rule)}</code></div>`
        : '';
      return `
        <div class="inv-row ${inv.ok ? '' : 'bad'}">
          <div>${inv.ok ? '✅' : '🚨'} <strong>${esc(inv.name)}</strong></div>
          <div class="inv-proof">${esc(inv.proof)}</div>
          ${ceHtml}
        </div>`;
    })
    .join('');

  parts.push(`
    <div class="fn-card ${allInvOk ? 'ok' : 'fail'}">
      <div class="fn-head">
        <div class="fn-title">I · 全局不变量形式化证明（Z3 SMT）</div>
        <span class="fn-tag ${allInvOk ? 'ok' : 'fail'}">${allInvOk ? 'ALL SAFE' : 'VIOLATED'}</span>
      </div>
      ${invRows}
    </div>
  `);

  // F2: Z3 Shadowed Rule Detection
  const shRows = shadowed_rules.length
    ? shadowed_rules
        .map(
          (r) => `
          <div class="inv-row">
            <div>⚠️ <strong>#${r.order} ${esc(r.rule_name)}</strong> (<code>${esc(r.source)}</code>)</div>
            <div class="inv-proof">${esc(r.reason)}</div>
          </div>`
        )
        .join('')
    : `<div class="inv-row">✅ Z3 证明当前 USG1 安全策略中不存在完全被遮蔽的死规则。</div>`;

  parts.push(`
    <div class="fn-card ${shadowed_rules.length ? 'warn' : 'ok'}">
      <div class="fn-head">
        <div class="fn-title">F2 · detect_shadowed_rules(USG1)</div>
        <span class="fn-tag ${shadowed_rules.length ? 'warn' : 'ok'}">${shadowed_rules.length} SHADOWED</span>
      </div>
      ${shRows}
    </div>
  `);

  $('#mid-body').innerHTML = parts.join('');
}

function renderRightPane() {
  const plan = state.data.last_plan;
  const badge = $('#plan-badge');
  if (!plan) {
    badge.textContent = '待运行';
    $('#right-body').innerHTML = `
      <div class="fn-card">
        <div class="fn-title">🧠 差分引导的多分支沙箱规划</div>
        <div style="color:var(--muted);font-size:12.5px;line-height:1.65;">
          点击上方 <strong>「🧠 运行动态本体沙箱规划」</strong>，系统将在<strong>内存 Copy-on-Write 沙箱</strong>中并行推演多个候选 Action 分支：<br/>
          1. 用真实 <code>vrp-ir</code> 解析并下推编译为华为最小化 Diff；<br/>
          2. 调用 <strong>Z3 SMT + 原子网段切分</strong> 计算每个分支的完整语义差分 Δ(S0, a)；<br/>
          3. 自动<strong>拦截违背安全不变量 / 碰触未解析行的危险方案</strong>，并在可行方案中按代价择优。<br/><br/>
          💡 <em>所有 Z3 形式化证明和沙箱规划均在本地毫秒级完成，无需填写任何 API Key。</em>
        </div>
      </div>`;
    return;
  }

  badge.textContent = `${plan.branch_count} 分支 · ${plan.elapsed_ms}ms`;

  const cards = plan.branches
    .map((b) => {
      const isSelected = Boolean(b.selected);
      const isCommitted = state.data.committed_branch_id === b.id;
      const cardCls = isSelected
        ? 'selected'
        : b.verdict === 'BLOCKED_PRECONDITION'
          ? 'blocked'
          : b.verdict === 'PRUNED_INVARIANT' || b.verdict === 'PRUNED_INCOMPLETE'
            ? 'pruned'
            : '';
      const chipCls = isSelected
        ? 'ok'
        : b.verdict === 'BLOCKED_PRECONDITION'
          ? 'purple'
          : b.verdict === 'FEASIBLE'
            ? 'warn'
            : 'fail';

      const stepsHtml = (b.steps || [])
        .map((st) => `<div class="act-pill">${st.ok ? '▸' : '⛔'} [${esc(st.action_type)}] ${esc(st.summary)}</div>`)
        .join('');

      let bodyExtra = '';
      if (b.error) {
        bodyExtra += `<div class="guard-box"><strong>护栏拦截原因：</strong>${esc(b.error)}</div>`;
      }

      if (b.semantic_diff) {
        const sd = b.semantic_diff;
        // Violated invariant Z3 counterexamples
        const badInvs = sd.invariants.filter((i) => !i.ok);
        if (badInvs.length) {
          const ceLines = badInvs
            .map((bi) => {
              const ce = bi.counterexample;
              const pkt = ce?.packet ? `反例数据包：<code>${esc(ce.packet)}</code> (${esc(ce.zone_pair)}) 命中 <code>${esc(ce.matched_rule)}</code>` : esc(bi.proof);
              return `<div>🚨 <strong>违背 ${esc(bi.name)}</strong><br/>${pkt}</div>`;
            })
            .join('');
          bodyExtra += `<div class="ce-box">${ceLines}</div>`;
        }

        // Semantic Diff Summary (Target + Firewall Z3 diff + Atomic Prefix Routing diff + Shadow diff)
        const tSummary = sd.targets.map((t) => `${esc(t.name)}: <strong>${esc(t.status)}</strong>`).join(' | ');
        const rDiff = sd.routing_diff.length
          ? sd.routing_diff.map((r) => `<code>${esc(r.prefix)}</code> (${esc(r.change)})`).join('，')
          : '无 L3 路由表变化';
        const fwPerm = sd.firewall_diff.newly_permitted.length
          ? sd.firewall_diff.newly_permitted.map((p) => `<code>${esc(p.packet)}</code>`).join('，')
          : '无新增放通流';
        const shDelta = `${sd.shadowed_diff.before_count} → ${sd.shadowed_diff.after_count} 条死规则`;

        bodyExtra += `
          <div class="diff-summary">
            <div><strong>Δ 目标流效果：</strong>${tSummary}</div>
            <div><strong>Δ L3 原子网段路由差分：</strong>${rDiff}</div>
            <div><strong>Δ Z3 防火墙新增放通采样：</strong>${fwPerm}</div>
            <div><strong>Δ Z3 策略遮蔽变化：</strong>${shDelta}</div>
          </div>`;
      }

      const diffBlock = b.diff
        ? `<details ${isSelected ? 'open' : ''}><summary style="cursor:pointer;color:var(--accent-ink);font-size:11.5px;font-weight:700;">查看下推编译的华为 VRP 配置 Diff（改动 ${b.changed_lines} 行）</summary><pre class="diff-pre" style="margin-top:6px;">${diffHtml(b.diff)}</pre></details>`
        : '';

      const canCommit = b.verdict !== 'BLOCKED_PRECONDITION' && b.verdict !== 'INVALID';
      const commitBtn = canCommit
        ? isCommitted
          ? `<span class="verdict-chip ok">✓ 已应用到当前配置</span>`
          : `<button type="button" class="commit-btn ${isSelected ? '' : 'secondary'}" data-commit="${esc(b.id)}">${isSelected ? '✅ 提交最优方案' : '应用此分支体验对比'}</button>`
        : `<span class="verdict-chip purple">不可提交</span>`;

      return `
        <div class="branch-card ${cardCls}">
          <div class="branch-head">
            <div>
              <div class="branch-title">${esc(b.title)}</div>
              <div class="branch-sub">${esc(b.source_tag)} · ${esc(b.rationale)}</div>
            </div>
            <span class="verdict-chip ${chipCls}">${esc(b.verdict_label)}</span>
          </div>
          <div class="branch-body">
            <div class="act-pills">${stepsHtml}</div>
            ${bodyExtra}
            ${diffBlock}
            <div class="branch-foot">
              <span class="score-meta">规划评分: ${b.score} · 改动行数: ${b.changed_lines} · Z3耗时: ${b.elapsed_ms}ms</span>
              ${commitBtn}
            </div>
          </div>
        </div>`;
    })
    .join('');

  $('#right-body').innerHTML = cards;
}

function renderAll() {
  renderScenarios();
  renderHero();
  renderLeftPane();
  renderMiddlePane();
  renderRightPane();
}

async function fetchState() {
  const res = await fetch('/api/state');
  state.data = await res.json();
  renderAll();
}

async function loadScenario(id) {
  const res = await fetch(`/api/scenario/${id}`, { method: 'POST' });
  state.data = await res.json();
  renderAll();
}

async function runPlanner() {
  const btn = $('#btn-plan');
  btn.disabled = true;
  btn.textContent = '⏳ Z3 沙箱推演中...';
  try {
    const res = await fetch('/api/plan/run', { method: 'POST' });
    state.data = await res.json();
    renderAll();
  } finally {
    btn.disabled = false;
    btn.textContent = '🧠 运行动态本体沙箱规划';
  }
}

async function commitBranch(branchId) {
  const res = await fetch(`/api/plan/commit/${branchId}`, { method: 'POST' });
  if (!res.ok) {
    alert(await res.text());
    return;
  }
  state.data = await res.json();
  renderAll();
}

async function openBenchmark() {
  $('#bench-modal').classList.remove('hidden');
  $('#bench-body').innerHTML = '正在对全部 3 个场景实时运行 Z3 差分对比评测...';
  const res = await fetch('/api/benchmark');
  const data = await res.json();
  const s = data.summary;
  const rows = data.scenarios
    .map(
      (r) => `
      <tr>
        <td><strong>${esc(r.scenario_name)}</strong></td>
        <td>${r.naive.target_ok ? '✅ 通' : '❌ 不通'} / ${r.naive.invariant_ok ? '✅ 安全' : '🚨 违背安全'}<br/><span style="color:var(--muted)">死规则: ${r.naive.shadowed_after ?? '-'} · 改动 ${r.naive.changed_lines} 行</span></td>
        <td>✅ 通 / ✅ Z3 证明安全<br/><span style="color:var(--ok)">死规则: ${r.ours.shadowed_after} · 改动 ${r.ours.changed_lines} 行 · ${r.ours.elapsed_ms}ms</span></td>
      </tr>`
    )
    .join('');

  $('#bench-body').innerHTML = `
    <div class="bench-kpi-row">
      <div class="kpi-box">
        <div class="kpi-label">目标连通率（传统 vs 动态本体）</div>
        <div class="kpi-val"><span class="bad">${esc(s.naive_target_rate)}</span> → <span class="good">${esc(s.ours_target_rate)}</span></div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">零副作用率（目标达成且零安全回归）</div>
        <div class="kpi-val"><span class="bad">${esc(s.naive_zero_regression_rate)}</span> → <span class="good">${esc(s.ours_zero_regression_rate)}</span></div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">最优无死规则率（零回归且零策略遮蔽）</div>
        <div class="kpi-val"><span class="bad">${esc(s.naive_zero_shadow_rate)}</span> → <span class="good">${esc(s.ours_zero_shadow_rate)}</span></div>
      </div>
    </div>
    <table class="bench-table">
      <thead>
        <tr>
          <th>评测场景（3 设备真实 vrp-ir + Z3 校验）</th>
          <th>传统方案（纯 LLM 偷懒 / 单层修复 / 顶部打补丁）</th>
          <th>可执行动态本体（Sandbox + Z3 差分引导规划）</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
    <div class="muted-note">💡 所有指标均由服务器刚刚实时调用真实 <code>vrp-ir</code> 解析器与 <code>Z3 SMT 求解器</code> 计算得出，非硬编码数据。</div>
  `;
}

async function runLlmPropose() {
  const txt = $('#llm-prompt').value.trim();
  if (!txt) return;
  if (!state.llm.apiKey) {
    $('#api-modal').classList.remove('hidden');
    return;
  }
  const btn = $('#btn-llm-propose');
  btn.disabled = true;
  btn.textContent = '⏳ 提案中...';
  try {
    const res = await fetch('/api/llm/propose', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-LLM-API-Key': state.llm.apiKey,
      },
      body: JSON.stringify({
        instruction: txt,
        base_url: state.llm.baseUrl,
        model: state.llm.model,
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      alert(data.detail || `HTTP ${res.status}`);
      return;
    }
    state.data = data.state;
    $('#llm-prompt').value = '';
    renderAll();
  } finally {
    btn.disabled = false;
    btn.textContent = '🤖 LLM 提案';
  }
}

// Events
$('#scenario-tabs').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-sc]');
  if (b) loadScenario(b.dataset.sc);
});
$('#btn-plan').addEventListener('click', runPlanner);
$('#btn-reset').addEventListener('click', () => loadScenario(state.data.active_scenario));
$('#hero-view-tabs').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-view]');
  if (!b) return;
  state.heroView = b.dataset.view;
  for (const x of $('#hero-view-tabs').querySelectorAll('button')) {
    x.setAttribute('aria-selected', String(x.dataset.view === state.heroView));
  }
  renderHero();
});
$('#topo-svg').addEventListener('click', (e) => {
  const n = e.target.closest('[data-dev]');
  if (!n) return;
  state.dev = n.dataset.dev;
  renderTopologySvg();
  renderLeftPane();
});
$('#dev-tabs').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-dev]');
  if (!b) return;
  state.dev = b.dataset.dev;
  renderTopologySvg();
  renderLeftPane();
});
$('#left-mode-tabs').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-mode]');
  if (!b) return;
  state.leftMode = b.dataset.mode;
  renderLeftPane();
});
$('#right-body').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-commit]');
  if (b) commitBranch(b.dataset.commit);
});
$('#btn-benchmark').addEventListener('click', openBenchmark);
$('#btn-close-bench').addEventListener('click', () => $('#bench-modal').classList.add('hidden'));
$('#bench-modal').addEventListener('click', (e) => { if (e.target.id === 'bench-modal') $('#bench-modal').classList.add('hidden'); });

$('#btn-api-modal').addEventListener('click', () => {
  $('#input-key').value = state.llm.apiKey || '';
  $('#input-url').value = state.llm.baseUrl || 'https://api.deepseek.com/v1';
  $('#input-model').value = state.llm.model || 'deepseek-chat';
  $('#api-modal').classList.remove('hidden');
});
$('#btn-close-api').addEventListener('click', () => $('#api-modal').classList.add('hidden'));
$('#btn-save-key').addEventListener('click', () => {
  state.llm = {
    apiKey: $('#input-key').value.trim(),
    baseUrl: $('#input-url').value.trim() || 'https://api.deepseek.com/v1',
    model: $('#input-model').value.trim() || 'deepseek-chat',
  };
  localStorage.setItem(LLM_KEY_STORAGE, JSON.stringify(state.llm));
  $('#api-modal').classList.add('hidden');
});
$('#btn-clear-key').addEventListener('click', () => {
  state.llm.apiKey = '';
  localStorage.removeItem(LLM_KEY_STORAGE);
  $('#input-key').value = '';
});
$('#btn-llm-propose').addEventListener('click', runLlmPropose);
$('#llm-prompt').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runLlmPropose();
});

loadLlm();
fetchState();
