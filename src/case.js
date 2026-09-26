// 读取并校验“按阶段分舱”的联合专案约定文档。
//
// 仓库只保存约定与虚构样例：本模块不做真实访问控制，而是检查文档本身
// 是否自洽——舱位、批次、可见对象、密封材料、解封条件、双负责人批准、
// 只追加日志、来源链与结案获知范围报告之间的引用和规则是否成立。
import { createHash } from 'node:crypto';

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

// 规范化事件内容，保证哈希只覆盖载荷与顺序锚点，不覆盖（可能被记录的）摘要字段。
export function canonicalEvent(entry) {
  return JSON.stringify({
    seq: entry.seq,
    at: entry.at,
    actor: entry.actor,
    action: entry.action,
    payload: entry.payload ?? {},
  });
}

// 重新计算整段日志的自摘要与 prev_hash（供构造测试样例使用）。
export function reseal(events) {
  let prevHash = null;
  for (const e of events) {
    e.prev_hash = prevHash;
    e.hash = sha256(canonicalEvent(e));
    prevHash = e.hash;
  }
  return events;
}

export function parseCaseDoc(raw) {
  const value = typeof raw === 'string' ? JSON.parse(raw) : structuredClone(raw);
  const errors = [];
  const add = (message) => errors.push(message);

  requireShape(value, add);
  if (errors.length) throw new Error(`案件约定文档格式不合法：\n- ${errors.join('\n- ')}`);

  const ctx = buildContext(value);
  runChecks(ctx, add);
  if (errors.length) throw new Error(`案件约定文档未通过领域校验：\n- ${errors.join('\n- ')}`);
  return value;
}

function requireShape(v, add) {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    add('根节点必须是对象');
    return;
  }
  for (const key of ['domain', 'version', 'sample_id', 'case_file', 'persons', 'compartments', 'batches', 'materials', 'leads', 'grants', 'events', 'receipts', 'closure']) {
    if (!(key in v)) add(`缺少必要字段 ${key}`);
  }
  if (v.domain !== 'joint-enforcement-secrecy') add('domain 必须为 joint-enforcement-secrecy');
  if (!Number.isInteger(v.version) || v.version < 1) add('version 必须为不小于 1 的整数');
  if (typeof v.sample_id !== 'string' || !v.sample_id) add('sample_id 必须为非空字符串');
}

function buildContext(v) {
  const persons = new Map(v.persons.map((p) => [p.person_id, p]));
  const compartments = new Map(v.compartments.map((c) => [c.compartment_id, c]));
  const materials = new Map(v.materials.map((m) => [m.material_id, m]));
  const leads = new Map(v.leads.map((l) => [l.lead_id, l]));
  const batches = new Map(v.batches.map((b) => [b.batch_id, b]));
  const grants = new Map(v.grants.map((g) => [g.grant_id, g]));
  const roles = new Map((v.roles ?? []).map((r) => [r.role_id, r]));
  return { v, persons, compartments, materials, leads, batches, grants, roles };
}

function runChecks(ctx, add) {
  checkCaseFile(ctx, add);
  checkActorsAndRoles(ctx, add);
  checkCompartments(ctx, add);
  checkBatches(ctx, add);
  checkMaterials(ctx, add);
  checkLeads(ctx, add);
  checkGrants(ctx, add);
  const eventsById = checkEvents(ctx, add);
  checkReceipts(ctx, add, eventsById);
  checkClosure(ctx, add, eventsById);
}

// ---- 案件档案与核心名单 -------------------------------------------------------

function checkCaseFile(ctx, add) {
  const { v } = ctx;
  const cf = v.case_file;
  for (const key of ['case_id', 'title', 'director_ids']) {
    if (cf[key] === undefined) add(`case_file 缺少 ${key}`);
  }
  const entries = cf.core_entries ?? [];
  const ids = new Set();
  for (const entry of entries) {
    if (ids.has(entry.entry_id)) add(`核心名单条目标识重复：${entry.entry_id}`);
    ids.add(entry.entry_id);
    if (!['suspect', 'warehouse', 'fund-account'].includes(entry.kind)) {
      add(`核心条目 ${entry.entry_id} 的 kind 非法`);
    }
    if (entry.initial === undefined) add(`核心条目 ${entry.entry_id} 必须声明 initial`);
    // 非初始条目必须说明是经哪次双批准扩大入册（事件校验中再核对批准本身）。
    if (!entry.initial && !entry.added_via_event_id) {
      add(`非初始核心条目 ${entry.entry_id} 缺少 added_via_event_id`);
    }
  }
}

// ---- 人员与角色 ------------------------------------------------------------

function checkActorsAndRoles(ctx, add) {
  const { v, persons, roles } = ctx;
  const units = new Set();
  for (const p of v.persons) {
    if (typeof p.unit !== 'string' || !p.unit) add(`人员 ${p.person_id} 缺少所属单位`);
    units.add(p.unit);
    if (p.role_ids) for (const rid of p.role_ids) {
      if (!roles.has(rid)) add(`人员 ${p.person_id} 引用了不存在的角色 ${rid}`);
    }
    // 调离必须有生效时间，调离之后不得再作为事件行为人出现（在事件校验中处理）。
    if (p.transferred_away_at !== undefined && typeof p.transferred_away_at !== 'string') {
      add(`人员 ${p.person_id} 的 transferred_away_at 必须是时间戳字符串`);
    }
  }
  const directors = v.case_file.director_ids ?? [];
  if (!Array.isArray(directors) || directors.length < 2) {
    add('case_file.director_ids 至少要有两名负责人（双批准的前提）');
  } else {
    const unitsOfDirectors = new Set(directors.map((id) => persons.get(id)?.unit));
    for (const id of directors) {
      if (!persons.has(id)) add(`负责人 ${id} 不在人员名册中`);
    }
    if (unitsOfDirectors.size < 2) add('两名负责人必须来自不同单位（医保 / 公安）');
  }
}

// ---- 舱位 ------------------------------------------------------------------

function checkCompartments(ctx, add) {
  const { v, persons } = ctx;
  for (const c of v.compartments) {
    if (c.opens_at !== undefined && c.closes_at !== undefined && c.closes_at <= c.opens_at) {
      add(`舱位 ${c.compartment_id} 关闭时间早于开启时间`);
    }
    if (!Array.isArray(c.owner_ids) || c.owner_ids.length === 0) {
      add(`舱位 ${c.compartment_id} 缺少 owner_ids`);
    }
    for (const id of c.owner_ids ?? []) {
      if (!persons.has(id)) add(`舱位 ${c.compartment_id} 的负责人 ${id} 不在名册中`);
    }
    // 解封条件引用的批次/时间必须真实存在；人工解封需要两名负责人批准事件。
    for (const cond of c.unseal_conditions ?? []) {
      if (cond.type === 'batch_activated' && !ctx.batches.has(cond.batch_id)) {
        add(`舱位 ${c.compartment_id} 的解封条件引用了不存在的批次 ${cond.batch_id}`);
      }
      if (cond.type === 'manual' && (!Array.isArray(cond.approver_ids) || new Set(cond.approver_ids).size < 2)) {
        add(`舱位 ${c.compartment_id} 的人工解封条件至少需要两名批准人`);
      }
      if (cond.type === 'scheduled' && !cond.at) {
        add(`舱位 ${c.compartment_id} 的定时解封条件缺少 at`);
      }
    }
  }
}

// ---- 行动批次 ---------------------------------------------------------------

function checkBatches(ctx, add) {
  const { v, compartments } = ctx;
  for (const b of v.batches) {
    if (!compartments.has(b.compartment_id)) {
      add(`批次 ${b.batch_id} 引用了不存在的舱位 ${b.compartment_id}`);
    }
  }
  // 延期以事件为准（batch.postponed_to），此处只校验静态计划时间不矛盾。
  for (const b of v.batches) {
    if (b.planned_at === undefined) add(`批次 ${b.batch_id} 缺少 planned_at`);
  }
}

// ---- 材料：密封、摘录与来源链 -------------------------------------------------

function checkMaterials(ctx, add) {
  const { v, materials, compartments } = ctx;
  for (const m of v.materials) {
    if (!compartments.has(m.compartment_id)) {
      add(`材料 ${m.material_id} 所在舱位 ${m.compartment_id} 不存在`);
    }
    if (m.core_entry_id !== undefined) {
      const entry = (v.case_file.core_entries ?? []).find((c) => c.entry_id === m.core_entry_id);
      if (!entry) add(`材料 ${m.material_id} 绑定了不存在的核心条目 ${m.core_entry_id}`);
    }
    for (const ref of m.derived_from ?? []) {
      const target = materials.has(ref.material_id) ? materials.get(ref.material_id) : null;
      if (!target) add(`材料 ${m.material_id} 的来源 ${ref.material_id} 不存在`);
      if (ref.relation === 'extract' && !ref.excerpt_ref) {
        add(`材料 ${m.material_id} 的摘录来源 ${ref.material_id} 必须给出 excerpt_ref 定位`);
      }
    }
    // 分类等级：公开检查材料不得直接充当专案证据，必须经移送/转换关系。
    if (m.classification === 'public-inspection') {
      for (const ref of m.derived_from ?? []) {
        const src = materials.get(ref.material_id);
        if (src && (src.classification === 'case-evidence' || src.classification === 'prosecution-copy')) {
          add(`公开材料 ${m.material_id} 不得反向引用专案/起诉材料作为来源`);
        }
      }
    }
  }
  // 起诉副本必须能沿来源链回溯到专案证据，再回溯到公开检查材料或原始线索。
  for (const m of v.materials) {
    if (m.classification === 'prosecution-copy') {
      const ok = traceToCaseEvidence(m.material_id, materials);
      if (!ok) add(`起诉副本 ${m.material_id} 的来源链未回溯到任何专案证据`);
    }
  }
}

function traceToCaseEvidence(id, materials, seen = new Set()) {
  if (seen.has(id)) return false;
  seen.add(id);
  const m = materials.get(id);
  for (const ref of m.derived_from ?? []) {
    const src = materials.get(ref.material_id);
    if (!src) continue;
    if (src.classification === 'case-evidence') return true;
    if (traceToCaseEvidence(ref.material_id, materials, seen)) return true;
  }
  return false;
}

// ---- 线索：普通线索在条件达成前不与专案身份关联 ----------------------------------

function checkLeads(ctx, add) {
  const { v, leads, batches } = ctx;
  const coreIds = new Set((v.case_file.core_entries ?? []).map((c) => c.entry_id));
  for (const lead of v.leads) {
    if (lead.linked_core_entry_ids !== undefined) {
      if (!lead.link_condition) {
        add(`线索 ${lead.lead_id} 已关联专案身份却缺少 link_condition`);
      }
      for (const cid of lead.linked_core_entry_ids ?? []) {
        if (!coreIds.has(cid)) add(`线索 ${lead.lead_id} 关联了不存在的核心条目 ${cid}`);
      }
      const cond = lead.link_condition;
      if (cond?.type === 'batch_activated' && !batches.has(cond.batch_id)) {
        add(`线索 ${lead.lead_id} 的关联条件引用了不存在的批次 ${cond.batch_id}`);
      }
    }
  }
}

// ---- 授权：常驻授权与临时授权 ---------------------------------------------------

function checkGrants(ctx, add) {
  const { v, persons, compartments, grants } = ctx;
  for (const g of v.grants) {
    if (!persons.has(g.person_id)) add(`授权 ${g.grant_id} 的人员 ${g.person_id} 不存在`);
    if (!compartments.has(g.compartment_id)) add(`授权 ${g.grant_id} 的舱位 ${g.compartment_id} 不存在`);
    if (!Array.isArray(g.actions) || g.actions.length === 0) add(`授权 ${g.grant_id} 缺少 actions`);
    const valid = new Set(['view', 'excerpt', 'transfer', 'grant-temp']);
    for (const a of g.actions) if (!valid.has(a)) add(`授权 ${g.grant_id} 含未知动作 ${a}`);
    if (g.temp) {
      if (!g.valid_from || !g.expires_at) add(`临时授权 ${g.grant_id} 必须同时给出 valid_from 与 expires_at`);
      if (g.valid_from && g.expires_at && g.expires_at <= g.valid_from) {
        add(`临时授权 ${g.grant_id} 到期时间不晚于生效时间`);
      }
      // 临时授权必须由事件授予（temp-grant），并记录理由；到期/撤销只失效、不删记录。
      if (!g.basis_event_id) add(`临时授权 ${g.grant_id} 缺少 basis_event_id（授予依据）`);
      // 生效时间不得早于授予事件，防止“提前授权”。
      const basis = (v.events ?? []).find((e) => e.event_id === g.basis_event_id);
      if (g.basis_event_id && !basis) add(`临时授权 ${g.grant_id} 的授予事件 ${g.basis_event_id} 不存在`);
      if (basis && basis.action !== 'temp-grant') add(`临时授权 ${g.grant_id} 的依据事件 ${g.basis_event_id} 不是 temp-grant`);
      if (basis && g.valid_from && g.valid_from < basis.at) {
        add(`临时授权 ${g.grant_id} 的生效时间早于其授予事件 ${g.basis_event_id}`);
      }
    }
  }
}

// ---- 只追加日志：哈希链、动作语义与实时状态规则 ------------------------------------

function checkEvents(ctx, add) {
  const { v, persons, compartments, materials, grants, batches, leads } = ctx;
  const eventsById = new Map();
  let prevHash = null;

  v.events.forEach((e, i) => {
    if (e.seq !== i + 1) add(`事件序号不连续：位置 ${i + 1} 的 seq 为 ${e.seq}`);
    if (eventsById.has(e.event_id)) add(`事件标识重复：${e.event_id}`);
    eventsById.set(e.event_id, e);

    if (i > 0 && e.prev_hash !== prevHash) {
      add(`事件 ${e.event_id} 的 prev_hash 与前一事件摘要不符（链断裂或被篡改）`);
    }
    if (e.hash !== sha256(canonicalEvent(e))) {
      add(`事件 ${e.event_id} 的自摘要不匹配（内容被篡改或未重新封缄）`);
    }
    prevHash = e.hash;

    if (!persons.has(e.actor)) add(`事件 ${e.event_id} 的行为人 ${e.actor} 不在名册`);
    const actor = persons.get(e.actor);
    if (actor?.transferred_away_at && e.at >= actor.transferred_away_at) {
      add(`人员 ${e.actor} 已于 ${actor.transferred_away_at} 调离，事件 ${e.event_id} 仍以其名义操作`);
    }
  });

  // 动作语义与状态机
  const coreEntryIds = new Set((v.case_file.core_entries ?? []).map((c) => c.entry_id));
  const openedCompartments = new Set(); // 已达成解封条件的舱位
  const frozenCompartments = new Set(); // 紧急止损封舱
  const unsealApprovals = new Map(); // 舱位 -> 已批准的负责人集合
  const batchActive = new Map();
  const batchEarliest = new Map(v.batches.map((b) => [b.batch_id, b.planned_at])); // 延期会推迟最早激活时间
  const revokedGrants = new Set();
  const linkedLeads = new Set();
  const coreAdded = new Set(); // 经双批准扩大后加入核心名单的条目

  for (const e of v.events) {
    const p = e.payload ?? {};
    switch (e.action) {
      case 'unseal-approval': {
        const c = compartments.get(p.compartment_id);
        if (!c) { add(`批准事件 ${e.event_id} 指向不存在的舱位`); break; }
        const manual = (c.unseal_conditions ?? []).find((cond) => cond.type === 'manual');
        if (!manual) add(`舱位 ${p.compartment_id} 没有人工解封条件，批准事件 ${e.event_id} 无依据`);
        else if (!manual.approver_ids.includes(e.actor)) {
          add(`批准事件 ${e.event_id} 的行为人 ${e.actor} 不是舱位 ${p.compartment_id} 指定的批准人`);
        }
        if (!unsealApprovals.has(p.compartment_id)) unsealApprovals.set(p.compartment_id, new Set());
        unsealApprovals.get(p.compartment_id).add(e.actor);
        break;
      }
      case 'compartment-unsealed': {
        const c = compartments.get(p.compartment_id);
        if (!c) { add(`事件 ${e.event_id} 解封了不存在的舱位`); break; }
        const ok = evaluateConditions(c.unseal_conditions ?? [], { batchActive, at: e.at, approvals: unsealApprovals.get(p.compartment_id) });
        if (!ok) add(`事件 ${e.event_id} 在解封条件未达成时开启舱位 ${p.compartment_id}`);
        openedCompartments.add(p.compartment_id);
        break;
      }
      case 'emergency-freeze': {
        if (!p.compartment_id || !compartments.has(p.compartment_id)) {
          add(`止损事件 ${e.event_id} 缺少有效舱位`);
        }
        if (!p.reason) add(`止损事件 ${e.event_id} 必须写明 reason`);
        frozenCompartments.add(p.compartment_id);
        break;
      }
      case 'freeze-lifted': {
        frozenCompartments.delete(p.compartment_id);
        break;
      }
      case 'batch-activated': {
        if (!batches.has(p.batch_id)) add(`事件 ${e.event_id} 激活了不存在的批次 ${p.batch_id}`);
        else if (e.at < batchEarliest.get(p.batch_id)) {
          add(`批次 ${p.batch_id} 已延期至 ${batchEarliest.get(p.batch_id)}，事件 ${e.event_id} 提前激活`);
        } else if (batchActive.has(p.batch_id)) {
          add(`批次 ${p.batch_id} 被重复激活（事件 ${e.event_id}）`);
        }
        batchActive.set(p.batch_id, e.at);
        break;
      }
      case 'batch-postponed': {
        if (!batches.has(p.batch_id)) add(`事件 ${e.event_id} 延期了不存在的批次 ${p.batch_id}`);
        if (!p.new_at) add(`延期事件 ${e.event_id} 缺少 new_at`);
        else {
          const prev = batchEarliest.get(p.batch_id);
          if (p.new_at < prev) add(`延期事件 ${e.event_id} 的新时间早于原计划/前次延期时间`);
          if (batchActive.has(p.batch_id)) add(`批次 ${p.batch_id} 已激活，不能再延期（事件 ${e.event_id}）`);
          batchEarliest.set(p.batch_id, p.new_at);
        }
        break;
      }
      case 'grant-revoked': {
        if (!grants.has(p.grant_id)) add(`撤销事件 ${e.event_id} 指向不存在的授权 ${p.grant_id}`);
        if (!p.reason) add(`撤销事件 ${e.event_id} 必须写明 reason`);
        revokedGrants.add(p.grant_id);
        break;
      }
      case 'view':
      case 'excerpt':
      case 'transfer': {
        checkAccessEvent(e, ctx, { openedCompartments, frozenCompartments, grants, revokedGrants, add });
        break;
      }
      case 'temp-grant': {
        const g = grants.get(p.grant_id);
        if (!g) add(`事件 ${e.event_id} 授予了不存在的临时授权 ${p.grant_id}`);
        else {
          if (!g.temp || g.basis_event_id !== e.event_id) {
            add(`临时授权 ${p.grant_id} 必须声明 temp=true 且 basis_event_id 指向授予事件`);
          }
          if (p.compartment_id && p.compartment_id !== g.compartment_id) {
            add(`临时授权事件 ${e.event_id} 的舱位与授权 ${p.grant_id} 登记舱位不一致`);
          }
        }
        if (!p.justification) add(`临时授权事件 ${e.event_id} 缺少 justification`);
        // 授予人本人必须在目标舱位持有 grant-temp 权限，且授权当时在有效期内。
        const granterOk = grantsListFor(e.actor, p.compartment_id ?? g?.compartment_id, grants)
          .filter((og) => !revokedGrants.has(og.grant_id))
          .some((og) => {
          if (!og.actions.includes('grant-temp')) return false;
          if (og.valid_from && e.at < og.valid_from) return false;
          if (og.expires_at && e.at >= og.expires_at) return false;
          return true;
        });
        if (!granterOk) add(`临时授权事件 ${e.event_id} 的授予人 ${e.actor} 没有有效的 grant-temp 权限`);
        break;
      }
      case 'lead-linked': {
        const lead = leads.get(p.lead_id);
        if (!lead) { add(`事件 ${e.event_id} 关联了不存在的线索`); break; }
        const ok = evaluateConditions([lead.link_condition].filter(Boolean), { batchActive, at: e.at });
        if (!ok) add(`线索 ${lead.lead_id} 在关联条件达成前被关联到专案身份（事件 ${e.event_id}）`);
        for (const cid of p.core_entry_ids ?? []) {
          if (!(lead.linked_core_entry_ids ?? []).includes(cid)) {
            add(`线索 ${lead.lead_id} 的关联事件 ${e.event_id} 含未声明的核心条目 ${cid}`);
          }
        }
        linkedLeads.add(lead.lead_id);
        break;
      }
      case 'core-list-expanded': {
        if (!Array.isArray(p.entry_ids) || p.entry_ids.length === 0) {
          add(`扩大核心名单事件 ${e.event_id} 必须列出新增条目 entry_ids`);
        }
        for (const id of p.entry_ids ?? []) {
          const entry = coreEntryIds.has(id) ? v.case_file.core_entries.find((c) => c.entry_id === id) : null;
          if (!entry) { add(`扩大核心名单事件 ${e.event_id} 引用了不存在的核心条目 ${id}`); continue; }
          if (entry.initial) add(`核心条目 ${id} 本就在初始名单中，不能作为“扩大”对象（事件 ${e.event_id}）`);
          else if (coreAdded.has(id)) add(`核心条目 ${id} 已在先前事件中加入名单（事件 ${e.event_id} 重复扩大）`);
          else if (entry.added_via_event_id !== e.event_id) {
            add(`核心条目 ${id} 声明的入册事件与实际扩大事件 ${e.event_id} 不符`);
          }
          coreAdded.add(id);
        }
        if (!Array.isArray(p.approver_ids) || new Set(p.approver_ids).size < 2) {
          add(`扩大核心名单事件 ${e.event_id} 必须列出两名共同批准人`);
        } else {
          const units = new Set(p.approver_ids.map((id) => persons.get(id)?.unit));
          if (units.size < 2) add(`扩大核心名单事件 ${e.event_id} 的批准人必须来自两个不同单位`);
          const directorIds = new Set(v.case_file.director_ids);
          for (const id of p.approver_ids) {
            if (!directorIds.has(id)) add(`扩大核心名单事件 ${e.event_id} 的批准人 ${id} 不是案件负责人`);
          }
        }
        break;
      }
      default:
        add(`事件 ${e.event_id} 使用了未知动作 ${e.action}`);
    }
  }

  // 已声明身份关联的线索，必须有 lead-linked 事件。
  for (const lead of v.leads) {
    if (lead.linked_core_entry_ids?.length && !linkedLeads.has(lead.lead_id)) {
      add(`线索 ${lead.lead_id} 已声明身份关联，但日志中没有 lead-linked 事件`);
    }
  }
  return eventsById;
}

function accessMaterialIds(payload) {
  if (Array.isArray(payload.material_ids)) return payload.material_ids;
  return payload.material_id ? [payload.material_id] : [];
}

function checkAccessEvent(e, ctx, state) {
  const { materials, persons, grants } = ctx;
  const { openedCompartments, frozenCompartments, revokedGrants, add } = state;
  const p = e.payload ?? {};
  const ids = accessMaterialIds(p);
  if (ids.length === 0) { add(`事件 ${e.event_id} 没有指定任何材料`); return; }

  // 整次访问涉及的舱位必须全部已解封、未冻结。
  const compartmentsTouched = new Set(ids.map((id) => materials.get(id)?.compartment_id).filter(Boolean));
  for (const cid of compartmentsTouched) {
    if (!openedCompartments.has(cid)) add(`事件 ${e.event_id} 在舱位 ${cid} 解封前访问材料`);
    if (frozenCompartments.has(cid)) add(`舱位 ${cid} 处于紧急止损冻结中，事件 ${e.event_id} 仍发生访问`);
  }

  for (const mid of ids) {
    const m = materials.get(mid);
    if (!m) { add(`事件 ${e.event_id} 操作了不存在的材料 ${mid}`); continue; }

    // 核心名单条目只能被持有 core_clearance 授权的成员在有效期内访问，
    // 且授权动作必须覆盖当前操作；普通舱位授权不覆盖核心材料。
    if (m.core_entry_id) {
      const actionMap = { view: 'view', excerpt: 'excerpt', transfer: 'transfer' };
      const ok = grantsListFor(e.actor, m.compartment_id, grants)
        .filter((g) => !revokedGrants.has(g.grant_id))
        .some((g) =>
        g.core_clearance === true &&
        g.actions.includes(actionMap[e.action]) &&
        (!g.valid_from || e.at >= g.valid_from) &&
        (!g.expires_at || e.at < g.expires_at));
      if (!ok) add(`事件 ${e.event_id} 的行为人 ${e.actor} 对核心材料 ${mid} 没有覆盖 ${e.action} 的核心名单授权`);
    } else {
      const actionMap = { view: 'view', excerpt: 'excerpt', transfer: 'transfer' };
      const allowed = grantsListFor(e.actor, m.compartment_id, grants)
        .filter((g) => !revokedGrants.has(g.grant_id))
        .some((g) => {
        if (!g.actions.includes(actionMap[e.action])) return false;
        if (g.valid_from && e.at < g.valid_from) return false;
        if (g.expires_at && e.at >= g.expires_at) return false; // 到期立即失效
        if (g.core_clearance === true) return false; // 核心专用授权不用于普通材料之外的越权推断
        return true;
      });
      if (!allowed) {
        add(`事件 ${e.event_id} 的行为人 ${e.actor} 对舱位 ${m.compartment_id} 没有覆盖 ${e.action} 的有效授权`);
      }
    }
  }

  // 转交必须指定接收人；接收不生成访问，但必须有跨部门回执（在回执校验中处理）。
  if (e.action === 'transfer') {
    const actor = persons.get(e.actor);
    const recipient = persons.get(p.recipient_id);
    if (!recipient) add(`转交事件 ${e.event_id} 缺少有效接收人`);
    if (actor && p.from_unit !== actor.unit) {
      add(`转交事件 ${e.event_id} 的转出单位 ${p.from_unit} 与行为人 ${e.actor} 实际所属单位不符`);
    }
    if (recipient && p.to_unit !== recipient.unit) {
      add(`转交事件 ${e.event_id} 的接收单位 ${p.to_unit} 与接收人 ${p.recipient_id} 实际所属单位不符`);
    }
    if (p.from_unit === p.to_unit) add(`转交事件 ${e.event_id} 的双方单位相同，不构成跨部门转交`);
  }
  if (e.action === 'excerpt') {
    if (!p.excerpt_ref) add(`摘录事件 ${e.event_id} 缺少 excerpt_ref`);
    if (ids.length !== 1) add(`摘录事件 ${e.event_id} 只能针对单份材料`);
  }
}

function grantsListFor(personId, compartmentId, grants) {
  return [...grants.values()].filter((g) => g.person_id === personId && g.compartment_id === compartmentId);
}

function evaluateConditions(conditions, { batchActive, at, approvals }) {
  if (!conditions.length) return false;
  return conditions.every((cond) => {
    if (cond.type === 'batch_activated') {
      const activatedAt = batchActive.get(cond.batch_id);
      return activatedAt !== undefined && activatedAt <= at;
    }
    if (cond.type === 'scheduled') return at >= cond.at;
    if (cond.type === 'manual') {
      return Boolean(cond.approval_event_ids && cond.approval_event_ids.length >= 2) ||
        (approvals ? [...cond.approver_ids].every((id) => approvals.has(id)) : false);
    }
    return false;
  });
}

// ---- 跨部门回执：每份跨部门转交都必须有回执，且回执晚于转交 --------------------------

function checkReceipts(ctx, add, eventsById) {
  const { v } = ctx;
  const transfers = v.events.filter((e) => e.action === 'transfer');
  const receiptsByEvent = new Map(v.receipts.map((r) => [r.transfer_event_id, r]));
  for (const t of transfers) {
    const r = receiptsByEvent.get(t.event_id);
    if (!r) { add(`转交事件 ${t.event_id} 缺少跨部门回执`); continue; }
    if (!r.received_at || r.received_at < t.at) add(`回执 ${r.receipt_id} 早于或缺失接收时间`);
    if (!r.receiver_confirmed) add(`回执 ${r.receipt_id} 未经接收方确认`);
    if (r.materials_hash !== sha256(JSON.stringify(accessMaterialIds(t.payload).slice().sort()))) {
      add(`回执 ${r.receipt_id} 的材料清单摘要与转交事件不符`);
    }
  }
  for (const r of v.receipts) {
    if (!eventsById.has(r.transfer_event_id)) add(`回执 ${r.receipt_id} 引用了不存在的事件 ${r.transfer_event_id}`);
  }
}

// ---- 结案报告：谁在何时依据什么获知哪些范围 ----------------------------------------

function checkClosure(ctx, add, eventsById) {
  const { v, persons, materials } = ctx;
  const closure = v.closure;
  if (!closure.report_at) add('结案报告缺少 report_at');

  // 从日志重建“获知范围”：每个 view 事件产生一条获知记录的依据。
  const actualKnowledge = new Map(); // person|material -> 最早的查看事件
  for (const e of v.events) {
    if (e.action !== 'view') continue;
    for (const mid of accessMaterialIds(e.payload)) {
      const key = `${e.actor}|${mid}`;
      const prev = actualKnowledge.get(key);
      if (!prev || e.at < prev.at) actualKnowledge.set(key, e);
    }
  }

  for (const entry of closure.knowledge_report ?? []) {
    if (!persons.has(entry.person_id)) add(`获知报告引用了不存在的人员 ${entry.person_id}`);
    for (const scope of entry.scopes ?? []) {
      for (const mid of scope.material_ids ?? []) {
        if (!materials.has(mid)) add(`获知报告中材料 ${mid} 不存在`);
        const key = `${entry.person_id}|${mid}`;
        const ev = actualKnowledge.get(key);
        if (!ev) {
          add(`获知报告声称 ${entry.person_id} 获知 ${mid}，但日志中没有对应查看事件`);
          continue;
        }
        if (scope.first_seen_at !== ev.at) {
          add(`获知报告中 ${entry.person_id} 对 ${mid} 的首次获知时间与日志事件 ${ev.event_id} 不符`);
        }
        if (scope.basis_event_id !== ev.event_id) {
          add(`获知报告中 ${entry.person_id} 对 ${mid} 的获知依据事件不正确`);
        }
        if (!eventsById.has(scope.basis_event_id)) add(`获知依据事件 ${scope.basis_event_id} 不存在`);
      }
    }
  }

  // 反向核对：日志里所有查看都必须出现在报告中。
  const reported = new Set();
  for (const entry of closure.knowledge_report ?? []) {
    for (const scope of entry.scopes ?? []) for (const mid of scope.material_ids ?? []) reported.add(`${entry.person_id}|${mid}`);
  }
  for (const key of actualKnowledge.keys()) {
    if (!reported.has(key)) add(`查看记录 ${key} 未纳入结案获知范围报告`);
  }

  // 来源关系说明：公开检查材料 → 专案证据 → 起诉副本必须在报告中点明，
  // 且摘要中列出的链路要与材料的 derived_from 边一致。
  const lineage = closure.provenance_summary ?? [];
  for (const m of v.materials) {
    if (m.classification === 'prosecution-copy' && !lineage.some((l) => l.prosecution_material_id === m.material_id)) {
      add(`起诉副本 ${m.material_id} 未在 provenance_summary 中交代来源关系`);
    }
  }
  for (const line of lineage) {
    const target = materials.get(line.prosecution_material_id);
    if (!target) { add(`来源摘要引用了不存在的起诉副本 ${line.prosecution_material_id}`); continue; }
    if (target.classification !== 'prosecution-copy') {
      add(`来源摘要条目 ${line.prosecution_material_id} 不是起诉副本`);
    }
    const sources = line.sources ?? [];
    if (sources.length < 2) add(`起诉副本 ${line.prosecution_material_id} 的来源链至少要包含副本本身与上游材料`);
    for (const s of sources) {
      const sm = materials.get(s.material_id);
      if (!sm) { add(`来源摘要中材料 ${s.material_id} 不存在`); continue; }
      if (sm.classification !== s.classification) {
        add(`来源摘要中 ${s.material_id} 的分类标注与材料登记不一致`);
      }
    }
    // 摘要中除副本本身外的每个上游材料，都必须能沿 derived_from 图真实到达。
    for (let i = 1; i < sources.length; i++) {
      if (!reaches(line.prosecution_material_id, sources[i].material_id, materials)) {
        add(`来源摘要声称 ${line.prosecution_material_id} 可追溯到 ${sources[i].material_id}，但 derived_from 图中不存在该路径`);
      }
    }
    // 链路必须覆盖至少一条公开检查材料，交代“公开检查 → 专案证据”的转化。
    if (!sources.some((s) => s.classification === 'public-inspection')) {
      add(`起诉副本 ${line.prosecution_material_id} 的来源链未追溯到公开检查材料`);
    }
  }
}

function reaches(fromId, toId, materials, seen = new Set()) {
  if (fromId === toId) return true;
  if (seen.has(fromId)) return false;
  seen.add(fromId);
  const m = materials.get(fromId);
  return (m?.derived_from ?? []).some((ref) => reaches(ref.material_id, toId, materials, seen));
}
