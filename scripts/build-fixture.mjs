// 构建虚构样例 fixtures/case.json：组装一份端到端的分舱专案约定文档，
// 自动计算事件自摘要、prev_hash 链与跨部门回执的材料清单摘要。
//
// 运行：node scripts/build-fixture.mjs
// 所有人员、单位、账号均为虚构。
import { writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const canonical = (e) => JSON.stringify({ seq: e.seq, at: e.at, actor: e.actor, action: e.action, payload: e.payload ?? {} });

// 在带时区偏移的 ISO 时间戳上加小时数，并以同样的 +08:00 偏移输出。
function plusHoursIso(iso, hours) {
  const ms = new Date(iso).getTime() + hours * 3600000 + 8 * 3600000;
  const d = new Date(ms);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}+08:00`;
}

const U = { yibao: '云溪医保分局', gongan: '云溪公安分局', jiancha: '云溪区检察院' };

const persons = [
  { person_id: 'p-yin', name: '殷岚（虚构）', unit: U.yibao, role_ids: ['r-director'] },
  { person_id: 'p-hao', name: '郝建（虚构）', unit: U.gongan, role_ids: ['r-director'] },
  { person_id: 'p-lu', name: '卢笛（虚构）', unit: U.yibao, role_ids: ['r-field-checker'] },
  { person_id: 'p-xing', name: '邢默（虚构）', unit: U.gongan, role_ids: ['r-investigator'] },
  { person_id: 'p-mai', name: '麦琪（虚构）', unit: U.gongan, role_ids: ['r-investigator', 'r-analyst'] },
  { person_id: 'p-chang', name: '常烁（虚构）', unit: U.gongan, role_ids: ['r-auxiliary'], transferred_away_at: '2026-03-11T00:00:00+08:00' },
  { person_id: 'p-kuang', name: '邝介（虚构）', unit: U.jiancha, role_ids: ['r-prosecutor'] },
];

const roles = [
  { role_id: 'r-director', name: '案件负责人' },
  { role_id: 'r-field-checker', name: '基层核查员' },
  { role_id: 'r-investigator', name: '侦查员' },
  { role_id: 'r-analyst', name: '资金分析员' },
  { role_id: 'r-auxiliary', name: '辅警钟点工' },
  { role_id: 'r-prosecutor', name: '检察承办人' },
];

const compartments = [
  {
    compartment_id: 'c-routine',
    name: '日常检查舱',
    owner_ids: ['p-yin'],
    unseal_conditions: [{ type: 'scheduled', at: '2026-03-02T08:00:00+08:00' }],
  },
  {
    compartment_id: 'c-core',
    name: '核心侦查舱（嫌疑人/仓库/资金身份）',
    owner_ids: ['p-yin', 'p-hao'],
    unseal_conditions: [{ type: 'manual', approver_ids: ['p-yin', 'p-hao'] }],
  },
  {
    compartment_id: 'c-finance',
    name: '资金分析舱',
    owner_ids: ['p-hao'],
    unseal_conditions: [{ type: 'batch_activated', batch_id: 'b-raid' }],
  },
  {
    compartment_id: 'c-prosecution',
    name: '起诉移送舱',
    owner_ids: ['p-hao'],
    unseal_conditions: [{ type: 'scheduled', at: '2026-03-25T09:00:00+08:00' }],
  },
];

const batches = [
  { batch_id: 'b-routine', name: '一季度例行稽核批次', compartment_id: 'c-routine', planned_at: '2026-03-02T08:00:00+08:00' },
  { batch_id: 'b-raid', name: '同步收网批次', compartment_id: 'c-core', planned_at: '2026-03-16T06:00:00+08:00' },
];

const core_entries = [
  { entry_id: 'ce-suspect-a', kind: 'suspect', label: '嫌疑人甲（虚构代号“郎中”）', initial: true },
  { entry_id: 'ce-warehouse-a', kind: 'warehouse', label: '枫林里假票据仓库（虚构地点）', initial: true },
  { entry_id: 'ce-fund-a', kind: 'fund-account', label: '过桥账户组 F-07（虚构账号）', initial: true },
  { entry_id: 'ce-suspect-b', kind: 'suspect', label: '嫌疑人乙（虚构代号“账房”）', initial: false, added_via_event_id: 'ev-013' },
];

const materials = [
  {
    material_id: 'm-pub-record',
    name: '枫林里药店日常检查记录（虚构）',
    classification: 'public-inspection',
    compartment_id: 'c-routine',
  },
  {
    material_id: 'm-suspect-dossier',
    name: '嫌疑人甲侦控卷宗（虚构）',
    classification: 'case-evidence',
    compartment_id: 'c-core',
    core_entry_id: 'ce-suspect-a',
  },
  {
    material_id: 'm-warehouse-watch',
    name: '仓库蹲守影像清单（虚构）',
    classification: 'case-evidence',
    compartment_id: 'c-core',
    core_entry_id: 'ce-warehouse-a',
  },
  {
    material_id: 'm-fund-flow',
    name: 'F-07 资金流向分析（虚构）',
    classification: 'case-evidence',
    compartment_id: 'c-finance',
    core_entry_id: 'ce-fund-a',
  },
  {
    material_id: 'm-evidence-pack',
    name: '移送公安证据汇编（虚构）',
    classification: 'case-evidence',
    compartment_id: 'c-core',
    core_entry_id: 'ce-suspect-a',
    derived_from: [
      { material_id: 'm-suspect-dossier', relation: 'extract', excerpt_ref: '节录本-0320#第2-5页' },
      { material_id: 'm-pub-record', relation: 'intake' },
    ],
  },
  {
    material_id: 'm-prosecution-brief',
    name: '起诉意见书附证据副本（虚构）',
    classification: 'prosecution-copy',
    compartment_id: 'c-prosecution',
    derived_from: [
      { material_id: 'm-evidence-pack', relation: 'copy' },
      { material_id: 'm-fund-flow', relation: 'copy' },
    ],
  },
];

const leads = [
  {
    lead_id: 'l-fenglin-pharmacy',
    name: '枫林里药店刷卡异常线索（虚构）',
    compartment_id: 'c-routine',
    linked_core_entry_ids: ['ce-suspect-a'],
    link_condition: { type: 'batch_activated', batch_id: 'b-raid' },
  },
];

const grants = [
  // 日常检查舱
  { grant_id: 'g-yin-routine', person_id: 'p-yin', compartment_id: 'c-routine', actions: ['view', 'grant-temp'] },
  { grant_id: 'g-lu-routine', person_id: 'p-lu', compartment_id: 'c-routine', actions: ['view', 'excerpt'] },
  {
    grant_id: 'g-chang-temp', person_id: 'p-chang', compartment_id: 'c-routine', actions: ['excerpt'],
    temp: true, valid_from: '2026-03-03T08:30:00+08:00', expires_at: '2026-03-05T18:00:00+08:00', basis_event_id: 'ev-004',
  },
  {
    grant_id: 'g-mai-temp', person_id: 'p-mai', compartment_id: 'c-routine', actions: ['view'],
    temp: true, valid_from: '2026-03-08T09:00:00+08:00', expires_at: '2026-03-12T18:00:00+08:00', basis_event_id: 'ev-006',
  },
  // 核心侦查舱
  { grant_id: 'g-yin-core', person_id: 'p-yin', compartment_id: 'c-core', actions: ['view', 'transfer'], core_clearance: true },
  {
    grant_id: 'g-xing-core', person_id: 'p-xing', compartment_id: 'c-core',
    actions: ['view', 'excerpt', 'transfer', 'grant-temp'], core_clearance: true,
  },
  {
    grant_id: 'g-mai-core-temp', person_id: 'p-mai', compartment_id: 'c-core', actions: ['view'],
    core_clearance: true, temp: true,
    valid_from: '2026-03-19T10:00:00+08:00', expires_at: '2026-03-21T10:00:00+08:00', basis_event_id: 'ev-014',
  },
  // 资金分析舱
  { grant_id: 'g-mai-finance', person_id: 'p-mai', compartment_id: 'c-finance', actions: ['view'], core_clearance: true },
  // 起诉移送舱
  { grant_id: 'g-xing-prosecution', person_id: 'p-xing', compartment_id: 'c-prosecution', actions: ['transfer'] },
];

// 先以占位 id 列出事件，最后统一编号并封缄。
const rawEvents = [
  ['2026-03-02T08:00:00+08:00', 'p-yin', 'compartment-unsealed', { compartment_id: 'c-routine' }],
  ['2026-03-02T08:05:00+08:00', 'p-yin', 'batch-activated', { batch_id: 'b-routine' }],
  ['2026-03-02T09:12:00+08:00', 'p-lu', 'view', { material_ids: ['m-pub-record'], note: '日常检查前调阅药店档案' }],
  // 常烁的临时授权：窗口内合法摘录，到期自动失效，随后调离。
  ['2026-03-03T08:30:00+08:00', 'p-yin', 'temp-grant',
    { grant_id: 'g-chang-temp', compartment_id: 'c-routine', justification: '协助摘录近三个月刷卡台账，限两个工作日' }],
  ['2026-03-03T09:05:00+08:00', 'p-chang', 'excerpt',
    { material_ids: ['m-pub-record'], excerpt_ref: '台账摘录-0303' }],
  // 麦琪的临时授权：窗口内查看一次，随后因岗位调整即时撤销；历史操作保留。
  ['2026-03-08T09:00:00+08:00', 'p-yin', 'temp-grant',
    { grant_id: 'g-mai-temp', compartment_id: 'c-routine', justification: '交叉比对票据线索，限当日至 3 月 12 日' }],
  ['2026-03-08T09:20:00+08:00', 'p-mai', 'view', { material_ids: ['m-pub-record'], note: '比对异常票据样式' }],
  ['2026-03-09T14:00:00+08:00', 'p-yin', 'grant-revoked',
    { grant_id: 'g-mai-temp', reason: '岗位调整，即时收回例行舱权限；此前操作记录保留' }],
  // 收网延期：原 3 月 16 日推迟到 3 月 20 日清晨。
  ['2026-03-12T17:30:00+08:00', 'p-hao', 'batch-postponed',
    { batch_id: 'b-raid', new_at: '2026-03-20T06:00:00+08:00', reason: '等待跨区仓储点同时具备收网条件' }],
  // 核心舱：两名不同单位负责人分别批准后解封。
  ['2026-03-18T15:00:00+08:00', 'p-yin', 'unseal-approval', { compartment_id: 'c-core' }],
  ['2026-03-18T15:10:00+08:00', 'p-hao', 'unseal-approval', { compartment_id: 'c-core' }],
  ['2026-03-18T15:15:00+08:00', 'p-hao', 'compartment-unsealed', { compartment_id: 'c-core' }],
  // 扩大核心名单：双负责人共同批准。
  ['2026-03-18T16:00:00+08:00', 'p-hao', 'core-list-expanded',
    { entry_ids: ['ce-suspect-b'], approver_ids: ['p-yin', 'p-hao'], justification: '资金对手方身份经串并确认' }],
  // 给麦琪开核心舱短窗口，用于核对新增嫌疑人，窗口到期自动失效。
  ['2026-03-19T10:00:00+08:00', 'p-xing', 'temp-grant',
    { grant_id: 'g-mai-core-temp', compartment_id: 'c-core', justification: '突击核对“账房”与仓库影像是否同人，48 小时内有效' }],
  ['2026-03-19T10:40:00+08:00', 'p-mai', 'view',
    { material_ids: ['m-suspect-dossier', 'm-warehouse-watch'], note: '人相比对' }],
  // 收网前夜紧急止损：冻结日常检查舱，防止例行询问走漏风声。
  ['2026-03-20T05:30:00+08:00', 'p-yin', 'emergency-freeze',
    { compartment_id: 'c-routine', reason: '接到线索称团伙在被检查机构布点，收网前暂停一切例行查阅' }],
  ['2026-03-20T06:00:00+08:00', 'p-hao', 'batch-activated', { batch_id: 'b-raid' }],
  ['2026-03-20T06:05:00+08:00', 'p-hao', 'compartment-unsealed', { compartment_id: 'c-finance' }],
  // 普通线索只在收网批次激活后才与专案身份关联。
  ['2026-03-20T06:10:00+08:00', 'p-xing', 'lead-linked',
    { lead_id: 'l-fenglin-pharmacy', core_entry_ids: ['ce-suspect-a'] }],
  ['2026-03-20T06:30:00+08:00', 'p-xing', 'view',
    { material_ids: ['m-suspect-dossier', 'm-warehouse-watch'], note: '抓捕前最后核对' }],
  ['2026-03-20T07:00:00+08:00', 'p-mai', 'view', { material_ids: ['m-fund-flow'], note: '同步冻结账户清单' }],
  ['2026-03-20T07:30:00+08:00', 'p-xing', 'excerpt',
    { material_ids: ['m-suspect-dossier'], excerpt_ref: '节录本-0320#第2-5页' }],
  // 收网结束，解除日常舱冻结，例行工作恢复。
  ['2026-03-21T18:00:00+08:00', 'p-yin', 'freeze-lifted', { compartment_id: 'c-routine' }],
  ['2026-03-22T09:00:00+08:00', 'p-lu', 'view', { material_ids: ['m-pub-record'], note: '恢复例行检查' }],
  // 跨部门转交：医保 → 公安，附接收回执。
  ['2026-03-22T15:00:00+08:00', 'p-yin', 'transfer',
    { material_ids: ['m-evidence-pack'], recipient_id: 'p-hao', from_unit: U.yibao, to_unit: U.gongan }],
  // 起诉移送舱按计划解封；公安 → 检察院的起诉副本转交。
  ['2026-03-25T09:00:00+08:00', 'p-hao', 'compartment-unsealed', { compartment_id: 'c-prosecution' }],
  ['2026-03-26T10:00:00+08:00', 'p-xing', 'transfer',
    { material_ids: ['m-prosecution-brief'], recipient_id: 'p-kuang', from_unit: U.gongan, to_unit: U.jiancha }],
];

const events = [];
let prevHash = null;
rawEvents.forEach(([at, actor, action, payload], i) => {
  const partial = { event_id: `ev-${String(i + 1).padStart(3, '0')}`, seq: i + 1, at, actor, action, payload, prev_hash: prevHash };
  const hash = sha256(canonical(partial));
  events.push({ ...partial, hash });
  prevHash = hash;
});

// 从日志重建跨部门转交回执。
const receipts = events
  .filter((e) => e.action === 'transfer')
  .map((e) => ({
    receipt_id: `rcpt-${e.event_id}`,
    transfer_event_id: e.event_id,
    received_at: plusHoursIso(e.at, 1),
    materials_hash: sha256(JSON.stringify(e.payload.material_ids.slice().sort())),
    receiver_confirmed: true,
  }));

// 从查看事件重建“谁在何时依据什么获知哪些范围”。
const firstView = new Map();
for (const e of events) {
  if (e.action !== 'view') continue;
  for (const mid of e.payload.material_ids) {
    const key = `${e.actor}|${mid}`;
    if (!firstView.has(key)) firstView.set(key, e);
  }
}
const knowledge_report = [];
for (const person of persons) {
  const scopes = [];
  for (const [key, e] of firstView) {
    if (!key.startsWith(`${person.person_id}|`)) continue;
    const material_id = key.split('|')[1];
    scopes.push({ first_seen_at: e.at, basis_event_id: e.event_id, material_ids: [material_id] });
  }
  scopes.sort((a, b) => (a.first_seen_at < b.first_seen_at ? -1 : 1));
  if (scopes.length) knowledge_report.push({ person_id: person.person_id, scopes });
}

const doc = {
  domain: 'joint-enforcement-secrecy',
  version: 2,
  sample_id: 'sample-015',
  case_file: {
    case_id: '虚构案-2026-云溪-07',
    title: '云溪“杏林回春”虚构骗保专案（全部要素虚构）',
    director_ids: ['p-yin', 'p-hao'],
    core_entries,
  },
  roles,
  persons,
  compartments,
  batches,
  materials,
  leads,
  grants,
  events,
  receipts,
  closure: {
    report_at: '2026-03-30T17:00:00+08:00',
    knowledge_report,
    provenance_summary: [
      {
        prosecution_material_id: 'm-prosecution-brief',
        sources: [
          { material_id: 'm-prosecution-brief', classification: 'prosecution-copy' },
          { material_id: 'm-evidence-pack', classification: 'case-evidence', via: 'copy' },
          { material_id: 'm-fund-flow', classification: 'case-evidence', via: 'copy' },
          { material_id: 'm-suspect-dossier', classification: 'case-evidence', via: 'extract：节录本-0320#第2-5页' },
          { material_id: 'm-pub-record', classification: 'public-inspection', via: 'intake：例行检查材料转化入卷' },
        ],
      },
    ],
  },
};

await writeFile(new URL('../fixtures/case.json', import.meta.url), `${JSON.stringify(doc, null, 2)}\n`, 'utf8');
console.log(`已生成 fixtures/case.json：${events.length} 条事件、${receipts.length} 份回执、${knowledge_report.length} 人列入获知报告`);
