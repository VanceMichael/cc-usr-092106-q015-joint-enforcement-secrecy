import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseCaseDoc, reseal } from '../src/case.js';

async function loadDoc() {
  const raw = await readFile(new URL('../fixtures/case.json', import.meta.url), 'utf8');
  return JSON.parse(raw);
}

// 对同一份文档做“只改语义、重新封缄哈希”的篡改，以便检验领域规则而不只是哈希链。
function mutate(doc, fn) {
  const copy = structuredClone(doc);
  fn(copy);
  copy.events.forEach((e, i) => { e.seq = i + 1; });
  reseal(copy.events);
  return copy;
}

// 按时间戳把事件插入日志（冻结等状态按日志顺序演进，不能简单追加到末尾）。
function insertEventChronologically(events, event) {
  const pos = events.findIndex((e) => e.at > event.at);
  events.splice(pos === -1 ? events.length : pos, 0, event);
}

test('虚构样例通过全部领域校验', async () => {
  const doc = await loadDoc();
  const parsed = parseCaseDoc(JSON.stringify(doc));
  assert.equal(parsed.domain, 'joint-enforcement-secrecy');
  assert.ok(parsed.events.length >= 20);
});

test('篡改任一事件载荷会破坏哈希链', async () => {
  const doc = await loadDoc();
  const copy = structuredClone(doc);
  copy.events[2].payload = { ...copy.events[2].payload, note: '被篡改的说明' };
  assert.throws(() => parseCaseDoc(JSON.stringify(copy)), /自摘要不匹配/);
});

test('调换两条事件的顺序会断裂 prev_hash 链', async () => {
  const doc = await loadDoc();
  const copy = structuredClone(doc);
  [copy.events[3], copy.events[4]] = [copy.events[4], copy.events[3]];
  // 顺序变动后不改 seq，仅交换位置即应触发序号/链校验
  assert.throws(() => parseCaseDoc(JSON.stringify(copy)), /prev_hash|序号不连续/);
});

test('解封条件未达成不得开启舱位', async () => {
  const doc = await loadDoc();
  const bad = mutate(doc, (d) => {
    // 删除核心舱的两次人工批准事件
    d.events = d.events.filter((e) => e.action !== 'unseal-approval');
  });
  assert.throws(() => parseCaseDoc(JSON.stringify(bad)), /解封条件未达成/);
});

test('扩大核心名单必须有两名不同单位负责人共同批准', async () => {
  const doc = await loadDoc();
  const bad = mutate(doc, (d) => {
    const ev = d.events.find((e) => e.action === 'core-list-expanded');
    ev.payload.approver_ids = ['p-yin', 'p-lu']; // p-lu 不是负责人
  });
  assert.throws(() => parseCaseDoc(JSON.stringify(bad)), /不是案件负责人/);
});

test('普通线索在关联条件（收网批次激活）达成前不得关联专案身份', async () => {
  const doc = await loadDoc();
  const bad = mutate(doc, (d) => {
    // 把线索关联事件提前到批次激活之前
    const link = d.events.find((e) => e.action === 'lead-linked');
    link.at = '2026-03-10T09:00:00+08:00';
  });
  assert.throws(() => parseCaseDoc(JSON.stringify(bad)), /关联条件达成前/);
});

test('收网批次延期后提前激活无效', async () => {
  const doc = await loadDoc();
  const bad = mutate(doc, (d) => {
    const act = d.events.find((e) => e.action === 'batch-activated' && e.payload.batch_id === 'b-raid');
    act.at = '2026-03-17T06:00:00+08:00'; // 延期后 3 月 20 日之前
  });
  assert.throws(() => parseCaseDoc(JSON.stringify(bad)), /提前激活/);
});

test('人员调离后不得再以其名义操作', async () => {
  const doc = await loadDoc();
  const bad = mutate(doc, (d) => {
    // 常烁于 3 月 11 日调离，在其后插入一条以他为行为人的查看
    insertEventChronologically(d.events, {
      event_id: 'ev-x',
      at: '2026-03-12T09:00:00+08:00', actor: 'p-chang',
      action: 'view', payload: { material_ids: ['m-pub-record'] },
    });
  });
  assert.throws(() => parseCaseDoc(JSON.stringify(bad)), /调离/);
});

test('授权到期后访问无效，且历史合法操作仍然保留', async () => {
  const doc = await loadDoc();
  const bad = mutate(doc, (d) => {
    // 常烁的临时授权 3 月 5 日到期；3 月 6 日的摘录应被拒绝
    insertEventChronologically(d.events, {
      event_id: 'ev-x',
      at: '2026-03-06T09:00:00+08:00', actor: 'p-chang',
      action: 'excerpt', payload: { material_ids: ['m-pub-record'], excerpt_ref: '过期后摘录' },
    });
  });
  assert.throws(() => parseCaseDoc(JSON.stringify(bad)), /没有覆盖 excerpt 的有效授权|授权/);

  // 原始文档中其窗口内（3 月 3 日）的摘录仍然合法
  assert.doesNotThrow(() => parseCaseDoc(JSON.stringify(doc)));
});

test('授权被撤销后即时失效，撤销前的合法查看仍在报告中保留', async () => {
  const doc = await loadDoc();
  const bad = mutate(doc, (d) => {
    // 麦琪的例行舱临时授权 3 月 9 日因岗位调整撤销；3 月 10 日再查看应被拒绝
    insertEventChronologically(d.events, {
      event_id: 'ev-x',
      at: '2026-03-10T09:00:00+08:00', actor: 'p-mai',
      action: 'view', payload: { material_ids: ['m-pub-record'] },
    });
  });
  assert.throws(() => parseCaseDoc(JSON.stringify(bad)), /有效授权/);
});

test('紧急止损冻结期间不得访问被封舱材料', async () => {
  const doc = await loadDoc();
  const bad = mutate(doc, (d) => {
    // 在 3 月 20 日 05:30 冻结、次日 18:00 解除之间插入例行舱访问
    insertEventChronologically(d.events, {
      event_id: 'ev-x',
      at: '2026-03-20T10:00:00+08:00', actor: 'p-lu',
      action: 'view', payload: { material_ids: ['m-pub-record'] },
    });
  });
  assert.throws(() => parseCaseDoc(JSON.stringify(bad)), /止损冻结/);
});

test('跨部门转交必须有接收方确认的回执且清单摘要一致', async () => {
  const doc = await loadDoc();
  const copy = structuredClone(doc);
  copy.receipts[0].receiver_confirmed = false;
  assert.throws(() => parseCaseDoc(JSON.stringify(copy)), /未经接收方确认/);

  const copy2 = structuredClone(doc);
  copy2.receipts[0].materials_hash = copy2.receipts[0].materials_hash.replace(/^./, '0');
  assert.throws(() => parseCaseDoc(JSON.stringify(copy2)), /材料清单摘要与转交事件不符/);
});

test('结案获知报告必须与日志查看记录双向一致', async () => {
  const doc = await loadDoc();
  const copy = structuredClone(doc);
  // 删除一条获知报告记录：日志中的查看就无处交代
  copy.closure.knowledge_report[0].scopes.pop();
  assert.throws(() => parseCaseDoc(JSON.stringify(copy)), /未纳入结案获知范围报告|首次获知时间与日志事件不符/);
});

test('起诉副本必须沿来源链回溯到专案证据', async () => {
  const doc = await loadDoc();
  const bad = structuredClone(doc);
  // 直接删掉证据汇编来源，只保留资金分析仍可回溯到专案证据；改成全部指向公开材料则失败
  bad.materials.find((m) => m.material_id === 'm-prosecution-brief').derived_from = [
    { material_id: 'm-pub-record', relation: 'intake' },
  ];
  assert.throws(() => parseCaseDoc(JSON.stringify(bad)), /来源链未回溯到任何专案证据|未在 provenance_summary/);
});

test('公开检查材料不得反向引用专案证据', async () => {
  const doc = await loadDoc();
  const bad = structuredClone(doc);
  bad.materials.find((m) => m.material_id === 'm-pub-record').derived_from = [
    { material_id: 'm-suspect-dossier', relation: 'copy' },
  ];
  assert.throws(() => parseCaseDoc(JSON.stringify(bad)), /不得反向引用/);
});

test('来源摘要中声称的追溯路径必须在 derived_from 图中真实存在', async () => {
  const doc = await loadDoc();
  const bad = structuredClone(doc);
  // 把证据汇编的来源删掉，但保留摘要中“由公开记录转化”的说法 → 图中不可达
  bad.materials.find((m) => m.material_id === 'm-evidence-pack').derived_from = [
    { material_id: 'm-suspect-dossier', relation: 'extract', excerpt_ref: '节录本-0320#第2-5页' },
  ];
  assert.throws(() => parseCaseDoc(JSON.stringify(bad)), /不存在该路径/);
});

test('转交的转出/接收单位必须与双方名册单位一致', async () => {
  const doc = await loadDoc();
  const bad = mutate(doc, (d) => {
    const t = d.events.find((e) => e.action === 'transfer' && e.payload.to_unit.includes('检察'));
    t.payload.from_unit = '云溪城管分局（虚构）';
  });
  assert.throws(() => parseCaseDoc(JSON.stringify(bad)), /实际所属单位不符/);
});
