#!/usr/bin/env node
// Reconstructs, from a series of /api/export snapshots, the two statistics the
// radar does not persist itself:
//
//   1. per-check failure rates, split by "failed on a known bad value" vs
//      "failed because the field was unknown" — the split that says whether a
//      threshold is screening tokens or just missing data;
//   2. a survivorship-corrected view of shadow performance, by treating a
//      horizon that stays unresolved (with no later horizon ever resolving) as
//      a censored-low observation rather than as missing at random.
//
// Read ops/README.md for what these numbers can and cannot support.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const snapshotDir = process.env.RADAR_SNAPSHOT_DIR || path.join(ROOT, 'snapshots');
const HORIZONS = Object.freeze({ m5: 300_000, m15: 900_000, m30: 1_800_000, h1: 3_600_000, h2: 7_200_000, h6: 21_600_000, h24: 86_400_000 });
const HORIZON_ORDER = Object.entries(HORIZONS).sort((a, b) => a[1] - b[1]).map(([key]) => key);

// Mirrors the prefix map in scanner.mjs classifyDeepResult(). Kept as a copy on
// purpose: this script reads exported JSON and must not import scanner state.
const UNKNOWN_PREFIXES = Object.freeze({
  openSource: ['openSource'],
  ownerRenounced: ['ownerRenounced', 'renouncedMint', 'renouncedFreezeAccount'],
  lpLocked: ['lockRate'], notHoneypot: ['honeypot', 'sellability.'], tax: ['buyTax', 'sellTax'],
  rug: ['rugRatio'], concentration: ['top10'], dev: ['devHold'], insider: ['insider'],
  bundler: ['bundler'], sniper: ['sniperHold'], wash: ['wash'], liquidity: ['liquidity'],
  wallets: ['holders.'], observation: ['candles']
});

function loadSnapshots(dir) {
  if (!fs.existsSync(dir)) throw new Error(`no snapshot directory at ${dir}`);
  const files = fs.readdirSync(dir, { recursive: true })
    .filter(name => String(name).endsWith('.json.gz'))
    .map(name => path.join(dir, String(name)));
  const rows = [];
  for (const file of files) {
    try {
      rows.push(JSON.parse(zlib.gunzipSync(fs.readFileSync(file)).toString('utf8')));
    } catch {
      process.stderr.write(`skipped unreadable snapshot ${path.relative(ROOT, file)}\n`);
    }
  }
  return rows.sort((a, b) => (a.exportedAt || 0) - (b.exportedAt || 0));
}

// One audit result = one (chain, address, reviewRevision). The revision hash
// changes whenever any judged field changes, so this de-duplicates the same
// verdict appearing in many snapshots without collapsing genuine re-audits.
function collectAudits(snapshots) {
  const audits = new Map();
  for (const snapshot of snapshots) {
    for (const [chain, scope] of Object.entries(snapshot.chains || {})) {
      for (const row of scope.candidates || []) {
        const revision = row.reviewRevision || `norev:${row.auditedAt || 0}`;
        audits.set(`${chain}:${row.address}:${revision}`, { chain, row });
      }
    }
  }
  return [...audits.values()];
}

function checkReport(audits) {
  const stats = new Map();
  let truncationRisk = 0;
  for (const { row } of audits) {
    const checks = row.deep?.checks || {};
    const failed = new Set(row.deep?.failed || []);
    const blocking = row.deep?.blockingUnknownFields || [];
    // marketBehavior is absent from the exported `checks` whitelist but does
    // appear in `failed`, so fold it in from there.
    const names = new Set([...Object.keys(checks), ...failed]);
    for (const name of names) {
      const entry = stats.get(name) || { evaluated: 0, failed: 0, failedUnknown: 0 };
      entry.evaluated++;
      const didFail = failed.has(name) || checks[name] === false;
      if (didFail) {
        entry.failed++;
        const prefixes = UNKNOWN_PREFIXES[name] || [];
        if (blocking.some(field => prefixes.some(prefix => field === prefix || field.startsWith(prefix)))) {
          entry.failedUnknown++;
        }
      }
      stats.set(name, entry);
    }
  }
  return { stats, truncationRisk };
}

// Follows one outcome row across snapshots and decides, per horizon, whether it
// resolved, is still pending, or should be treated as censored-low.
function outcomeHistory(snapshots) {
  const rows = new Map();
  for (const snapshot of snapshots) {
    for (const [chain, scope] of Object.entries(snapshot.chains || {})) {
      for (const row of scope.outcomes || []) {
        const key = `${chain}:${row.address}`;
        const existing = rows.get(key) || {
          chain, address: row.address, symbol: row.symbol,
          baselineAt: row.baselineAt, baselinePrice: row.baselinePrice,
          initialDecision: row.initialDecision, samples: {}, lastSeenAt: 0
        };
        for (const horizon of HORIZON_ORDER) {
          const sample = row.samples?.[horizon];
          if (sample && Number.isFinite(sample.return) && !existing.samples[horizon]) {
            existing.samples[horizon] = sample;
          }
        }
        existing.lastSeenAt = Math.max(existing.lastSeenAt, snapshot.exportedAt || 0);
        rows.set(key, existing);
      }
    }
  }
  return [...rows.values()];
}

// A horizon counts as censored-low only when the token was observed well past
// its due time and never resolved at that horizon OR at any later one. A later
// resolution proves the token was still trading, which makes the earlier hole a
// data gap rather than a death.
const SETTLE_MS = 3 * 60 * 60_000;

function censoredHorizons(row) {
  const censored = new Set();
  for (let i = 0; i < HORIZON_ORDER.length; i++) {
    const horizon = HORIZON_ORDER[i];
    if (row.samples[horizon]) continue;
    const due = row.baselineAt + HORIZONS[horizon];
    if (row.lastSeenAt < due + SETTLE_MS) continue;
    if (HORIZON_ORDER.slice(i + 1).some(later => row.samples[later])) continue;
    censored.add(horizon);
  }
  return censored;
}

function median(values) {
  if (!values.length) return null;
  return (values[Math.floor((values.length - 1) / 2)] + values[Math.floor(values.length / 2)]) / 2;
}

function cohortReport(rows, decision, now) {
  return Object.fromEntries(HORIZON_ORDER.map(horizon => {
    const cohort = rows.filter(row => row.initialDecision === decision
      && now >= row.baselineAt + HORIZONS[horizon]);
    const values = cohort.map(row => row.samples[horizon]?.return)
      .filter(Number.isFinite).sort((a, b) => a - b);
    const censored = cohort.filter(row => censoredHorizons(row).has(horizon)).length;
    const n = values.length;
    const total = n + censored;

    // The conservative median needs only the ordering: censored observations sit
    // below every observed value, so they occupy the bottom `censored` slots and
    // never need a fabricated return. A null result means the median itself
    // falls inside the censored region — the strongest possible statement that
    // the optimistic number is an artefact of survivorship.
    const at = index => index < censored ? null : values[index - censored];
    let conservative = null;
    if (total) {
      const lo = at(Math.floor((total - 1) / 2));
      const hi = at(Math.floor(total / 2));
      conservative = lo === null || hi === null ? null : (lo + hi) / 2;
    }
    const lagged = cohort.map(row => row.samples[horizon])
      .filter(Boolean).map(sample => Math.abs(Number(sample.at) - Number(sample.targetAt)))
      .filter(Number.isFinite).sort((a, b) => a - b);

    return [horizon, {
      eligible: cohort.length,
      completed: n,
      censoredLow: censored,
      unresolved: cohort.length - n - censored,
      medianOptimistic: median(values),
      medianConservative: conservative,
      medianInCensoredRegion: conservative === null && censored > 0,
      positiveRateOptimistic: n ? values.filter(value => value > 0).length / n : null,
      positiveRateConservative: total ? values.filter(value => value > 0).length / total : null,
      p90LagMs: lagged.length ? lagged[Math.floor(lagged.length * 0.9)] : null
    }];
  }));
}

const percent = value => value === null ? '     —' : `${(value * 100).toFixed(1).padStart(6)}%`;
const count = value => String(value).padStart(5);

const snapshots = loadSnapshots(snapshotDir);
if (!snapshots.length) throw new Error(`no snapshots found under ${snapshotDir}`);
const now = snapshots.at(-1).exportedAt || Date.now();
const spanHours = ((now - (snapshots[0].exportedAt || now)) / 3_600_000).toFixed(1);

console.log(`\n快照 ${snapshots.length} 份，跨度 ${spanHours} 小时，最新 ${new Date(now).toISOString()}\n`);

const audits = collectAudits(snapshots);
const { stats } = checkReport(audits);
console.log(`== 每项 check 的失败率（去重后 ${audits.length} 个审计结果）==`);
console.log('check                评估   失败   失败率   其中"因未知"  未知占失败');
for (const [name, entry] of [...stats.entries()].sort((a, b) => b[1].failed - a[1].failed)) {
  const failRate = entry.evaluated ? entry.failed / entry.evaluated : null;
  const unknownShare = entry.failed ? entry.failedUnknown / entry.failed : null;
  console.log(`${name.padEnd(18)}${count(entry.evaluated)}${count(entry.failed)}  ${percent(failRate)}${count(entry.failedUnknown)}        ${percent(unknownShare)}`);
}
console.log('\n  "未知占失败"接近 100% = 该项卡在数据缺失，调阈值无用；接近 0% = 该项真的在筛币。');

const rows = outcomeHistory(snapshots);
for (const [decision, label] of [['X_REVIEW', '通过组'], ['HARD_REJECT', '拒绝组（1/5 抽样）']]) {
  const report = cohortReport(rows, decision, now);
  console.log(`\n== 影子表现 · ${label} ==`);
  console.log('窗口   到期  完成  死亡  未决   乐观中位   保守中位   乐观正收益  保守正收益   p90滞后');
  for (const horizon of HORIZON_ORDER) {
    const r = report[horizon];
    const conservative = r.medianInCensoredRegion ? '  <死亡区' : percent(r.medianConservative);
    const lag = r.p90LagMs === null ? '     —' : `${(r.p90LagMs / 1000).toFixed(0)}s`.padStart(6);
    console.log(`${horizon.padEnd(6)}${count(r.eligible)}${count(r.completed)}${count(r.censoredLow)}${count(r.unresolved)}  ${percent(r.medianOptimistic)}  ${conservative}   ${percent(r.positiveRateOptimistic)}     ${percent(r.positiveRateConservative)}  ${lag}`);
  }
}

const ready = HORIZON_ORDER.filter(horizon => {
  const passed = cohortReport(rows, 'X_REVIEW', now)[horizon];
  return passed.completed >= 50;
});
console.log(`\n达到 50 个完成样本的窗口：${ready.length ? ready.join(', ') : '无'}`);
console.log('样本量不足时上表只用于观察数据管线是否健康，不用于判断筛选是否有效。\n');
