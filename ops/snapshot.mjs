#!/usr/bin/env node
// Captures one /api/export snapshot. The radar prunes its own state on a
// schedule (candidates 2h, outcomes 7d, events 500), so history only survives
// if it is copied out before those windows close.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const port = Number(process.env.RADAR_PORT || 3791);
const outDir = process.env.RADAR_SNAPSHOT_DIR || path.join(ROOT, 'snapshots');
const host = `127.0.0.1:${port}`;

function fetchExport() {
  return new Promise((resolve, reject) => {
    const req = http.get({
      host: '127.0.0.1', port, path: '/api/export',
      // The radar rejects anything that does not look like a same-origin
      // loopback request; mirror what the dashboard sends.
      headers: { Host: host, Origin: `http://${host}`, Accept: 'application/json' },
      timeout: 20_000
    }, res => {
      let body = '';
      res.on('data', chunk => {
        body += chunk;
        if (body.length > 64 * 1024 * 1024) req.destroy(new Error('export too large'));
      });
      res.on('end', () => res.statusCode === 200
        ? resolve(body)
        : reject(new Error(`export returned ${res.statusCode}`)));
    });
    req.on('timeout', () => req.destroy(new Error('export timed out')));
    req.on('error', reject);
  });
}

const body = await fetchExport();
let parsed;
try { parsed = JSON.parse(body); } catch { throw new Error('export was not valid JSON'); }
if (!parsed || typeof parsed !== 'object' || !parsed.chains) throw new Error('export has no chain scopes');

// A snapshot with no audited candidates is still worth keeping: the absence of
// results at a given minute is itself evidence about scan health.
const at = Number(parsed.exportedAt) || Date.now();
const day = new Date(at).toISOString().slice(0, 10);
const dir = path.join(outDir, day);
fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
const file = path.join(dir, `export-${at}.json.gz`);
fs.writeFileSync(file, zlib.gzipSync(body, { level: 9 }), { mode: 0o600 });

const chains = Object.entries(parsed.chains).map(([id, scope]) =>
  `${id}:${(scope.candidates || []).length}c/${(scope.outcomes || []).length}o`).join(' ');
console.log(`${new Date(at).toISOString()} ${path.relative(ROOT, file)} ${(body.length / 1024).toFixed(0)}KB ${chains} status=${parsed.status}`);
