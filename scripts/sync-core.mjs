#!/usr/bin/env node
// Copie packages/core/src/ vers cli/lib/, ainsi que packages/core/data/ vers cli/data/.
//
// Pourquoi ce script existe : `packages/core/src/` est la SEULE source éditable du
// moteur de scan -- on n'édite jamais directement cli/lib/ à la main, pour éviter toute
// divergence silencieuse entre le code source et ce qui est réellement publié sur npm.
//
// Usage : node scripts/sync-core.mjs
// Le workflow CI (.github/workflows/check-core-drift.yml) échoue si quelqu'un modifie
// cli/lib/ sans relancer ce script.

import { readdir, mkdir, copyFile, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, "..");

const CORE_SRC = path.join(ROOT, "packages/core/src");
const CORE_DATA = path.join(ROOT, "packages/core/data");

const TARGETS = [
  { src: path.join(ROOT, "cli/lib"), data: path.join(ROOT, "cli/data") },
];

async function copyDir(srcDir, destDir) {
  await rm(destDir, { recursive: true, force: true });
  await mkdir(destDir, { recursive: true });
  const entries = await readdir(srcDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    await copyFile(path.join(srcDir, entry.name), path.join(destDir, entry.name));
  }
}

for (const target of TARGETS) {
  await copyDir(CORE_SRC, target.src);
  await copyDir(CORE_DATA, target.data);
  console.log(`Synchronisé : ${path.relative(ROOT, target.src)}`);
}

console.log("\nOK -- cli/lib est maintenant une copie exacte de packages/core/src.");
