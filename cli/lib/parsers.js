import { readFile } from "node:fs/promises";
import path from "node:path";
import {
  extractPep621Dependencies,
  extractPoetryDependencies,
  extractCargoDependencies,
  extractGoModules,
  extractGemfileDependencies,
  extractMavenDependencies,
} from "./format-lite.js";

// Extract { name, ecosystem, source } entries from package.json
export async function parseNpm(dir) {
  const filePath = path.join(dir, "package.json");
  let raw;
  try {
    raw = await readFile(filePath, "utf8");
  } catch {
    return [];
  }
  let json;
  try {
    json = JSON.parse(raw);
  } catch {
    return { error: `Impossible de parser ${filePath} (JSON invalide)` };
  }
  const groups = ["dependencies", "devDependencies", "optionalDependencies"];
  const seen = new Map();
  for (const group of groups) {
    const deps = json[group];
    if (!deps) continue;
    for (const name of Object.keys(deps)) {
      // skip local/workspace/git deps -- not registry-checkable
      const version = deps[name];
      if (
        typeof version === "string" &&
        (version.startsWith("file:") ||
          version.startsWith("link:") ||
          version.startsWith("git") ||
          version.startsWith("workspace:"))
      ) {
        continue;
      }
      if (!seen.has(name)) {
        // [13/09/2026] `version` conservée pour le SBOM (--sbom) -- c'est la contrainte
        // déclarée dans package.json (ex: "^4.17.21"), pas une version résolue depuis
        // package-lock.json/pnpm-lock.yaml (non lus par ce parseur).
        seen.set(name, { name, ecosystem: "npm", source: group, version: typeof version === "string" ? version : null });
      }
    }
  }
  return [...seen.values()];
}

// Extract { name, ecosystem, source } entries from requirements.txt
export async function parsePip(dir) {
  const filePath = path.join(dir, "requirements.txt");
  let raw;
  try {
    raw = await readFile(filePath, "utf8");
  } catch {
    return [];
  }
  const results = [];
  const lines = raw.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    // strip version specifiers / extras / environment markers
    const name = line
      .split(/[=<>!~\s;\[]/)[0]
      .trim()
      .toLowerCase();
    // [13/09/2026] Contrainte de version pour le SBOM -- tout ce qui suit le nom sur la
    // ligne (ex: "requests==2.31.0" -> "==2.31.0"), null si aucune contrainte déclarée.
    const versionPart = name ? line.slice(name.length).trim() : "";
    if (name) results.push({ name, ecosystem: "pypi", source: "requirements.txt", version: versionPart || null });
  }
  return results;
}

// Extract { name, ecosystem, source } entries from pyproject.toml (PEP 621 et/ou Poetry)
export async function parsePyproject(dir) {
  const filePath = path.join(dir, "pyproject.toml");
  let raw;
  try {
    raw = await readFile(filePath, "utf8");
  } catch {
    return [];
  }
  const seen = new Map();
  for (const dep of [...extractPep621Dependencies(raw), ...extractPoetryDependencies(raw)]) {
    if (!seen.has(dep.name)) seen.set(dep.name, { name: dep.name, ecosystem: "pypi", source: "pyproject.toml", version: dep.version });
  }
  return [...seen.values()];
}

// Extract { name, ecosystem, source } entries from Cargo.toml
export async function parseCargo(dir) {
  const filePath = path.join(dir, "Cargo.toml");
  let raw;
  try {
    raw = await readFile(filePath, "utf8");
  } catch {
    return [];
  }
  const seen = new Map();
  for (const dep of extractCargoDependencies(raw)) {
    if (!seen.has(dep.name)) seen.set(dep.name, { name: dep.name, ecosystem: "cratesio", source: "Cargo.toml", version: dep.version });
  }
  return [...seen.values()];
}

// Extract { name, ecosystem, source } entries from composer.json (PHP)
export async function parseComposer(dir) {
  const filePath = path.join(dir, "composer.json");
  let raw;
  try {
    raw = await readFile(filePath, "utf8");
  } catch {
    return [];
  }
  let json;
  try {
    json = JSON.parse(raw);
  } catch {
    return { error: `Impossible de parser ${filePath} (JSON invalide)` };
  }
  const groups = ["require", "require-dev"];
  const seen = new Map();
  for (const group of groups) {
    const deps = json[group];
    if (!deps) continue;
    for (const name of Object.keys(deps)) {
      // "php" est une contrainte de version du langage, pas un package ; "ext-*"/"lib-*"
      // désignent des extensions/libs système -- aucun des deux n'existe sur Packagist.
      if (name === "php" || name.startsWith("ext-") || name.startsWith("lib-")) continue;
      if (!seen.has(name)) seen.set(name, { name, ecosystem: "packagist", source: group, version: typeof deps[name] === "string" ? deps[name] : null });
    }
  }
  return [...seen.values()];
}

// Extract { name, ecosystem, source } entries from go.mod
export async function parseGoMod(dir) {
  const filePath = path.join(dir, "go.mod");
  let raw;
  try {
    raw = await readFile(filePath, "utf8");
  } catch {
    return [];
  }
  const seen = new Map();
  for (const dep of extractGoModules(raw)) {
    if (!seen.has(dep.name)) seen.set(dep.name, { name: dep.name, ecosystem: "go", source: "go.mod", version: dep.version });
  }
  return [...seen.values()];
}

// Extract { name, ecosystem, source } entries from Gemfile
export async function parseGemfile(dir) {
  const filePath = path.join(dir, "Gemfile");
  let raw;
  try {
    raw = await readFile(filePath, "utf8");
  } catch {
    return [];
  }
  const seen = new Map();
  for (const dep of extractGemfileDependencies(raw)) {
    if (!seen.has(dep.name)) seen.set(dep.name, { name: dep.name, ecosystem: "rubygems", source: "Gemfile", version: dep.version });
  }
  return [...seen.values()];
}

// Extract { name, ecosystem, source } entries from pom.xml (Maven)
export async function parseMaven(dir) {
  const filePath = path.join(dir, "pom.xml");
  let raw;
  try {
    raw = await readFile(filePath, "utf8");
  } catch {
    return [];
  }
  const seen = new Map();
  for (const dep of extractMavenDependencies(raw)) {
    if (!seen.has(dep.name)) seen.set(dep.name, { name: dep.name, ecosystem: "maven", source: "pom.xml", version: dep.version });
  }
  return [...seen.values()];
}

export async function collectDependencies(dir) {
  const [npm, pip, pyproject, cargo, composer, goMod, gemfile, maven] = await Promise.all([
    parseNpm(dir),
    parsePip(dir),
    parsePyproject(dir),
    parseCargo(dir),
    parseComposer(dir),
    parseGoMod(dir),
    parseGemfile(dir),
    parseMaven(dir),
  ]);
  const errors = [];
  const npmDeps = Array.isArray(npm) ? npm : (errors.push(npm.error), []);
  const composerDeps = Array.isArray(composer) ? composer : (errors.push(composer.error), []);

  // Dédoublonnage global -- au cas où le même package apparaîtrait dans deux fichiers
  // du même écosystème (ex: requirements.txt ET pyproject.toml dans le même projet).
  const merged = new Map();
  for (const dep of [...npmDeps, ...pip, ...pyproject, ...cargo, ...composerDeps, ...goMod, ...gemfile, ...maven]) {
    const key = `${dep.ecosystem}:${dep.name}`;
    if (!merged.has(key)) merged.set(key, dep);
  }

  return { deps: [...merged.values()], errors };
}
