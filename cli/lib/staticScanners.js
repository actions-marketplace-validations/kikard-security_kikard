import { readFile } from "node:fs/promises";
import path from "node:path";
import { walk } from "./walk.js";
import { detectStack } from "./stackDetector.js";
import { scanSecrets } from "./secrets.js";
import { scanInjections } from "./injections.js";
import { scanAuth } from "./auth.js";
import { scanDatabase } from "./database.js";
import { scanConfig } from "./config.js";
import { scanCrypto } from "./crypto.js";
import { scanPhp } from "./php-patterns.js";
import { scanGo } from "./go-patterns.js";
import { scanRuby } from "./ruby-patterns.js";
import { scanJava } from "./java-patterns.js";

// Charge la liste des chemins ou règles à ignorer depuis .kikardignore
async function loadIgnoreList(projectDir) {
  const ignoreFile = path.join(projectDir, ".kikardignore");
  try {
    const content = await readFile(ignoreFile, "utf8");
    return content
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"));
  } catch {
    return [];
  }
}

export async function runStaticScans(projectDir) {
  const [fileEntries, ignoreList] = await Promise.all([
    walk(projectDir),
    loadIgnoreList(projectDir),
  ]);

  // Filtrer les fichiers ignorés par .kikardignore
  const filteredEntries = fileEntries.filter(({ relativePath }) => {
    return !ignoreList.some((ignorePattern) => relativePath.includes(ignorePattern));
  });

  const stack = detectStack(filteredEntries);

  // Scan des secrets
  const secrets = [];
  for (const entry of filteredEntries) {
    const sec = scanSecrets(entry.relativePath, entry.content);
    if (sec && sec.length > 0) {
      secrets.push(
        ...sec.map((s) => ({
          ...s,
          category: "Secrets Scanner",
        }))
      );
    }
  }

  // Scans statiques
  const [injections, auth, db, config, crypto, php, go, ruby, java] = await Promise.all([
    scanInjections(filteredEntries, stack),
    scanAuth(filteredEntries, stack),
    scanDatabase(filteredEntries, stack),
    scanConfig(filteredEntries, stack),
    scanCrypto(filteredEntries, stack),
    scanPhp(filteredEntries, stack),
    scanGo(filteredEntries, stack),
    scanRuby(filteredEntries, stack),
    scanJava(filteredEntries, stack),
  ]);

  return [
    ...secrets,
    ...injections,
    ...auth,
    ...db,
    ...config,
    ...crypto,
    ...php,
    ...go,
    ...ruby,
    ...java,
  ];
}