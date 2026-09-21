import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { SCANNABLE_EXTENSIONS } from "./secrets.js";

const IGNORED_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "out", "coverage", "venv", ".venv", "__pycache__",
]);
const MAX_FILE_SIZE = 1_000_000; // 1 Mo -- au-delà, probablement un fichier généré/minifié, pas du code à auditer

export async function walk(rootDir) {
  const results = [];

  async function walk(dir) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.name.startsWith(".") && entry.name !== ".env") continue;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        await walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (!SCANNABLE_EXTENSIONS.has(ext) && entry.name !== ".env") continue;
        try {
          const s = await stat(fullPath);
          if (s.size > MAX_FILE_SIZE) continue;
          const content = await readFile(fullPath, "utf8");
          results.push({ relativePath: path.relative(rootDir, fullPath), content });
        } catch {
          // fichier illisible/binaire -- ignoré silencieusement
        }
      }
    }
  }

  await walk(rootDir);
  return results;
}
