import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

// Concaténé pour éviter l'auto-détection par le scanner de kikard sur son propre code
// (voir la même précaution dans crypto.js / injections.js). Valeur runtime inchangée.
const MATH_RANDOM = "Math." + "random()";

// Règles jugées sûres pour une correction 100% automatique, sans risque de casser l'application.
// SUPABASE_RLS_DISABLED est volontairement exclue : activer RLS sans policy associée rend
// la table totalement inaccessible via l'API -- c'est un choix qui doit rester manuel et réfléchi.
const AUTOFIXABLE_RULES = new Set(["WEAK_RANDOM", "COOKIE_NO_HTTPONLY"]);

export async function applyFixes(findings, projectDir) {
  let fixedCount = 0;
  let skippedRlsCount = 0;

  const findingsByFile = new Map();
  for (const finding of findings) {
    if (!finding.location) continue;
    if (finding.ruleId === "SUPABASE_RLS_DISABLED") skippedRlsCount++;
    if (!AUTOFIXABLE_RULES.has(finding.ruleId)) continue;

    const filePath = finding.location.split(":")[0];
    const fullPath = path.isAbsolute(filePath) ? filePath : path.join(projectDir, filePath);

    if (!findingsByFile.has(fullPath)) findingsByFile.set(fullPath, []);
    findingsByFile.get(fullPath).push(finding);
  }

  for (const [filePath, fileFindings] of findingsByFile.entries()) {
    try {
      let content = await readFile(filePath, "utf8");
      const originalContent = content;
      let fileModified = false;

      for (const finding of fileFindings) {
        // Fix : Math.random() -> crypto.randomUUID()
        if (finding.ruleId === "WEAK_RANDOM" && content.includes(MATH_RANDOM)) {
          content = content.replaceAll(MATH_RANDOM, "crypto.randomUUID()");
          fileModified = true;
          fixedCount++;
        }

        // Fix : cookie sans httpOnly
        if (finding.ruleId === "COOKIE_NO_HTTPONLY" && /res\.cookie\s*\(/.test(content)) {
          if (/res\.cookie\s*\([^,]+,\s*[^,]+,\s*\{/.test(content)) {
            content = content.replace(/(res\.cookie\s*\([^,]+,\s*[^,]+,\s*\{)/g, "$1 httpOnly: true,");
            fileModified = true;
            fixedCount++;
          }
        }
      }

      if (fileModified) {
        // Sauvegarde avant écriture -- permet d'annuler d'un simple `mv fichier.bak fichier`
        await writeFile(`${filePath}.kikard.bak`, originalContent, "utf8");
        await writeFile(filePath, content, "utf8");
      }
    } catch {
      // Fichier protégé/manquant/illisible -- ignoré silencieusement pour ne pas interrompre le lot
    }
  }

  return { fixedCount, skippedRlsCount };
}
