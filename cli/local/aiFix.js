/**
 * Applicatif de correction de code automatique (IA) -- CLI (`--ai-fix`, voir le récap
 * projet, roadmap V2 "Applicatif de correction de code"). Même architecture que le scan
 * avancé ("option B") : la clé du fournisseur IA (Anthropic, décision produit du
 * 01/09/2026) ne peut vivre que côté serveur (CWE-602) -- ce module ne fait qu'extraire un
 * EXTRAIT BORNÉ de code autour de chaque faille éligible et l'envoyer à
 * POST /api/cli/generate-fix pour obtenir une SUGGESTION. Rien n'est jamais écrit sur
 * disque par ce module lui-même : voir bin/kikard.js pour la confirmation interactive et
 * l'écriture réelle (avec sauvegarde .kikard.bak) -- décision produit du 01/09/2026 :
 * aperçu + confirmation obligatoire, jamais une application automatique et silencieuse
 * (contrairement à --fix, lib/autofix.js, qui n'applique que des patterns déterministes
 * jugés 100% sûrs -- un correctif généré par IA peut être faux ou casser du code).
 *
 * Comme cli/local/advancedScan.js, ce fichier est volontairement HORS de la synchronisation
 * scripts/sync-core.mjs (voir cli/local/ -- licensing.js, advancedScan.js, firewall*.js) :
 * il ne fait pas partie du moteur de scan open-source, seulement de la commodité CLI
 * optionnelle et connectée.
 */
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const CONTEXT_LINES = 12; // lignes avant/après la ligne signalée -- suffisant pour le
// contexte d'un correctif ciblé, jamais un fichier entier envoyé.
const REQUEST_TIMEOUT_MS = 30_000; // légèrement au-dessus du timeout interne du serveur
// (28s, voir dashboard/routes/aiFix.js) -- laisse le serveur être la première source d'un
// abandon propre plutôt que le client.

// Devine grossièrement le langage à partir de l'extension -- purement indicatif pour le
// prompt envoyé au serveur (voir dashboard/lib/aiFix.js), jamais une décision de sécurité.
const LANGUAGE_BY_EXTENSION = {
  ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".ts": "typescript", ".tsx": "typescript",
  ".py": "python", ".php": "php", ".phtml": "php",
  ".go": "go", ".rb": "ruby", ".java": "java", ".cs": "csharp", ".rs": "rust",
};

function guessLanguage(filePath) {
  return LANGUAGE_BY_EXTENSION[path.extname(filePath).toLowerCase()];
}

// Une faille "dépendance" (hallucination de package) n'a pas d'emplacement de code à
// corriger par un LLM -- se corrige en retirant/remplaçant la dépendance elle-même, hors
// scope de cet applicatif (voir --fix pour les correctifs déterministes 100% sûrs, et
// `fix_prompt` -- une fonctionnalité distincte -- pour un prompt générique à coller
// manuellement dans un assistant IA).
export function isEligibleForAiFix(finding) {
  if (!finding || finding.dep) return false;
  const loc = finding.file || (finding.location ? finding.location.split(":")[0] : null);
  return Boolean(loc);
}

function locationParts(finding) {
  const raw = finding.file || finding.location || "";
  const [filePart, lineStr] = String(raw).split(":");
  const line = finding.line || (lineStr ? Number(lineStr) : undefined);
  return { filePart, line: Number.isFinite(line) ? line : undefined };
}

// Résultat toujours normalisé, jamais d'exception -- un fichier manquant/illisible/déjà
// modifié ne doit jamais interrompre le traitement des autres findings.
export async function extractSnippetContext(rootDir, finding) {
  const { filePart, line } = locationParts(finding);
  if (!filePart) return null;
  const fullPath = path.isAbsolute(filePart) ? filePart : path.join(rootDir, filePart);

  let content;
  try {
    content = await readFile(fullPath, "utf8");
  } catch {
    return null;
  }

  const lines = content.split(/\r?\n/);
  const centerIdx = line && line >= 1 ? Math.min(line - 1, lines.length - 1) : 0;
  const startIdx = Math.max(0, centerIdx - CONTEXT_LINES);
  const endIdx = Math.min(lines.length - 1, centerIdx + CONTEXT_LINES);
  const rawSnippet = lines.slice(startIdx, endIdx + 1).join("\n");
  const numberedSnippet = lines
    .slice(startIdx, endIdx + 1)
    .map((l, i) => `${startIdx + i + 1}: ${l}`)
    .join("\n");

  return {
    fullPath,
    rawSnippet,
    numberedSnippet,
    startLine: startIdx + 1,
    endLine: endIdx + 1,
    language: guessLanguage(fullPath),
  };
}

// Résultat toujours normalisé -- jamais d'exception propagée à bin/kikard.js, même
// philosophie que runAdvancedScan (local/advancedScan.js) : une fonctionnalité optionnelle
// ne doit jamais faire échouer `kikard scan`.
export async function requestAiFix({ apiUrl, apiKey, finding, snippetCtx }) {
  try {
    const res = await fetch(`${apiUrl.replace(/\/$/, "")}/api/cli/generate-fix`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        ruleId: finding.ruleId,
        title: finding.title || finding.message,
        detail: finding.detail || finding.message,
        language: snippetCtx.language,
        snippet: snippetCtx.numberedSnippet,
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    let data;
    try {
      data = await res.json();
    } catch {
      data = null;
    }

    if (!res.ok || !data?.ok) {
      return { ok: false, reason: data?.error || data?.reason || `réponse serveur ${res.status}` };
    }

    return { ok: true, explanation: data.explanation, fixedSnippet: data.fixedSnippet, confidence: data.confidence };
  } catch (err) {
    return { ok: false, reason: err.name === "TimeoutError" ? "délai dépassé" : (err.message || "erreur réseau") };
  }
}

// Écrit le correctif accepté dans le fichier -- sauvegarde .kikard.bak AVANT toute écriture
// (même convention que lib/autofix.js), une seule fois par fichier même si plusieurs
// correctifs y sont appliqués dans la même exécution (voir `backedUpFiles`, un Set partagé
// passé par l'appelant, bin/kikard.js). Remplacement par CORRESPONDANCE EXACTE de l'extrait
// d'origine (jamais par plage de lignes) -- robuste même si un correctif précédent, dans la
// même exécution, a déjà légèrement décalé les lignes du fichier.
export async function applyAiFix({ fullPath, rawSnippet, fixedSnippet, backedUpFiles }) {
  const current = await readFile(fullPath, "utf8");
  if (!current.includes(rawSnippet)) {
    return { applied: false, reason: "extrait d'origine introuvable dans le fichier (modifié entre-temps ?)" };
  }
  if (!backedUpFiles.has(fullPath)) {
    await writeFile(`${fullPath}.kikard.bak`, current, "utf8");
    backedUpFiles.add(fullPath);
  }
  const updated = current.replace(rawSnippet, fixedSnippet);
  await writeFile(fullPath, updated, "utf8");
  return { applied: true };
}
