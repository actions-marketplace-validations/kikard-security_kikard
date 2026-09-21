// "Prompt de correction" (fix_prompt, roadmap V2) -- génère un texte prêt à coller dans
// un assistant IA externe (ChatGPT, Claude, etc.) pour une ou plusieurs failles détectées.
// 100% local et déterministe : AUCUN appel réseau, aucune clé API, aucun coût serveur --
// contrairement à l'applicatif de correction automatique (ai_auto_fix, distinct et payant,
// voir dashboard/lib/aiFix.js), qui génère et applique lui-même un correctif via un LLM.
// Ici, kikard ne fait QUE préparer la question à poser -- c'est vous (ou l'assistant IA de
// votre choix) qui produisez et validez le correctif. Fonctionnalité gratuite par choix
// produit (voir supabase-schema.sql : min_plan='free') : zéro coût d'exécution, donc
// aucune raison de la réserver au plan payant.
//
// Fichier partagé à l'identique entre packages/core/src/ (source), cli/lib/ (copie
// synchronisée par scripts/sync-core.mjs) et dashboard/lib/scanner/ (copie vendorisée par
// scripts/vendor-core.mjs) -- même convention que le reste du moteur de scan.

// Une faille "dépendance" (hallucination de package) n'a pas d'emplacement de code à
// corriger par un assistant IA -- le correctif est de retirer/remplacer la dépendance
// elle-même, pas de patcher une ligne. Même règle d'éligibilité que ai_auto_fix (voir
// dashboard/routes/aiFix.js:isEligibleFinding / dashboard/views/pages.js:isAiFixEligibleFinding),
// dupliquée ici volontairement puisque ce fichier doit rester autonome (aucune dépendance
// vers le code dashboard-only).
export function isFixPromptEligibleFinding(f) {
  if (!f) return false;
  if (f.dep) return false;
  return Boolean(f.file || f.location);
}

function locationText(f) {
  if (f.file) return `${f.file}${f.line ? `:${f.line}` : ""}`;
  return f.location || "emplacement inconnu";
}

// Un bloc de faille -- réutilisé tel quel par le CLI (qui en assemble plusieurs dans un
// seul document, voir buildFixPromptDocument) et par le dashboard (un bloc à la fois, un
// par bouton "Prompt de correction" sur le rapport de scan, voir routes/fixPrompt.js).
// `snippet` est optionnel : un extrait de code réel rend le prompt bien plus exploitable,
// mais son absence (scan de code collé/importé, fichier introuvable, etc.) ne doit jamais
// empêcher de générer un prompt -- la faille reste utile à décrire même sans code joint.
export function buildFindingPromptSection(finding, snippet) {
  const lines = [];
  lines.push(`### ${finding.title || finding.ruleId || "Faille détectée"}`);
  lines.push(`- Sévérité : ${finding.severity || "inconnue"}`);
  if (finding.ruleId) lines.push(`- Règle : ${finding.ruleId}`);
  lines.push(`- Emplacement : ${locationText(finding)}`);
  if (finding.detail) lines.push(`- Détail : ${finding.detail}`);
  if (finding.fix) lines.push(`- Piste de correction connue de kikard : ${finding.fix}`);
  if (snippet && snippet.trim()) {
    lines.push("");
    lines.push("Code concerné :");
    lines.push("```");
    lines.push(snippet);
    lines.push("```");
  }
  return lines.join("\n");
}

export const FIX_PROMPT_INTRO =
  "Tu es un ingénieur en sécurité logicielle. kikard (scanner de sécurité pour code généré " +
  "par IA) a détecté la ou les faille(s) ci-dessous. Pour chacune : explique le risque en " +
  "une phrase, puis propose un correctif de code précis qui conserve le comportement " +
  "métier existant. Si le code concerné n'est pas fourni, indique clairement quelle " +
  "modification appliquer et à quel endroit.";

// Document complet -- un par exécution de `kikard scan --fix-prompt`, toutes les failles
// éligibles regroupées dans un seul texte prêt à coller. `snippetsByIndex` (optionnel) :
// Map<index dans `findings`, string> -- le CLI peut se permettre de lire les fichiers
// scannés directement sur disque (contrairement au dashboard, qui ne conserve jamais le
// code après un scan et doit le retélécharger à la demande, voir routes/fixPrompt.js).
// Retourne null si aucune faille éligible (jamais un document vide).
export function buildFixPromptDocument(findings, snippetsByIndex) {
  const eligible = findings
    .map((f, index) => ({ f, index }))
    .filter(({ f }) => isFixPromptEligibleFinding(f));

  if (eligible.length === 0) return null;

  const sections = eligible.map(({ f, index }) =>
    buildFindingPromptSection(f, snippetsByIndex ? snippetsByIndex.get(index) : undefined)
  );

  return [FIX_PROMPT_INTRO, "", sections.join("\n\n---\n\n")].join("\n");
}
