const COLORS = {
  critical: "\x1b[91m",
  high: "\x1b[91m",
  medium: "\x1b[93m",
  low: "\x1b[94m",
  info: "\x1b[90m",
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[92m",
  red: "\x1b[91m",
};

const SEVERITY_LABEL = {
  critical: "CRITIQUE",
  high: "ÉLEVÉ",
  medium: "MOYEN",
  low: "FAIBLE",
  info: "INFO",
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Mapping des catégories de la Roadmap vers les libellés de l'affichage
const ROADMAP_CATEGORIES = [
  { key: "Hallucination de packages", label: "Hallucination de packages" },
  { key: "Secrets Scanner", label: "Secrets en clair" },
  { key: "JSON.parse(), innerHTML, injection XSS", label: "JSON.parse(), innerHTML, injection XSS" },
  { key: "Injection SQL par concaténation", label: "Injection SQL par concaténation" },
  { key: "Crypto faible", label: "Crypto faible" },
  { key: "CORS ouvert", label: "CORS ouvert" },
  { key: "RLS Supabase", label: "RLS Supabase" },
  { key: "Endpoints non protégés", label: "Endpoints non protégés" },
];

function locationLabel(f) {
  if (f.dep) return `${f.dep.ecosystem} · ${f.dep.name}`;
  if (f.file) return `${f.file}${f.line ? `:${f.line}` : ""}`;
  if (f.location) return f.location;
  return "Inconnu";
}

export function printTerminalReport(findings, meta) {
  const { scanned, filesScanned } = meta;
  const parts = [];
  if (scanned) parts.push(`${scanned} dépendance${scanned > 1 ? "s" : ""}`);
  if (filesScanned !== undefined) parts.push(`${filesScanned} fichier${filesScanned > 1 ? "s" : ""} source`);
  
  console.log(`\n${COLORS.bold}kikard${COLORS.reset} -- ${parts.join(" · ")} analysé(s)\n`);

  // 1. Tableau de synthèse par catégorie (Style Image 1)
  console.log(`${COLORS.bold}Catégorie${" ".repeat(35)}Statut${COLORS.reset}`);
  console.log("─".repeat(52));

  for (const cat of ROADMAP_CATEGORIES) {
    const hasIssue = findings.some(
      (f) => f.category === cat.key || f.category === cat.label
    );
    const status = hasIssue
      ? `${COLORS.red}✕${COLORS.reset}`
      : `${COLORS.green}✓${COLORS.reset}`;
    const paddedLabel = cat.label.padEnd(42, " ");
    console.log(`${paddedLabel} ${status}`);
  }

  // Catégories spécifiques à un langage (PHP, Go, Ruby, Java...) qui ne font pas partie
  // du socle de règles génériques ci-dessus -- une seule ligne récapitulative plutôt que
  // d'en lister une par langage, pour garder ce tableau lisible en un coup d'œil.
  const roadmapKeys = new Set(ROADMAP_CATEGORIES.map((c) => c.key));
  const hasOtherFindings = findings.some((f) => f.category && !roadmapKeys.has(f.category));
  const otherStatus = hasOtherFindings
    ? `${COLORS.red}✕${COLORS.reset}`
    : `${COLORS.green}✓${COLORS.reset}`;
  console.log(`${"Failles spécifiques (PHP, Go, Ruby, Java...)".padEnd(42, " ")} ${otherStatus}`);

  console.log("\n" + "─".repeat(52) + "\n");

  if (findings.length === 0) {
    console.log(`${COLORS.green}✓ Aucune vulnérabilité ni secret exposé détecté.${COLORS.reset}\n`);
    return;
  }

  // 2. Détail des vulnérabilités trouvées
  const sorted = [...findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
  );

  console.log(`${COLORS.bold}DÉTAILS DES VULNÉRABILITÉS :${COLORS.reset}\n`);

  for (const f of sorted) {
    const color = COLORS[f.severity] || COLORS.info;
    const title = f.title || f.message || f.ruleId;
    const detail = f.detail || f.message || "";
    
    console.log(`${color}${COLORS.bold}[${SEVERITY_LABEL[f.severity] || "INFO"}]${COLORS.reset} ${title}`);
    console.log(`  ${COLORS.dim}Emplacement : ${locationLabel(f)}${COLORS.reset}`);
    if (detail && detail !== title) console.log(`  ${detail}`);
    if (f.fix) console.log(`  ${color}→ Fix : ${f.fix}${COLORS.reset}`);
    console.log("");
  }

  // 3. Résumé global
  const counts = sorted.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  // [19/09/2026] Accord pluriel -- "3 CRITIQUE" se lisait mal, corrigé en "3 CRITIQUES"
  // dès que le compte dépasse 1 (demande explicite de l'utilisateur). Même règle pour
  // toutes les sévérités, y compris un `sev` inconnu qui retomberait sur la clé brute.
  const summary = Object.entries(counts)
    .map(([sev, n]) => `${COLORS[sev]}${n} ${SEVERITY_LABEL[sev] || sev}${n > 1 ? "S" : ""}${COLORS.reset}`)
    .join("  ·  ");

  console.log(`${COLORS.bold}Résumé :${COLORS.reset} ${summary}\n`);
}

export function buildJsonReport(findings, meta) {
  return {
    tool: "kikard",
    scannedAt: new Date().toISOString(),
    dependenciesScanned: meta.scanned,
    filesScanned: meta.filesScanned,
    findings: findings.map((f) => ({
      severity: f.severity,
      category: f.category || (f.dep ? "dependency" : "static"),
      ruleId: f.ruleId,
      ecosystem: f.dep?.ecosystem,
      package: f.dep?.name,
      location: locationLabel(f),
      title: f.title || f.message,
      detail: f.detail || f.message,
      fix: f.fix,
    })),
  };
}