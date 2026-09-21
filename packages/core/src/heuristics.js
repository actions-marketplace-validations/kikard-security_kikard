import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Suffixes/patterns AI models commonly invent for plausible-sounding helper packages.
const SUSPICIOUS_NAME_PATTERNS = [
  /-gpt(-|$)/i,
  /-ai-(helper|utils|tools|kit)(-|$)/i,
  /-ai$/i,
  /^easy-[a-z]+$/i,
  /-helper$/i,
  /-wrapper$/i,
];

let knownHallucinatedCache = null;
async function loadKnownHallucinated() {
  if (knownHallucinatedCache) return knownHallucinatedCache;
  // KIKARD_DATA_DIR permet à un appelant externe de préciser où trouver data/,
  // sans que ce fichier ait besoin de connaître sa propre profondeur d'imbrication.
  // Par défaut : un niveau au-dessus de ce fichier.
  const dataDir = process.env.KIKARD_DATA_DIR || path.join(__dirname, "..", "data");
  const raw = await readFile(path.join(dataDir, "known-hallucinated.json"), "utf8");
  const json = JSON.parse(raw);
  knownHallucinatedCache = {
    npm: new Set((json.npm || []).map((n) => n.toLowerCase())),
    pypi: new Set((json.pypi || []).map((n) => n.toLowerCase())),
    cratesio: new Set((json.cratesio || []).map((n) => n.toLowerCase())),
    packagist: new Set((json.packagist || []).map((n) => n.toLowerCase())),
    go: new Set((json.go || []).map((n) => n.toLowerCase())),
    rubygems: new Set((json.rubygems || []).map((n) => n.toLowerCase())),
    maven: new Set((json.maven || []).map((n) => n.toLowerCase())),
  };
  return knownHallucinatedCache;
}

const REGISTRY_SITE = {
  npm: "npmjs.com",
  pypi: "pypi.org",
  cratesio: "crates.io",
  packagist: "packagist.org",
  go: "pkg.go.dev",
  rubygems: "rubygems.org",
  maven: "search.maven.org",
};

function hasSuspiciousName(name) {
  return SUSPICIOUS_NAME_PATTERNS.some((re) => re.test(name));
}

// Transforme le résultat brut de vérification de registre en un problème/finding au format standard kikard.
export async function evaluate(dep, registryResult) {
  const known = await loadKnownHallucinated();
  const isKnownHallucinated = known[dep.ecosystem]?.has(dep.name.toLowerCase());

  const baseFinding = {
    category: "Slopsquatting & Dépendances IA",
    location: dep.file || dep.ecosystem,
    snippet: `${dep.name}@${dep.version || "latest"}`,
    dep,
  };

  if (registryResult.exists === false) {
    return {
      ...baseFinding,
      severity: "critical",
      ruleId: "HALLUCINATED_PACKAGE",
      title: "Package introuvable sur le registre",
      detail: `"${dep.name}" (${dep.ecosystem}) n'existe pas sur le registre public. Si l'IA a suggéré ce nom, il s'agit très probablement d'une hallucination -- un attaquant peut l'enregistrer à tout moment (slopsquatting).`,
      fix: `Vérifiez le nom exact du package dans sa documentation officielle avant d'installer quoi que ce soit sous ce nom.`,
    };
  }

  if (registryResult.exists === null) {
    return {
      ...baseFinding,
      severity: "info",
      ruleId: "REGISTRY_UNREACHABLE",
      title: "Vérification du registre impossible",
      detail: `Le registre n'a pas pu être interrogé pour "${dep.name}" (problème réseau ou limite de requêtes).`,
      fix: `Relancez le scan ou vérifiez manuellement sur ${REGISTRY_SITE[dep.ecosystem] || dep.ecosystem}.`,
    };
  }

  // Si le package existe sur le registre
  if (isKnownHallucinated) {
    return {
      ...baseFinding,
      severity: "critical",
      ruleId: "KNOWN_HALLUCINATION",
      title: "Nom présent dans la liste des hallucinations documentées",
      detail: `"${dep.name}" existe sur le registre, mais ce nom exact est documenté comme une hallucination IA récurrente. Le package existant n'est peut-être pas celui attendu.`,
      fix: `Confirmez que ce package est bien celui que vous avez l'intention d'utiliser (mainteneur, dépôt source, description).`,
    };
  }

  const reasons = [];
  if (registryResult.recentlyPublished) {
    reasons.push(`publié il y a moins de ${registryResult.ageDays ?? "?"} jours`);
  }
  if (registryResult.hasRepo === false) {
    reasons.push("aucun dépôt source lié");
  }
  if (hasSuspiciousName(dep.name)) {
    reasons.push("nom au format typique d'une suggestion IA (ex: \"-helper\", \"-ai-utils\")");
  }

  if (reasons.length >= 2) {
    return {
      ...baseFinding,
      severity: "medium",
      ruleId: "SUSPICIOUS_PACKAGE_PROFILE",
      title: "Package existant mais profil suspect",
      detail: `"${dep.name}" existe, mais cumule plusieurs signaux de risque : ${reasons.join(", ")}.`,
      fix: `Vérifiez le mainteneur, le dépôt source et le nombre de téléchargements sur ${REGISTRY_SITE[dep.ecosystem] || dep.ecosystem}.`,
    };
  }

  if (reasons.length === 1) {
    return {
      ...baseFinding,
      severity: "low",
      ruleId: "LOW_RISK_PACKAGE_SIGNAL",
      title: "Package existant, signal faible détecté",
      detail: `"${dep.name}" existe. Signal relevé : ${reasons[0]}.`,
      fix: `Une vérification rapide suffit si ce package est critique pour votre application.`,
    };
  }

  return null; // Dépendance propre
}