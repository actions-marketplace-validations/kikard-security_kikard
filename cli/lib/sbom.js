// [13/09/2026] Génération d'un SBOM (Software Bill of Materials) au format CycloneDX
// (JSON, spec 1.5) -- fonctionnalité --sbom du CLI. [19/09/2026] Gratuit, sans compte
// requis (voir kikard-decision-19092026-modele-final-free-payant-firewall-sbom.md) : le
// gating Team+ initial (voir bin/kikard.js, section "SBOM") a été retiré après audit. Consomme le tableau `deps` déjà produit par
// `collectDependencies()` (lib/parsers.js), qui contient désormais { name, ecosystem,
// source, version } pour les 8 écosystèmes supportés.
//
// Limite assumée et documentée : `version` est la CONTRAINTE déclarée dans le manifeste
// (ex: "^4.17.21", "~> 1.0", ">=2.28"), pas une version résolue depuis un lockfile --
// aucun des parseurs de kikard ne lit package-lock.json/pnpm-lock.yaml/poetry.lock/
// Cargo.lock/Gemfile.lock/etc. Un composant du SBOM peut donc avoir un `version` absent
// (contrainte non exploitable ou dépendance non versionnée) -- la contrainte brute est de
// toute façon conservée dans les `properties` de chaque composant pour rester honnête sur
// ce qui a été réellement observé.

import crypto from "node:crypto";
import path from "node:path";

// Correspondance écosystème kikard -> type purl (package URL, https://github.com/package-url/purl-spec)
const PURL_TYPE = {
  npm: "npm",
  pypi: "pypi",
  cratesio: "cargo",
  packagist: "composer",
  go: "golang",
  rubygems: "gem",
  maven: "maven",
};

// Tente d'extraire une version "propre" (utilisable dans un purl) depuis une contrainte
// déclarée -- best-effort uniquement, voir note en tête de fichier. Renvoie null si la
// contrainte ne ressemble pas à une version exploitable (ex: plage complexe, vide).
function cleanVersionForPurl(raw) {
  if (!raw || typeof raw !== "string") return null;
  let v = raw.trim();
  if (!v) return null;
  // opérateurs de plage courants en tête (npm/pip/poetry/cargo/rubygems) : ^ ~ = < > ! espace
  v = v.replace(/^[\^~=<>! ]+/, "").trim();
  // go.mod préfixe ses versions par "v" (ex: v1.9.1) -- purl golang n'attend pas ce préfixe
  v = v.replace(/^v(?=\d)/, "");
  return /^\d/.test(v) ? v : null;
}

function buildPurl(dep) {
  const type = PURL_TYPE[dep.ecosystem];
  if (!type) return null;
  const cleanVersion = cleanVersionForPurl(dep.version);
  const versionSuffix = cleanVersion ? `@${encodeURIComponent(cleanVersion)}` : "";

  if (dep.ecosystem === "npm" && dep.name.startsWith("@")) {
    const [scope, ...rest] = dep.name.split("/");
    return `pkg:npm/${encodeURIComponent(scope)}/${encodeURIComponent(rest.join("/"))}${versionSuffix}`;
  }
  if (dep.ecosystem === "packagist") {
    return `pkg:composer/${dep.name.split("/").map(encodeURIComponent).join("/")}${versionSuffix}`;
  }
  if (dep.ecosystem === "go") {
    return `pkg:golang/${dep.name.split("/").map(encodeURIComponent).join("/")}${versionSuffix}`;
  }
  if (dep.ecosystem === "maven") {
    const [groupId, artifactId] = dep.name.split(":");
    return `pkg:maven/${encodeURIComponent(groupId || "")}/${encodeURIComponent(artifactId || "")}${versionSuffix}`;
  }
  return `pkg:${type}/${encodeURIComponent(dep.ecosystem === "pypi" ? dep.name.toLowerCase() : dep.name)}${versionSuffix}`;
}

function toComponent(dep) {
  const purl = buildPurl(dep);
  let group;
  let name = dep.name;
  if (dep.ecosystem === "maven") {
    const [groupId, artifactId] = dep.name.split(":");
    group = groupId;
    name = artifactId || dep.name;
  } else if (dep.ecosystem === "npm" && dep.name.startsWith("@")) {
    const [scope, ...rest] = dep.name.split("/");
    group = scope;
    name = rest.join("/");
  }

  const cleanVersion = cleanVersionForPurl(dep.version);

  const component = {
    type: "library",
    "bom-ref": purl || `${dep.ecosystem}:${dep.name}`,
    name,
    properties: [
      { name: "kikard:ecosystem", value: dep.ecosystem },
      { name: "kikard:manifestSource", value: dep.source },
      { name: "kikard:declaredVersionConstraint", value: dep.version || "(non déclarée)" },
    ],
  };
  if (group) component.group = group;
  if (cleanVersion) component.version = cleanVersion;
  if (purl) component.purl = purl;
  return component;
}

// deps : tableau { name, ecosystem, source, version } (voir collectDependencies)
// targetDir : dossier scanné (utilisé pour nommer le composant "application" racine)
// toolVersion : version du CLI kikard (affichée dans metadata.tools)
export function buildCycloneDxSbom({ deps, targetDir, toolVersion }) {
  const now = new Date().toISOString();
  const rootName = path.basename(path.resolve(targetDir || ".")) || "projet";

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: now,
      tools: [
        {
          vendor: "kikard",
          name: "kikard-cli",
          version: toolVersion || "unknown",
        },
      ],
      component: {
        type: "application",
        "bom-ref": `kikard-target:${rootName}`,
        name: rootName,
      },
      properties: [
        {
          name: "kikard:sbomNote",
          value:
            "Versions = contraintes déclarées dans les manifestes (ex: \"^4.17.21\"), pas des versions résolues depuis un lockfile -- aucun lockfile n'est lu par kikard.",
        },
      ],
    },
    components: deps.map(toComponent),
  };
}
