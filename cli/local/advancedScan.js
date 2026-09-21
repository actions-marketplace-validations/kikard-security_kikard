/**
 * Scan avancé CLI ("option B") -- collecte locale des fichiers de manifeste d'un langage
 * "premium" (C#/.NET pour l'instant) puis envoi à /api/cli/advanced-scan pour vérification
 * côté serveur (registre NuGet). Le moteur open-source de ce dépôt (lib/*.js) N'EST PAS
 * modifié pour ce langage -- kikard reste 100% fonctionnel hors ligne sans cette
 * fonctionnalité (npm/PyPI/crates.io/Packagist/Go/RubyGems/Maven vérifiés localement comme
 * avant, aucune régression). --advanced est un OPT-IN explicite qui, une fois connecté à
 * un compte éligible, permet EN PLUS de rester en ligne le temps du scan pour bénéficier
 * d'une vérification supplémentaire côté serveur -- jamais une dégradation de ce qui
 * fonctionne déjà hors ligne.
 *
 * Sécurité (voir le récap projet, section "Scan avancé CLI (option B)") : le CLI lui-même
 * ne décide jamais de rien -- il propose (affichage local basé sur getLicenseStatus()) mais
 * le serveur revérifie systématiquement l'entitlement à l'appel réel. Ce fichier ne
 * transmet QUE les fichiers de manifeste pertinents (.csproj, packages.config), jamais le
 * reste du dépôt, et se dégrade toujours silencieusement vers le scan local en cas
 * d'échec réseau, de timeout, ou de refus serveur -- jamais d'erreur fatale pour une
 * fonctionnalité optionnelle.
 */
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";

const IGNORED_DIRS = new Set([
  "node_modules", ".git", "bin", "obj", "dist", "build", ".vs", ".vscode",
]);

// Bornes appliquées côté CLI avant même l'envoi -- le serveur applique les siennes
// indépendamment (défense en profondeur, voir dashboard/lib/scanner-premium/csharp-nuget.js),
// mais échouer tôt et localement donne un message d'erreur plus clair à l'utilisateur.
const MAX_FILES = 50;
const MAX_FILE_BYTES = 100 * 1024; // 100 Ko
const MAX_SCAN_DEPTH = 12;
const REQUEST_TIMEOUT_MS = 35_000; // légèrement au-dessus du timeout serveur (30s, voir advancedScan.js) --
// laisse le serveur être la première source d'un abandon propre plutôt que le client.

// Langages premium reconnus par le CLI et leur détection locale (quels fichiers chercher).
// Ajouter un langage premium ici = l'ajouter aussi côté serveur
// (dashboard/lib/scanner-premium/, dashboard/routes/advancedScan.js) ET dans la table
// `languages` (supabase-schema.sql) -- les deux listes doivent rester synchronisées
// manuellement, il n'y a pas de source unique partagée entre les deux dépôts.
const PREMIUM_LANGUAGE_MATCHERS = {
  csharp: (filename) => filename.endsWith(".csproj") || filename.toLowerCase() === "packages.config",
};

export function getSupportedPremiumLanguages() {
  return Object.keys(PREMIUM_LANGUAGE_MATCHERS);
}

// Collecte bornée des fichiers de manifeste pertinents pour un langage premium donné --
// jamais le contenu du reste du projet (pas de code source applicatif, pas de secrets).
export async function collectPremiumManifestFiles(rootDir, language) {
  const matcher = PREMIUM_LANGUAGE_MATCHERS[language];
  if (!matcher) return [];

  const results = [];

  async function walk(dir, depth) {
    if (results.length >= MAX_FILES || depth > MAX_SCAN_DEPTH) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (results.length >= MAX_FILES) return;
      if (entry.name.startsWith(".") && entry.isDirectory()) continue;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        await walk(fullPath, depth + 1);
      } else if (entry.isFile() && matcher(entry.name)) {
        try {
          const s = await stat(fullPath);
          if (s.size > MAX_FILE_BYTES) continue; // fichier anormalement volumineux pour ce type -- ignoré, pas envoyé
          const content = await readFile(fullPath, "utf8");
          results.push({ path: path.relative(rootDir, fullPath).split(path.sep).join("/"), content });
        } catch {
          // illisible/binaire -- ignoré silencieusement, comme le reste du moteur (lib/walk.js)
        }
      }
    }
  }

  await walk(rootDir, 0);
  return results;
}

// Résultat toujours normalisé -- jamais d'exception propagée à l'appelant (bin/kikard.js) :
// une fonctionnalité optionnelle ne doit jamais faire échouer `kikard scan`.
//   { attempted: false }                              -- rien à scanner pour ce langage (aucun fichier trouvé)
//   { attempted: true, ok: true, findings, dependenciesScanned }
//   { attempted: true, ok: false, reason }             -- échec réseau/serveur, dégradation silencieuse
export async function runAdvancedScan({ dir, language, apiUrl, apiKey }) {
  const files = await collectPremiumManifestFiles(dir, language);
  if (files.length === 0) {
    return { attempted: false };
  }

  try {
    const res = await fetch(`${apiUrl.replace(/\/$/, "")}/api/cli/advanced-scan`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({ language, files }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    let data;
    try {
      data = await res.json();
    } catch {
      data = null;
    }

    if (!res.ok || !data?.ok) {
      const reason = data?.error || `réponse serveur ${res.status}`;
      return { attempted: true, ok: false, reason };
    }

    return { attempted: true, ok: true, findings: data.findings || [], dependenciesScanned: data.dependenciesScanned || 0 };
  } catch (err) {
    // Timeout, réseau indisponible, DNS, etc. -- jamais fatal, voir l'en-tête de ce fichier.
    return { attempted: true, ok: false, reason: err.name === "TimeoutError" ? "délai dépassé" : (err.message || "erreur réseau") };
  }
}
