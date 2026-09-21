import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import os from "node:os";

const CONFIG_DIR = path.join(os.homedir(), ".kikard");
const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");
const CACHE_TTL_MS = 60 * 60 * 1000; // 1h -- évite un appel réseau à chaque scan
const VERIFY_TIMEOUT_MS = 5000; // ne bloque jamais longtemps un scan si le réseau est lent

export async function loadConfig() {
  try {
    const raw = await readFile(CONFIG_PATH, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function writeConfig(config) {
  await mkdir(CONFIG_DIR, { recursive: true });
  // mode 0o600 : lisible/écrivable seulement par le propriétaire -- la clé API a la
  // même sensibilité qu'un mot de passe, elle est stockée avec les mêmes précautions.
  await writeFile(CONFIG_PATH, JSON.stringify(config, null, 2), { mode: 0o600 });
}

export async function saveApiKey(apiKey, apiUrl) {
  await writeConfig({ apiKey, apiUrl });
}

export async function clearApiKey() {
  await writeConfig({});
}

// Vérifie la clé auprès du serveur de licence configuré (--api-url). NE LANCE JAMAIS D'EXCEPTION vers l'appelant --
// en cas d'échec réseau, de timeout, ou d'absence de clé, retourne le plan "free" par
// défaut (ou le dernier plan connu en cache). C'est la garantie que le CLI reste
// utilisable offline et sans compte, exactement comme avant l'ajout de ce système.
export async function getLicenseStatus() {
  const config = await loadConfig();
  if (!config?.apiKey) return { plan: "free", features: [], languages: [], source: "no-key" };
  if (!config.apiUrl) return { plan: "free", features: [], languages: [], source: "no-api-url" };

  const now = Date.now();
  if (config.cachedAt && now - config.cachedAt < CACHE_TTL_MS && config.cachedPlan) {
    return { plan: config.cachedPlan, features: config.cachedFeatures || [], languages: config.cachedLanguages || [], source: "cache" };
  }

  try {
    const res = await fetch(`${config.apiUrl.replace(/\/$/, "")}/api/cli/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ apiKey: config.apiKey }),
      signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`verify failed (${res.status})`);
    const data = await res.json();
    if (!data.valid) return { plan: "free", features: [], languages: [], source: "invalid-key" };

    // `languages` (scan avancé, ex : C#/.NET) n'est qu'une INFORMATION mise en cache pour
    // l'UX locale (afficher/proposer intelligemment --advanced) -- jamais une autorisation.
    // Le serveur revérifie systématiquement et indépendamment l'entitlement au moment de
    // l'appel réel à /api/cli/advanced-scan (voir cli/local/advancedScan.js) : un cache
    // local périmé ou manipulé ne débloque donc jamais réellement rien.
    await writeConfig({ ...config, cachedAt: now, cachedPlan: data.plan, cachedFeatures: data.features, cachedLanguages: data.languages || [] });
    return { plan: data.plan, features: data.features, languages: data.languages || [], source: "verified" };
  } catch {
    // Hors ligne, timeout, serveur indisponible -- on retombe sur le cache existant
    // (même expiré) plutôt que de faire échouer le scan pour une raison de licence.
    if (config.cachedPlan) return { plan: config.cachedPlan, features: config.cachedFeatures || [], languages: config.cachedLanguages || [], source: "stale-cache" };
    return { plan: "free", features: [], languages: [], source: "offline" };
  }
}

// [12/09/2026] Compte obligatoire + quota gratuit (voir kikard-update-12092026-nouveau-
// modele-economique.md) : contrairement à getLicenseStatus() ci-dessus (mis en cache 1h,
// jamais l'autorité finale), CE compteur DOIT être appelé et vérifié en ligne À CHAQUE
// scan -- c'est la seule source de vérité sur le quota consommé, exactement comme le
// serveur revérifie systématiquement /api/cli/advanced-scan indépendamment du cache local.
// Fail-open volontaire sur toute panne réseau/serveur (jamais sur un quota réellement
// dépassé, ça c'est le serveur qui le dit explicitement) : un utilisateur hors ligne ou un
// serveur en incident ne doit jamais perdre l'usage du CLI pour une raison qui n'est pas
// la sienne -- même philosophie que le reste de ce fichier.
const QUOTA_TIMEOUT_MS = 5000;

export async function checkScanQuota() {
  const config = await loadConfig();
  if (!config?.apiKey || !config?.apiUrl) return { ok: false, reason: "no-account" };

  try {
    const res = await fetch(`${config.apiUrl.replace(/\/$/, "")}/api/cli/scan-quota`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ apiKey: config.apiKey }),
      signal: AbortSignal.timeout(QUOTA_TIMEOUT_MS),
    });
    if (res.status === 401) return { ok: false, reason: "invalid-key" };
    if (!res.ok) return { ok: true, degraded: true }; // erreur serveur -- fail-open, voir en-tête ci-dessus
    return await res.json();
  } catch {
    return { ok: true, degraded: true }; // hors ligne/timeout -- fail-open, voir en-tête ci-dessus
  }
}
