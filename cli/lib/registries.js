const NPM_REGISTRY = "https://registry.npmjs.org";
const PYPI_REGISTRY = "https://pypi.org/pypi";
const CRATES_REGISTRY = "https://crates.io/api/v1/crates";
const PACKAGIST_REGISTRY = "https://packagist.org/packages";
const GO_PROXY = "https://proxy.golang.org";
const RUBYGEMS_REGISTRY = "https://rubygems.org/api/v1/gems";
const MAVEN_CENTRAL = "https://repo1.maven.org/maven2";

const DAY_MS = 24 * 60 * 60 * 1000;
const RECENT_THRESHOLD_DAYS = 30;
const FETCH_TIMEOUT_MS = 5000;

async function fetchJson(url) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      headers: { "user-agent": "kikard-cli" },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.status === 404) return { exists: false, status: 404 };
    if (!res.ok) return { exists: null, status: res.status };
    const json = await res.json();
    return { exists: true, status: res.status, json };
  } catch {
    clearTimeout(timeoutId);
    return { exists: null, status: 0 };
  }
}

// Variante qui ne tente pas de parser la réponse en JSON -- utile pour les registres
// qui répondent en XML (Maven Central) ou dont on n'a besoin que du code de statut.
async function fetchExists(url) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      headers: { "user-agent": "kikard-cli" },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.status === 404) return { exists: false, status: 404 };
    if (!res.ok) return { exists: null, status: res.status };
    return { exists: true, status: res.status };
  } catch {
    clearTimeout(timeoutId);
    return { exists: null, status: 0 };
  }
}

export async function checkNpm(name) {
  const encoded = name.startsWith("@") ? name.replace("/", "%2F") : name;
  const result = await fetchJson(`${NPM_REGISTRY}/${encoded}`);
  if (result.exists !== true) return result;

  const pkg = result.json;
  const createdRaw = pkg.time?.created;
  const created = createdRaw ? new Date(createdRaw) : null;
  const ageDays = created ? Math.floor((Date.now() - created.getTime()) / DAY_MS) : null;
  const hasRepo = Boolean(pkg.repository?.url);

  return {
    exists: true,
    ageDays,
    recentlyPublished: ageDays !== null && ageDays < RECENT_THRESHOLD_DAYS,
    hasRepo,
    maintainerCount: Array.isArray(pkg.maintainers) ? pkg.maintainers.length : null,
  };
}

export async function checkPyPI(name) {
  const result = await fetchJson(`${PYPI_REGISTRY}/${encodeURIComponent(name)}/json`);
  if (result.exists !== true) return result;

  const info = result.json.info || {};
  const releases = result.json.releases || {};
  const releaseDates = Object.values(releases)
    .flat()
    .map((r) => r.upload_time_iso_8601)
    .filter(Boolean)
    .sort();
  const created = releaseDates.length ? new Date(releaseDates[0]) : null;
  const ageDays = created ? Math.floor((Date.now() - created.getTime()) / DAY_MS) : null;
  const hasRepo = Boolean(info.project_urls && Object.values(info.project_urls).some((u) => /github|gitlab/i.test(u || "")));

  return {
    exists: true,
    ageDays,
    recentlyPublished: ageDays !== null && ageDays < RECENT_THRESHOLD_DAYS,
    hasRepo,
    maintainerCount: null,
  };
}

export async function checkCrates(name) {
  const result = await fetchJson(`${CRATES_REGISTRY}/${encodeURIComponent(name)}`);
  if (result.exists !== true) return result;

  const crate = result.json.crate || {};
  const created = crate.created_at ? new Date(crate.created_at) : null;
  const ageDays = created ? Math.floor((Date.now() - created.getTime()) / DAY_MS) : null;
  const hasRepo = Boolean(crate.repository);

  return {
    exists: true,
    ageDays,
    recentlyPublished: ageDays !== null && ageDays < RECENT_THRESHOLD_DAYS,
    hasRepo,
    maintainerCount: null, // pas exposé directement par cette route de l'API crates.io
  };
}

export async function checkPackagist(name) {
  // Les noms Packagist sont au format "vendor/package" -- le "/" doit rester littéral
  // dans l'URL, contrairement au reste du nom qui doit être encodé.
  const [vendor, pkgName] = name.split("/");
  if (!vendor || !pkgName) return { exists: false, status: 400 };

  const result = await fetchJson(`${PACKAGIST_REGISTRY}/${encodeURIComponent(vendor)}/${encodeURIComponent(pkgName)}.json`);
  if (result.exists !== true) return result;

  const pkg = result.json.package || {};
  const versionTimes = Object.values(pkg.versions || {})
    .map((v) => v.time)
    .filter(Boolean)
    .sort();
  const created = versionTimes.length ? new Date(versionTimes[0]) : null;
  const ageDays = created ? Math.floor((Date.now() - created.getTime()) / DAY_MS) : null;
  const hasRepo = Boolean(pkg.repository);

  return {
    exists: true,
    ageDays,
    recentlyPublished: ageDays !== null && ageDays < RECENT_THRESHOLD_DAYS,
    hasRepo,
    maintainerCount: Array.isArray(pkg.maintainers) ? pkg.maintainers.length : null,
  };
}

// Le module proxy Go exige un "encodage de casse" : chaque majuscule du chemin de module
// est remplacée par "!" suivi de sa version minuscule (spec officielle des modules Go).
function escapeGoModulePath(modulePath) {
  return modulePath.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
}

export async function checkGoModule(name) {
  const escaped = escapeGoModulePath(name);
  // On ne récupère que l'existence -- @latest renvoie la date de la dernière version publiée,
  // pas la date de création du module, donc on ne s'en sert pas comme heuristique d'ancienneté
  // (ça donnerait des faux "récemment publié" pour des modules anciens juste mis à jour).
  const result = await fetchExists(`${GO_PROXY}/${escaped}/@latest`);
  if (result.exists !== true) return result;

  return { exists: true, ageDays: null, recentlyPublished: false, hasRepo: null, maintainerCount: null };
}

export async function checkRubyGems(name) {
  const result = await fetchJson(`${RUBYGEMS_REGISTRY}/${encodeURIComponent(name)}.json`);
  if (result.exists !== true) return result;

  const gem = result.json;
  const hasRepo = Boolean(gem.source_code_uri || gem.homepage_uri);
  // "version_created_at" est la date de publication de la version courante, pas la création
  // du gem -- approximation correcte pour repérer un gem tout juste publié, imprécise pour
  // calculer l'âge réel d'un gem établi qui vient de sortir une mise à jour.
  const created = gem.version_created_at ? new Date(gem.version_created_at) : null;
  const ageDays = created ? Math.floor((Date.now() - created.getTime()) / DAY_MS) : null;

  return {
    exists: true,
    ageDays,
    recentlyPublished: ageDays !== null && ageDays < RECENT_THRESHOLD_DAYS,
    hasRepo,
    maintainerCount: null,
  };
}

export async function checkMaven(name) {
  // Coordonnée Maven au format "groupId:artifactId"
  const [groupId, artifactId] = name.split(":");
  if (!groupId || !artifactId) return { exists: false, status: 400 };

  const groupPath = groupId.replace(/\./g, "/");
  const result = await fetchExists(`${MAVEN_CENTRAL}/${groupPath}/${artifactId}/maven-metadata.xml`);
  if (result.exists !== true) return result;

  // maven-metadata.xml ne donne pas de date de première publication sans requête
  // supplémentaire par version -- on se limite donc à la vérification d'existence.
  return { exists: true, ageDays: null, recentlyPublished: false, hasRepo: null, maintainerCount: null };
}

export async function checkPackage(dep) {
  try {
    if (dep.ecosystem === "npm") return await checkNpm(dep.name);
    if (dep.ecosystem === "cratesio") return await checkCrates(dep.name);
    if (dep.ecosystem === "packagist") return await checkPackagist(dep.name);
    if (dep.ecosystem === "go") return await checkGoModule(dep.name);
    if (dep.ecosystem === "rubygems") return await checkRubyGems(dep.name);
    if (dep.ecosystem === "maven") return await checkMaven(dep.name);
    return await checkPyPI(dep.name);
  } catch (err) {
    return { exists: null, error: err.message };
  }
}

export async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const i = cursor++;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}