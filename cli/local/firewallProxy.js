// Coeur du pare-feu registre local ("kikard firewall") -- un serveur HTTP que l'on fait
// pointer en registre npm/pip local (voir firewallDaemon.js) pour intercepter la
// RÉSOLUTION des paquets avant que `npm install` / `pip install` NATIFS ne les installent --
// même si le développeur tape la commande native directement, sans aucun wrapper kikard.
// C'est le mécanisme le plus complet des trois envisagés (voir le récap projet) : un simple
// wrapper CLI ne protège que si le développeur pense à l'utiliser, un hook Git n'intervient
// qu'après coup (le paquet est déjà installé) -- un proxy registre protège la commande
// d'installation elle-même, quel que soit l'outil qui l'invoque (terminal, IDE, script CI).
//
// Détection : on réutilise EXACTEMENT le même moteur que `kikard scan` (lib/registries.js +
// lib/heuristics.js, écosystèmes npm et pypi) -- un paquet halluciné/typosquatté détecté par
// le scan local l'est donc aussi ici, sans code de détection dupliqué. Conséquence
// importante : ce n'est PAS une fonctionnalité premium, aucun appel réseau vers kikard n'est
// fait ici, ça fonctionne hors compte et hors plan payant, exactement comme `kikard scan`.
//
// Choix volontaire de scope (v1) : seule la RÉSOLUTION DE MÉTADONNÉES (GET du nom de paquet)
// est interceptée. Le téléchargement du tarball/fichier lui-même n'est jamais reproxifié --
// les métadonnées renvoyées par les registres officiels contiennent déjà une URL absolue
// vers le registre réel (registry.npmjs.org / files.pythonhosted.org), donc un paquet
// autorisé est téléchargé directement depuis la source officielle après notre vérification,
// sans repasser par nous (pas de re-streaming de gros binaires à notre charge). On ne bloque
// QUE les paquets confirmés comme hallucination/typosquat -- tout le reste (recherche, audit,
// whoami, publish, requêtes non reconnues...) est transmis tel quel au registre réel
// (fail-open : on ne casse jamais une commande npm/pip pour une raison autre qu'un blocage
// explicite et justifié).
//
// Écosystèmes couverts en v1 : npm et PyPI (pip) -- les deux protocoles de résolution les
// plus simples à reproduire fidèlement, et les deux écosystèmes les plus concernés par le
// slopsquatting assisté par IA aujourd'hui. crates.io, Packagist, RubyGems, Go et Maven ont
// des protocoles de registre plus lourds (index sparse, format Marshal, zips signés...) --
// volontairement hors v1, voir le récap projet pour l'extension prévue.
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { URL } from "node:url";
import { checkPackage } from "../lib/registries.js";
import { evaluate } from "../lib/heuristics.js";

const REAL_NPM_ORIGIN = "https://registry.npmjs.org";
const REAL_PYPI_ORIGIN = "https://pypi.org";

// Seules ces deux règles justifient un blocage réel (paquet inexistant / hallucination
// documentée) -- un signal "suspect mais existant" (SUSPICIOUS_PACKAGE_PROFILE,
// LOW_RISK_PACKAGE_SIGNAL) ou une vérification impossible (REGISTRY_UNREACHABLE) ne bloque
// jamais une installation : ce serait bloquer du travail légitime sur une simple ambiguïté.
const BLOCKING_RULE_IDS = new Set(["HALLUCINATED_PACKAGE", "KNOWN_HALLUCINATION"]);

// Un paquet npm non-scoped est demandé via "GET /<nom>" ou "GET /<nom>/<version>" ; un
// paquet scoped via "GET /@scope%2fnom" ou "GET /@scope%2fnom/<version>" (npm encode le "/"
// séparant scope et nom, mais pas celui séparant nom et version). On extrait uniquement le
// nom du paquet dans les deux cas -- la version n'a pas d'importance pour cette vérification.
function decodeNpmPackageNameFromPath(pathname) {
  const decoded = decodeURIComponent(pathname.replace(/^\/+/, ""));
  if (!decoded) return null;
  const segments = decoded.split("/").filter(Boolean);
  if (decoded.startsWith("@")) {
    if (segments.length < 2 || segments.length > 3) return null; // pas une forme reconnue -- laissé passer tel quel
    return `${segments[0]}/${segments[1]}`;
  }
  if (segments.length < 1 || segments.length > 2) return null; // ex: "-/v1/search", "-/npm/v1/security/..." -- jamais interceptés
  return segments[0];
}

// L'index simple PyPI répond à "GET /simple/<nom>/" -- c'est l'URL que pip demande lorsque
// son index-url pointe vers nous (voir firewallDaemon.js, qui configure
// "http://127.0.0.1:<port>/simple/").
function decodePypiPackageNameFromPath(pathname) {
  const m = /^\/simple\/([^/]+)\/?$/.exec(pathname);
  return m ? decodeURIComponent(m[1]) : null;
}

function pickUpstreamOrigin(pathname) {
  return pathname.startsWith("/simple/") ? REAL_PYPI_ORIGIN : REAL_NPM_ORIGIN;
}

async function findBlockingReason(name, ecosystem, log) {
  try {
    const dep = { name, ecosystem };
    const registryResult = await checkPackage(dep);
    const finding = await evaluate(dep, registryResult);
    return finding && BLOCKING_RULE_IDS.has(finding.ruleId) ? finding : null;
  } catch (err) {
    // Une erreur du moteur de détection lui-même ne doit jamais bloquer une installation --
    // fail-open, cohérent avec la dégradation silencieuse déjà pratiquée ailleurs dans le
    // projet (voir cli/local/advancedScan.js).
    log(`⚠️  Vérification impossible pour "${name}" (${ecosystem}) -- ${err.message} -- paquet laissé passer.`);
    return null;
  }
}

function proxyPassthrough(req, res, originBaseUrl) {
  const target = new URL(req.url, originBaseUrl);
  const isHttps = target.protocol === "https:";
  const requestFn = isHttps ? httpsRequest : httpRequest;

  const proxyReq = requestFn(
    {
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (isHttps ? 443 : 80),
      path: target.pathname + target.search,
      method: req.method,
      headers: { ...req.headers, host: target.hostname },
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    }
  );

  proxyReq.on("error", () => {
    if (!res.headersSent) res.writeHead(502, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "bad_gateway", reason: "registre réel injoignable" }));
  });

  req.pipe(proxyReq);
}

function sendBlocked(res, finding, name) {
  res.writeHead(404, { "content-type": "application/json" });
  // npm/pip n'afficheront à l'utilisateur qu'un "404 Not Found" générique pour ce paquet --
  // le détail complet (pourquoi) est toujours dans le journal du daemon, voir
  // firewallDaemon.js / FIREWALL_LOG_PATH, pour rester diagnosticable.
  res.end(JSON.stringify({ error: "not_found", reason: `kikard-firewall: "${name}" bloqué -- ${finding.title}` }));
}

// ecosystems: sous-ensemble de ["npm", "pypi"]. log: (line: string) => void, jamais async
// attendu par l'appelant (fire-and-forget, ne doit jamais ralentir une réponse HTTP).
export function createFirewallRequestHandler({ ecosystems, log }) {
  const npmEnabled = ecosystems.includes("npm");
  const pypiEnabled = ecosystems.includes("pypi");

  return async function handleRequest(req, res) {
    let pathname;
    try {
      pathname = new URL(req.url, "http://localhost").pathname;
    } catch {
      return proxyPassthrough(req, res, REAL_NPM_ORIGIN);
    }

    const upstream = pickUpstreamOrigin(pathname);

    if (req.method !== "GET") {
      // publish, whoami, audit, etc. -- jamais interceptés, transmis tels quels.
      return proxyPassthrough(req, res, upstream);
    }

    if (npmEnabled && upstream === REAL_NPM_ORIGIN) {
      const name = decodeNpmPackageNameFromPath(pathname);
      if (name) {
        const finding = await findBlockingReason(name, "npm", log);
        if (finding) {
          log(`🛑 BLOQUÉ (npm) : ${name} -- ${finding.title}`);
          return sendBlocked(res, finding, name);
        }
        log(`✅ Autorisé (npm) : ${name}`);
      }
      return proxyPassthrough(req, res, upstream);
    }

    if (pypiEnabled && upstream === REAL_PYPI_ORIGIN) {
      const name = decodePypiPackageNameFromPath(pathname);
      if (name) {
        const finding = await findBlockingReason(name, "pypi", log);
        if (finding) {
          log(`🛑 BLOQUÉ (pip) : ${name} -- ${finding.title}`);
          return sendBlocked(res, finding, name);
        }
        log(`✅ Autorisé (pip) : ${name}`);
      }
      return proxyPassthrough(req, res, upstream);
    }

    // Écosystème non activé pour cette requête -- transmise telle quelle, fail-open.
    return proxyPassthrough(req, res, upstream);
  };
}
