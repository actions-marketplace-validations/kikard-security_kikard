#!/usr/bin/env node
// Processus démon du pare-feu registre local ("kikard firewall") -- lancé en arrière-plan
// (détaché) par `kikard firewall start` (voir firewall.js / bin/kikard.js). Ce fichier n'est
// JAMAIS importé ailleurs : c'est un point d'entrée autonome, invoqué via
// `node firewallDaemon.js --port <port> --ecosystems npm,pypi`.
//
// Rôle : démarre le serveur proxy (firewallProxy.js), reconfigure npm/pip pour rediriger les
// commandes natives vers ce proxy, écrit son état (firewallState.js) une fois prêt, et
// restaure la configuration d'origine à l'arrêt (signal, ou tué par `kikard firewall stop`)
// -- jamais de configuration npm/pip laissée cassée silencieusement sur la machine.
import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { appendFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { createFirewallRequestHandler } from "./firewallProxy.js";
import { writeFirewallState, FIREWALL_LOG_PATH } from "./firewallState.js";

// [19/09/2026] La re-vérification périodique d'abonnement (introduite le 12/09) a été
// retirée avec le reste du gating -- kikard firewall est de nouveau gratuit, sans compte
// requis. Voir kikard-decision-19092026-modele-final-free-payant-firewall-sbom.md.

const execFileAsync = promisify(execFile);
// npm/pip sont typiquement des scripts (.cmd) sous Windows -- execFile sans shell ne les
// trouve pas dans ce cas, d'où ce shell conditionnel (même précaution que le reste du CLI
// pour l'ouverture de rapport HTML, voir bin/kikard.js).
const TOOL_EXEC_OPTS = { shell: process.platform === "win32" };

function parseArgs(argv) {
  const args = { port: 7878, ecosystems: ["npm", "pypi"] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--port") args.port = Number(argv[++i]) || 7878;
    else if (argv[i] === "--ecosystems") {
      args.ecosystems = (argv[++i] || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    }
  }
  return args;
}

async function log(line) {
  const stamped = `[${new Date().toISOString()}] ${line}\n`;
  try {
    await mkdir(path.dirname(FIREWALL_LOG_PATH), { recursive: true });
    await appendFile(FIREWALL_LOG_PATH, stamped);
  } catch {
    // best-effort -- un problème d'écriture du journal ne doit jamais arrêter le pare-feu
  }
}

async function getNpmRegistry() {
  try {
    const { stdout } = await execFileAsync("npm", ["config", "get", "registry"], TOOL_EXEC_OPTS);
    return stdout.trim() || null;
  } catch {
    return null; // npm introuvable -- l'écosystème npm sera simplement ignoré plus bas
  }
}

async function setNpmRegistry(url) {
  await execFileAsync("npm", ["config", "set", "registry", url], TOOL_EXEC_OPTS);
}

async function getPipIndexUrl() {
  try {
    // `pip config get` échoue (code retour non nul) si la clé n'est pas définie -- ce n'est
    // pas une erreur, ça signifie juste "pip utilise son index par défaut" (PyPI).
    const { stdout } = await execFileAsync("pip", ["config", "get", "global.index-url"], TOOL_EXEC_OPTS);
    return stdout.trim() || null;
  } catch {
    return null;
  }
}

async function setPipIndexUrl(url) {
  await execFileAsync("pip", ["config", "set", "global.index-url", url], TOOL_EXEC_OPTS);
}

async function unsetPipIndexUrl() {
  try {
    await execFileAsync("pip", ["config", "unset", "global.index-url"], TOOL_EXEC_OPTS);
  } catch {
    // rien à retirer -- pip utilisait déjà son index par défaut
  }
}

async function main() {
  const { port, ecosystems } = parseArgs(process.argv.slice(2));
  const originalNpmRegistry = ecosystems.includes("npm") ? await getNpmRegistry() : null;
  const originalPipIndexUrl = ecosystems.includes("pypi") ? await getPipIndexUrl() : null;

  const server = createServer(createFirewallRequestHandler({ ecosystems, log: (line) => log(line) }));

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });

  // On n'active la redirection npm/pip QUE pour les outils réellement présents et
  // reconfigurables -- un `npm config set` qui réussit prouve que npm existe sur la machine ;
  // s'il échoue (outil absent), cet écosystème est simplement ignoré plutôt que de faire
  // échouer tout le pare-feu.
  const applied = [];
  if (ecosystems.includes("npm")) {
    try {
      await setNpmRegistry(`http://127.0.0.1:${port}/`);
      applied.push("npm");
    } catch (err) {
      await log(`⚠️  Impossible de configurer npm (npm introuvable ?) -- ${err.message}`);
    }
  }
  if (ecosystems.includes("pypi")) {
    try {
      await setPipIndexUrl(`http://127.0.0.1:${port}/simple/`);
      applied.push("pypi");
    } catch (err) {
      await log(`⚠️  Impossible de configurer pip (pip introuvable ?) -- ${err.message}`);
    }
  }

  await writeFirewallState({
    pid: process.pid,
    port,
    ecosystems: applied,
    originalNpmRegistry,
    originalPipIndexUrl,
    startedAt: new Date().toISOString(),
  });

  await log(`🛡️  kikard firewall démarré sur 127.0.0.1:${port} -- écosystèmes actifs : ${applied.join(", ") || "aucun"}.`);

  let shuttingDown = false;
  async function shutdown(reason) {
    if (shuttingDown) return;
    shuttingDown = true;
    await log(`Arrêt du pare-feu${reason ? ` (${reason})` : ""} -- restauration de la configuration npm/pip...`);
    try {
      if (applied.includes("npm") && originalNpmRegistry) {
        await setNpmRegistry(originalNpmRegistry);
      }
      if (applied.includes("pypi")) {
        if (originalPipIndexUrl) await setPipIndexUrl(originalPipIndexUrl);
        else await unsetPipIndexUrl();
      }
      await log("✅ Configuration npm/pip d'origine restaurée.");
    } catch (err) {
      await log(`⚠️  Restauration partielle -- ${err.message}. Relancez 'kikard firewall stop' ou reconfigurez manuellement (npm config set registry / pip config set global.index-url).`);
    }
    server.close();
    process.exit(0);
  }

  process.on("SIGINT", () => shutdown());
  process.on("SIGTERM", () => shutdown());
}

main().catch(async (err) => {
  await log(`❌ Échec du démarrage du pare-feu -- ${err.message}`);
  process.exit(1);
});
