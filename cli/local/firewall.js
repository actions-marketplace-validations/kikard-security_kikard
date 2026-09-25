// Orchestration du pare-feu registre local, appelée par `kikard firewall <start|stop|status>`
// (voir bin/kikard.js). Sépare le PILOTAGE (un process de courte durée, celui qui exécute la
// commande `kikard firewall ...`) du DAEMON lui-même (firewallDaemon.js, qui tourne en
// continu en arrière-plan -- voir ce fichier pour le fonctionnement du proxy et la
// restauration de configuration).
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readFirewallState, clearFirewallState, FIREWALL_LOG_PATH } from "./firewallState.js";

const execFileAsync = promisify(execFile);
const TOOL_EXEC_OPTS = { shell: process.platform === "win32" };
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DAEMON_PATH = path.join(__dirname, "firewallDaemon.js");

// [19/09/2026] kikard firewall repasse gratuit, sans compte requis (voir kikard-decision-
// 19092026-modele-final-free-payant-firewall-sbom.md) : la gate de plan (checkFirewallEntitlement,
// introduite le 12/09) a été retirée après audit -- tout le travail réel (proxy npm/pip local)
// tourne 100% en local dans ce dépôt public, donc la gate ne protégeait aucun revenu réel et
// se comparait défavorablement à Socket Firewall (concurrent direct, gratuit sans compte). Le
// firewall suit désormais la même logique de notoriété/distribution que le moteur de scan de
// base. Une future version payante défendable existerait sous forme d'infrastructure réseau
// centralisée imposée par l'IT (façon Sonatype Repository Firewall) -- voir ROADMAP.md.

function isProcessAlive(pid) {
  try {
    // signal 0 : ne tue rien, vérifie juste que le PID existe et nous appartient.
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function killProcess(pid) {
  if (process.platform === "win32") {
    // Le daemon est lancé détaché (`detached: true`) -- sous Windows, ça crée son propre
    // groupe de process, `taskkill /t` s'assure qu'il est bien arrêté.
    try {
      await execFileAsync("taskkill", ["/pid", String(pid), "/f", "/t"]);
    } catch {
      // déjà arrêté -- rien à faire
    }
  } else {
    try {
      process.kill(pid, "SIGTERM");
    } catch {
      // déjà arrêté
    }
  }
}

export async function startFirewall({ port, ecosystems, foreground }) {
  const existing = await readFirewallState();
  if (existing && isProcessAlive(existing.pid)) {
    console.log(`ℹ️  Le pare-feu tourne déjà (PID ${existing.pid}, port ${existing.port}). Lancez 'kikard firewall stop' d'abord pour changer la configuration.`);
    return;
  }

  const daemonArgs = [DAEMON_PATH, "--port", String(port), "--ecosystems", ecosystems.join(",")];

  if (foreground) {
    console.log(`🛡️  Démarrage du pare-feu au premier plan sur le port ${port} (Ctrl+C pour arrêter et restaurer la configuration npm/pip)...`);
    const child = spawn(process.execPath, daemonArgs, { stdio: "inherit" });
    await new Promise((resolve) => child.on("exit", resolve));
    return;
  }

  const child = spawn(process.execPath, daemonArgs, { detached: true, stdio: "ignore" });
  child.unref();

  // Le daemon écrit son état (firewallState.js) une fois le serveur démarré et la config
  // npm/pip appliquée -- on patiente un court instant pour donner un retour utile
  // immédiatement plutôt que de laisser l'utilisateur deviner si ça a fonctionné.
  // [24/09/2026] Fenêtre élargie de 3s à 8s (20x150ms -> 40x200ms) suite à un bug de terrain :
  // sur certaines machines Windows, la (re)configuration npm/pip côté daemon (firewallDaemon.js)
  // pouvait à elle seule dépasser 3s (résolution PATH lente pour un outil absent, ex. pip non
  // installé) -- le pare-feu démarrait correctement mais ce délai trop court affichait quand
  // même l'avertissement "démarrage non confirmé" ci-dessous. Le daemon borne maintenant chaque
  // appel npm/pip à 4s (voir TOOL_EXEC_OPTS dans firewallDaemon.js), donc 8s ici couvre
  // confortablement le pire cas (vérif présence + éventuel appel de config, par écosystème).
  let state = null;
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 200));
    state = await readFirewallState();
    if (state && state.pid === child.pid) break;
  }

  if (!state || state.pid !== child.pid) {
    console.log(`⚠️  Le pare-feu a été lancé (PID ${child.pid}) mais son démarrage n'a pas pu être confirmé après 8s -- il continue probablement de démarrer en arrière-plan. Vérifiez dans quelques instants avec 'kikard firewall status', ou consultez ${FIREWALL_LOG_PATH}.`);
    return;
  }

  console.log(`🛡️  kikard firewall actif -- port ${state.port}, écosystèmes protégés : ${state.ecosystems.join(", ") || "aucun (npm/pip introuvables ?)"}.`);
  console.log("   Toute installation npm/pip native (même sans passer par kikard) est désormais vérifiée avant d'aboutir.");
  console.log(`   Journal : ${FIREWALL_LOG_PATH}`);
  console.log("   Pour arrêter et restaurer la configuration d'origine : kikard firewall stop");
}

async function restoreFromState(state) {
  if (state.ecosystems?.includes("npm") && state.originalNpmRegistry) {
    await execFileAsync("npm", ["config", "set", "registry", state.originalNpmRegistry], TOOL_EXEC_OPTS);
  }
  if (state.ecosystems?.includes("pypi")) {
    if (state.originalPipIndexUrl) {
      await execFileAsync("pip", ["config", "set", "global.index-url", state.originalPipIndexUrl], TOOL_EXEC_OPTS);
    } else {
      await execFileAsync("pip", ["config", "unset", "global.index-url"], TOOL_EXEC_OPTS).catch(() => {});
    }
  }
}

export async function stopFirewall() {
  const state = await readFirewallState();
  if (!state) {
    console.log("ℹ️  Aucun pare-feu actif connu (rien à arrêter).");
    return;
  }

  if (isProcessAlive(state.pid)) {
    await killProcess(state.pid);
    // Le signal déclenche la restauration DANS firewallDaemon.js lui-même -- laisser un
    // court instant pour qu'elle s'effectue avant de considérer que c'est fait.
    await new Promise((r) => setTimeout(r, 500));
  } else {
    // Le process n'existe déjà plus (crash, redémarrage de la machine...) -- restaurer
    // nous-mêmes la config npm/pip pour ne jamais laisser une machine pointée vers un
    // registre local mort.
    console.log("⚠️  Le process du pare-feu n'existait déjà plus -- restauration directe de la configuration npm/pip.");
    try {
      await restoreFromState(state);
    } catch (err) {
      console.log(`⚠️  Restauration automatique incomplète (${err.message}) -- vérifiez 'npm config get registry' / 'pip config get global.index-url' manuellement.`);
    }
  }

  await clearFirewallState();
  console.log("✅ Pare-feu arrêté, configuration npm/pip d'origine restaurée.");
}

export async function firewallStatus() {
  const state = await readFirewallState();
  if (!state || !isProcessAlive(state.pid)) {
    console.log("Pare-feu : inactif.");
    if (state) await clearFirewallState(); // état orphelin (process mort) -- nettoyage
    return;
  }
  console.log(`Pare-feu : actif (PID ${state.pid}, port ${state.port}, depuis ${state.startedAt}).`);
  console.log(`Écosystèmes protégés : ${state.ecosystems.join(", ") || "aucun"}.`);
  console.log(`Journal : ${FIREWALL_LOG_PATH}`);
}
