// Persistance de l'état du pare-feu registre local ("kikard firewall") -- PID du daemon,
// port, écosystèmes actifs, et valeurs ORIGINALES de config npm/pip à restaurer au `stop`.
// Même répertoire que licensing.js (~/.kikard/) mais fichier séparé : la clé API/licence
// et l'état du pare-feu sont deux préoccupations indépendantes.
import { readFile, writeFile, mkdir, unlink } from "node:fs/promises";
import path from "node:path";
import os from "node:os";

const STATE_DIR = path.join(os.homedir(), ".kikard");
const STATE_PATH = path.join(STATE_DIR, "firewall-state.json");
export const FIREWALL_LOG_PATH = path.join(STATE_DIR, "firewall.log");

export async function readFirewallState() {
  try {
    const raw = await readFile(STATE_PATH, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function writeFirewallState(state) {
  await mkdir(STATE_DIR, { recursive: true });
  // mode 0o600 -- même précaution que config.json (licensing.js) : ce fichier ne contient
  // pas de secret, mais garder une convention de permissions uniforme dans ~/.kikard/.
  await writeFile(STATE_PATH, JSON.stringify(state, null, 2), { mode: 0o600 });
}

export async function clearFirewallState() {
  try {
    await unlink(STATE_PATH);
  } catch {
    // déjà absent -- rien à faire
  }
}
