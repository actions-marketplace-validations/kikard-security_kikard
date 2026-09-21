#!/usr/bin/env node
/**
 * Kikard - Static Security Scanner (SAST) and dependency auditing designed to audit source code and detect critical vulnerabilities, exposed secrets, and *slopsquatting* (AI-induced hallucinations in packages).
 * Copyright 2026 Kikard
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { collectDependencies } from "../lib/parsers.js";
import { checkPackage, mapWithConcurrency } from "../lib/registries.js";
import { evaluate } from "../lib/heuristics.js";
import { printTerminalReport, buildJsonReport } from "../lib/report.js";
import { runStaticScans } from "../lib/staticScanners.js";
import { applyFixes } from "../lib/autofix.js";
import { generateHtmlReport } from "../lib/html-reporter.js";
import { buildFixPromptDocument, isFixPromptEligibleFinding } from "../lib/fixPrompt.js";
import { saveApiKey, clearApiKey, getLicenseStatus, loadConfig, checkScanQuota } from "../local/licensing.js";
import { verifyCertificateToken } from "../local/certify.js";
import { runAdvancedScan, getSupportedPremiumLanguages } from "../local/advancedScan.js";
import { startFirewall, stopFirewall, firewallStatus } from "../local/firewall.js";
import { isEligibleForAiFix, extractSnippetContext, requestAiFix, applyAiFix } from "../local/aiFix.js";
import { buildCycloneDxSbom } from "../lib/sbom.js";
import { createInterface } from "node:readline/promises";
import { createRequire } from "node:module";

// [13/09/2026] Kikard n'expose qu'un seul serveur de licence géré pour tous les paliers
// Free/Pro/Team (app.kikard.com) -- contrairement à des outils type Docker/GitLab CLI qui
// pointent vers plusieurs registres/instances valides, `--api-url` n'a donc pas lieu d'être
// obligatoire ici. Il reste disponible en override explicite (ex: future offre self-hosted/
// dédiée Enterprise, ou environnement de staging interne), mais `kikard login <clé-api>` seul
// doit fonctionner pour l'immense majorité des utilisateurs. Voir kikard-recap.md.
const DEFAULT_API_URL = "https://app.kikard.com";

const require = createRequire(import.meta.url);
// Best-effort uniquement -- n'affecte jamais le fonctionnement du CLI si le package.json
// n'est pas lisible pour une raison quelconque (ex: bundlers/pkg exotiques).
function getCliVersion() {
  try {
    return require("../package.json").version || "unknown";
  } catch {
    return "unknown";
  }
}

// [20/09/2026] "high" manquait ici alors que injections.js/php-patterns.js/java-patterns.js/
// go-patterns.js/ruby-patterns.js produisent bien des findings severity: "high" (XSS via
// innerHTML, SQLi par concaténation, etc. -- voir SEVERITY_ORDER déjà correct dans
// lib/report.js pour l'affichage). Conséquence avant ce correctif : SEVERITY_RANK[f.severity]
// valait `undefined` pour toute faille "high", et `undefined <= failThreshold` est toujours
// `false` en JS -- ces failles ne faisaient donc JAMAIS échouer --fail-on, quel que soit le
// seuil choisi (y compris --fail-on high lui-même). Repéré en vérifiant le format réel de
// buildJsonReport() avant la finalisation de l'Action GitHub (kikard-security/kikard#action.yml)
// -- ordre aligné sur SEVERITY_ORDER de lib/report.js.
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function parseArgs(argv) {
  const args = {
    target: ".",
    json: false,
    html: false,
    open: false,
    fix: false,
    fixPrompt: false,
    failOn: "critical",
    allow: ".kikardignore",
    concurrency: 8,
    advanced: false,
    aiFix: false,
    sbom: false,
    yes: false,
  };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") args.json = true;
    else if (a === "--html") {
      const nextArg = argv[i + 1];
      if (nextArg && !nextArg.startsWith("-")) {
        args.html = nextArg;
        i++;
      } else {
        args.html = true;
      }
    }
    else if (a === "--sbom") {
      const nextArg = argv[i + 1];
      if (nextArg && !nextArg.startsWith("-")) {
        args.sbom = nextArg;
        i++;
      } else {
        args.sbom = true;
      }
    }
    else if (a === "--fix-prompt") {
      const nextArg = argv[i + 1];
      if (nextArg && !nextArg.startsWith("-")) {
        args.fixPrompt = nextArg;
        i++;
      } else {
        args.fixPrompt = true;
      }
    }
    else if (a === "--open") args.open = true;
    else if (a === "--fix") args.fix = true;
    else if (a === "--fail-on") args.failOn = argv[++i];
    else if (a === "--allow") args.allow = argv[++i];
    else if (a === "--concurrency") args.concurrency = Number(argv[++i]) || 8;
    else if (a === "--advanced") args.advanced = true;
    else if (a === "--ai-fix") args.aiFix = true;
    else if (a === "--yes") args.yes = true;
    else rest.push(a);
  }
  if (rest[0] && rest[0] !== "scan") args.target = rest[0];
  if (rest[0] === "scan" && rest[1]) args.target = rest[1];
  return args;
}

async function loadAllowlist(dir, allowFile) {
  try {
    const raw = await readFile(path.join(dir, allowFile), "utf8");
    return new Set(
      raw
        .split(/\r?\n/)
        .map((l) => l.trim().toLowerCase())
        .filter((l) => l && !l.startsWith("#"))
    );
  } catch {
    return new Set();
  }
}

// Prompt de correction (--fix-prompt, gratuit -- voir lib/fixPrompt.js) : contrairement
// au dashboard (qui doit retélécharger le fichier concerné à la demande, voir
// dashboard/routes/fixPrompt.js), le CLI a déjà accès à tout le projet sur disque -- lit
// directement l'extrait de code autour de chaque faille éligible, en best-effort (un
// fichier introuvable/illisible ne fait jamais échouer la génération du prompt, la faille
// reste simplement décrite sans code joint).
const FIX_PROMPT_CONTEXT_LINES = 12;

async function buildCliSnippetsByIndex(findings, dir) {
  const map = new Map();
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    if (!isFixPromptEligibleFinding(f)) continue;
    const filePath = f.file || (f.location ? f.location.split(":")[0] : null);
    if (!filePath) continue;
    const lineFromLocation = f.location ? Number(f.location.split(":")[1]) : NaN;
    const line = f.line || (Number.isFinite(lineFromLocation) ? lineFromLocation : undefined);
    if (!line) continue; // pas de ligne précise (ex: RLS Supabase) -- le texte de la faille suffit déjà

    try {
      const fullPath = path.isAbsolute(filePath) ? filePath : path.join(dir, filePath);
      const content = await readFile(fullPath, "utf8");
      const lines = content.split(/\r?\n/);
      const centerIdx = Math.min(line - 1, lines.length - 1);
      const startIdx = Math.max(0, centerIdx - FIX_PROMPT_CONTEXT_LINES);
      const endIdx = Math.min(lines.length - 1, centerIdx + FIX_PROMPT_CONTEXT_LINES);
      const snippet = lines
        .slice(startIdx, endIdx + 1)
        .map((l, idx) => `${startIdx + idx + 1}: ${l}`)
        .join("\n");
      map.set(i, snippet);
    } catch {
      // Fichier introuvable/renommé/illisible depuis le scan -- ignoré silencieusement.
    }
  }
  return map;
}

async function main() {
  const subcommand = process.argv[2];

  // [20/09/2026] `--version`/`-v` n'était géré nulle part -- retombait silencieusement sur
  // le scan par défaut (le dossier courant était scanné). getCliVersion() existait déjà
  // (utilisée pour le champ toolVersion du SBOM, voir plus bas) mais n'était jamais exposée
  // en commande. Vérifié avant toute autre branche pour primer sur `scan .` par défaut.
  if (subcommand === "--version" || subcommand === "-v") {
    console.log(`kikard ${getCliVersion()}`);
    process.exit(0);
  }

  if (subcommand === "login") {
    const apiKey = process.argv[3];
    const apiUrlFlagIdx = process.argv.indexOf("--api-url");
    const apiUrl = apiUrlFlagIdx !== -1 ? process.argv[apiUrlFlagIdx + 1] : DEFAULT_API_URL;
    if (!apiKey) {
      console.error("Usage : kikard login <clé-api>");
      console.error("Génère une clé depuis https://app.kikard.com (Paramètres du compte).");
      console.error("(Optionnel : --api-url https://un-autre-serveur pour un serveur de licence dédié.)");
      process.exit(1);
    }
    await saveApiKey(apiKey, apiUrl);
    console.log("✅ Clé enregistrée. Vérification en cours...");
    const status = await getLicenseStatus();
    if (status.source === "verified") {
      console.log(`Connecté -- plan : ${status.plan}. Fonctions débloquées : ${status.features.join(", ") || "aucune"}.`);
      if (status.plan === "free") {
        console.log("Palier Free : 1000 scans/mois. Voir https://kikard.com/#pricing pour passer à Pro/Team.");
      }
      if (status.languages?.length) {
        console.log(`Scan avancé disponible pour : ${status.languages.join(", ")} (option --advanced, nécessite d'être en ligne).`);
      }
    } else {
      console.log("⚠️  Clé enregistrée, mais la vérification a échoué (réseau ou clé invalide). `kikard scan` nécessitant un compte vérifié, réessayez une fois en ligne, ou vérifiez votre clé.");
    }
    process.exit(0);
  }

  if (subcommand === "logout") {
    await clearApiKey();
    console.log("✅ Déconnecté -- le CLI repasse en mode gratuit.");
    process.exit(0);
  }

  // Pare-feu registre local ("interception avant installation") -- intercepte
  // `npm install`/`pip install` NATIFS avant qu'un paquet halluciné/typosquatté n'atteigne
  // le disque, même invoqués directement sans passer par `kikard scan`. Voir
  // cli/local/firewall.js et firewallProxy.js pour le détail du fonctionnement et des choix
  // de scope (v1 : npm + PyPI uniquement). La RÉSOLUTION de paquets reste 100% locale
  // (aucune donnée de code envoyée à kikard, aucun appel réseau vers kikard). [19/09/2026]
  // `kikard firewall` est gratuit et sans compte requis (voir kikard-decision-19092026-
  // modele-final-free-payant-firewall-sbom.md) -- la gate de plan introduite le 12/09
  // (`checkFirewallEntitlement`) a été retirée après audit : elle ne protégeait aucun
  // revenu réel (tout le code tourne en local, dans ce dépôt public) et se comparait
  // défavorablement à Socket Firewall (concurrent direct, gratuit sans compte).
  if (subcommand === "firewall") {
    const action = process.argv[3];
    if (action === "start") {
      const portIdx = process.argv.indexOf("--port");
      const port = portIdx !== -1 ? Number(process.argv[portIdx + 1]) || 7878 : 7878;
      const ecoIdx = process.argv.indexOf("--ecosystems");
      const ecosystems =
        ecoIdx !== -1
          ? process.argv[ecoIdx + 1].split(",").map((s) => s.trim()).filter(Boolean)
          : ["npm", "pypi"];
      const foreground = process.argv.includes("--foreground");
      await startFirewall({ port, ecosystems, foreground });
      process.exit(0);
    } else if (action === "stop") {
      await stopFirewall();
      process.exit(0);
    } else if (action === "status") {
      await firewallStatus();
      process.exit(0);
    } else {
      console.error("Usage : kikard firewall <start|stop|status> [--port 7878] [--ecosystems npm,pypi] [--foreground]");
      process.exit(1);
    }
  }

  // Norme KIKARD -- vérification publique d'un certificat (03/09/2026), voir local/certify.js
  // et l'article 8.3 du Référentiel technique ("vérifiable sans compte"). Contrairement à
  // `login`/`whoami` ci-dessus, `verify` n'a besoin d'AUCUNE clé API. [13/09/2026] `--api-url`
  // n'est plus requis non plus -- comme pour `login`, un seul serveur géré existe pour tous
  // les paliers (DEFAULT_API_URL), gardé en override explicite pour un futur self-hosted
  // Enterprise (même raisonnement que --advanced/--ai-fix, voir plus bas). L'appel reste anonyme.
  if (subcommand === "verify") {
    const token = process.argv[3];
    const apiUrlFlagIdx = process.argv.indexOf("--api-url");
    const apiUrlFlag = apiUrlFlagIdx !== -1 ? process.argv[apiUrlFlagIdx + 1] : undefined;
    if (!token) {
      console.error("Usage : kikard verify <jeton-de-certificat> [--api-url https://un-autre-serveur]");
      process.exit(1);
    }
    const config = await loadConfig();
    const apiUrl = apiUrlFlag || config?.apiUrl || DEFAULT_API_URL;

    const result = await verifyCertificateToken(token, apiUrl);

    if (result.error === "network") {
      console.error("❌ Vérification impossible : serveur injoignable (réseau ou --api-url incorrect).");
      process.exit(2);
    }
    if (result.error === "rate_limited") {
      console.error("⚠️  Trop de vérifications récentes depuis cette IP -- réessayez plus tard.");
      process.exit(2);
    }
    if (!result.found) {
      console.log("❌ Certificat introuvable -- jeton invalide, inconnu, ou mal recopié.");
      process.exit(1);
    }

    // Convention de nommage actée dans le récap projet -- la NORME utilise "Secure"
    // ("KIKARD Secure Code - <Famille>:<millésime>"), le RÉSULTAT/CERTIFICAT utilise
    // "Security" ("Certified KIKARD Security Code - <Famille>:<millésime>"). Jamais
    // d'abréviation de KIKARD, ici ou ailleurs.
    const label = `Certified KIKARD Security Code - ${result.familyNameFr}:${result.vintageYear}`;
    console.log(`\n${label}`);
    console.log(`Dépôt certifié : ${result.repoFullName}`);
    console.log(`Palier : ${String(result.level || "").toUpperCase()}`);
    console.log(`Émis le : ${new Date(result.issuedAt).toLocaleDateString("fr-FR")}`);

    if (result.revoked) {
      console.log(`⚠️  RÉVOQUÉ le ${new Date(result.revokedAt).toLocaleDateString("fr-FR")}${result.revokedReason ? ` (${result.revokedReason})` : ""}.`);
      process.exit(1);
    }
    if (result.expired) {
      console.log(`⚠️  EXPIRÉ depuis le ${new Date(result.expiresAt).toLocaleDateString("fr-FR")}.`);
      process.exit(1);
    }
    console.log(`✅ Valide jusqu'au ${new Date(result.expiresAt).toLocaleDateString("fr-FR")}.`);
    process.exit(0);
  }

  if (subcommand === "whoami") {
    const config = await loadConfig();
    if (!config?.apiKey) {
      console.log("Non connecté -- `kikard scan` nécessite un compte (palier Free inclus, 1000 scans/mois).");
      console.log("Créez un compte sur https://app.kikard.com puis : kikard login <clé-api>");
      process.exit(0);
    }
    const status = await getLicenseStatus();
    console.log(`Plan : ${status.plan}`);
    console.log(`Fonctions avancées débloquées : ${status.features.join(", ") || "aucune"}`);
    console.log(`Langages pour le scan avancé (--advanced) : ${status.languages?.join(", ") || "aucun"}`);
    console.log(`Source : ${status.source}${status.source === "offline" || status.source === "stale-cache" ? " (impossible de vérifier auprès du serveur -- dernier statut connu utilisé)" : ""}`);
    process.exit(0);
  }

  // [12/09/2026] Compte obligatoire dès `kikard scan` (voir kikard-update-12092026-
  // nouveau-modele-economique.md) -- palier Free inclus, mais plus d'usage anonyme. Deux
  // vérifications distinctes, volontairement séparées :
  //  1. Un compte a-t-il déjà été lié une fois (kikard login) ? Basé sur getLicenseStatus()
  //     (cache 1h, tolérant hors-ligne une fois vérifié au moins une fois) -- ne bloque PAS
  //     un scan juste parce que le réseau est momentanément indisponible pour un compte déjà
  //     connu, cohérent avec le reste de ce fichier (--advanced, --ai-fix).
  //  2. Le quota mensuel (checkScanQuota, voir licensing.js) -- lui DOIT être vérifié en
  //     ligne à chaque scan (jamais mis en cache), mais se dégrade toujours vers "autorisé"
  //     en cas de panne réseau/serveur -- ne bloque que sur un quota RÉELLEMENT dépassé,
  //     confirmé par le serveur.
  const accountConfig = await loadConfig();
  if (!accountConfig?.apiKey || !accountConfig?.apiUrl) {
    console.error("❌ Un compte kikard est requis pour scanner (palier Free inclus, 1000 scans/mois).");
    console.error("   Créez un compte gratuit sur https://app.kikard.com puis :");
    console.error("   kikard login <votre-clé-api>");
    process.exit(1);
  }
  const accountStatus = await getLicenseStatus();
  if (accountStatus.source === "invalid-key") {
    console.error("❌ Clé API invalide ou révoquée -- reconnectez-vous :");
    console.error("   kikard login <votre-clé-api>");
    process.exit(1);
  }

  const quota = await checkScanQuota();
  if (!quota.ok && quota.reason === "quota_exceeded") {
    console.error(`❌ Quota mensuel atteint (${quota.used}/${quota.limit} scans ce mois-ci sur le palier Free).`);
    console.error("   Passez à Pro pour des scans illimités : https://kikard.com/#pricing");
    process.exit(1);
  }
  if (!quota.ok && quota.reason === "invalid-key") {
    console.error("❌ Clé API invalide ou révoquée -- reconnectez-vous :");
    console.error("   kikard login <votre-clé-api>");
    process.exit(1);
  }
  // Autres cas (degraded: hors ligne, erreur serveur, ou quota OK) : on continue, voir le
  // commentaire ci-dessus -- une panne qui n'est pas la faute de l'utilisateur ne doit
  // jamais l'empêcher de scanner.

  const startTime = Date.now();
  const args = parseArgs(process.argv.slice(2));
  const dir = path.resolve(args.target);

  // 1. Exécution parallèle : Collecte des dépendances + Scans Statiques (Injection, Crypto, BDD, Config)
  const [{ deps, errors }, allowlist, staticFindings] = await Promise.all([
    collectDependencies(dir),
    loadAllowlist(dir, args.allow),
    runStaticScans(dir),
  ]);

  for (const err of errors) console.error(`kikard: ${err}`);

  const toCheck = deps.filter((d) => !allowlist.has(d.name.toLowerCase()));
  const findings = [...staticFindings];

  // 2. Scan AI / Package Intelligence sur les dépendances
  if (toCheck.length > 0) {
    const registryResults = await mapWithConcurrency(toCheck, args.concurrency, (dep) => checkPackage(dep));

    for (let i = 0; i < toCheck.length; i++) {
      const finding = await evaluate(toCheck[i], registryResults[i]);
      if (finding) findings.push(finding);
    }
  }

  // 2.5. Scan avancé -- optionnel, opt-in explicite via --advanced UNIQUEMENT ("option B",
  // voir le récap projet pour l'analyse de sécurité complète). Sans ce flag, ce bloc ne
  // s'exécute jamais : kikard reste strictement identique et 100% fonctionnel hors ligne.
  // Avec --advanced, kikard reste 100% fonctionnel hors ligne EN PLUS de pouvoir, une fois
  // connecté à un compte éligible, bénéficier d'une vérification supplémentaire côté
  // serveur pour un langage premium (C#/.NET pour l'instant). Toute défaillance ici
  // (non connecté, plan insuffisant, réseau indisponible, serveur en erreur) se dégrade
  // silencieusement vers le scan local déjà effectué ci-dessus -- ne fait jamais échouer
  // `kikard scan`.
  const premiumScanSummary = [];
  if (args.advanced) {
    const advancedConfig = await loadConfig();
    if (!advancedConfig?.apiKey || !advancedConfig?.apiUrl) {
      console.log("ℹ️  --advanced ignoré : non connecté (voir `kikard login <clé-api>`). Le scan local reste complet.");
    } else {
      const status = await getLicenseStatus();
      const eligibleLanguages = getSupportedPremiumLanguages().filter((lang) => status.languages?.includes(lang));
      if (eligibleLanguages.length === 0) {
        console.log("ℹ️  --advanced ignoré : aucun langage de scan avancé disponible pour votre plan actuel (voir kikard.com/pricing). Le scan local reste complet.");
      }
      for (const language of eligibleLanguages) {
        // Transparence explicite avant tout envoi réseau -- ce qui est transmis (et ce qui
        // ne l'est jamais) est annoncé, à chaque exécution, jamais silencieusement.
        console.log(`📡 Scan avancé (${language}) : envoi des fichiers de manifeste de dépendances concernés (ex: .csproj, packages.config -- jamais le reste du code source) à ${advancedConfig.apiUrl} pour vérification côté serveur.`);
        const result = await runAdvancedScan({ dir, language, apiUrl: advancedConfig.apiUrl, apiKey: advancedConfig.apiKey });
        if (!result.attempted) {
          console.log(`ℹ️  Scan avancé (${language}) : aucun fichier pertinent trouvé dans ce dossier, rien à envoyer.`);
        } else if (result.ok) {
          findings.push(...result.findings);
          console.log(`✅ Scan avancé (${language}) : ${result.dependenciesScanned} dépendance(s) vérifiée(s) côté serveur.`);
        } else {
          console.log(`⚠️  Scan avancé (${language}) indisponible (${result.reason}) -- résultats basés uniquement sur le scan local.`);
        }
        premiumScanSummary.push({ language, ...result });
      }
    }
  }

  // 2.6. Applicatif de correction de code automatique (IA) -- optionnel, opt-in explicite
  // via --ai-fix UNIQUEMENT (comme --advanced). Décision produit du 01/09/2026 : APERÇU +
  // CONFIRMATION OBLIGATOIRE pour chaque faille, jamais une application automatique et
  // silencieuse -- un correctif généré par IA peut être faux ou casser du code, contrairement
  // à --fix ci-dessous (patterns déterministes jugés 100% sûrs). Toute défaillance (non
  // connecté, plan insuffisant, réseau indisponible, serveur en erreur) se dégrade
  // silencieusement -- ne fait jamais échouer `kikard scan`. --yes saute les confirmations
  // (utile en script/CI non interactif) mais reste un choix explicite de l'utilisateur au
  // moment de l'invocation, pas un défaut.
  if (args.aiFix) {
    const aiFixConfig = await loadConfig();
    if (!aiFixConfig?.apiKey || !aiFixConfig?.apiUrl) {
      console.log("ℹ️  --ai-fix ignoré : non connecté (voir `kikard login <clé-api>`).");
    } else {
      const status = await getLicenseStatus();
      if (!status.features?.includes("ai_auto_fix")) {
        console.log("ℹ️  --ai-fix ignoré : fonctionnalité non disponible pour votre plan actuel (voir kikard.com/pricing).");
      } else {
        const eligible = findings.filter(isEligibleForAiFix);
        if (eligible.length === 0) {
          console.log("ℹ️  --ai-fix : aucune faille éligible à un correctif de code dans ce scan.");
        } else {
          console.log(`\n🤖 Génération de correctif(s) IA pour ${eligible.length} faille(s) éligible(s)...\n`);
          const backedUpFiles = new Set();
          let appliedCount = 0;
          const rl = args.yes ? null : createInterface({ input: process.stdin, output: process.stdout });

          for (const finding of eligible) {
            const snippetCtx = await extractSnippetContext(dir, finding);
            if (!snippetCtx) continue; // fichier introuvable/illisible -- ignoré silencieusement

            const result = await requestAiFix({ apiUrl: aiFixConfig.apiUrl, apiKey: aiFixConfig.apiKey, finding, snippetCtx });
            if (!result.ok || !result.fixedSnippet) {
              console.log(`⚠️  ${finding.ruleId || finding.title} (${path.relative(dir, snippetCtx.fullPath)}) : ${result.reason || "aucun correctif proposé"}`);
              continue;
            }

            console.log(`\n— ${finding.ruleId || finding.title} — ${path.relative(dir, snippetCtx.fullPath)}:${snippetCtx.startLine}-${snippetCtx.endLine} (confiance : ${result.confidence || "moyenne"})`);
            console.log(result.explanation || "");
            console.log("--- avant ---");
            console.log(snippetCtx.rawSnippet);
            console.log("--- après (suggestion) ---");
            console.log(result.fixedSnippet);

            let confirmed = args.yes;
            if (!confirmed && rl) {
              const answer = await rl.question("Appliquer ce correctif ? (o/N) ");
              confirmed = /^o(ui)?$/i.test(answer.trim());
            }

            if (confirmed) {
              const applyResult = await applyAiFix({
                fullPath: snippetCtx.fullPath,
                rawSnippet: snippetCtx.rawSnippet,
                fixedSnippet: result.fixedSnippet,
                backedUpFiles,
              });
              if (applyResult.applied) {
                appliedCount++;
                console.log("✅ Correctif appliqué.");
              } else {
                console.log(`⚠️  Correctif non appliqué : ${applyResult.reason}`);
              }
            } else {
              console.log("↷ Ignoré.");
            }
          }

          if (rl) rl.close();
          console.log(`\n${appliedCount} correctif(s) IA appliqué(s)${backedUpFiles.size ? ` (sauvegarde .kikard.bak créée pour ${backedUpFiles.size} fichier(s) modifié(s))` : ""}.`);
          if (appliedCount > 0) console.log("👉 Relancez 'kikard scan .' pour mettre à jour le rapport.");
        }
      }
    }
    process.exit(0);
  }

  // 3. Application des correctifs automatiques sécurisés si --fix est passé
  if (args.fix) {
    if (!args.json) {
      console.log("\n🛠️  Application des correctifs automatiques sécurisés...\n");
    }
    const { fixedCount, skippedRlsCount } = await applyFixes(findings, dir);
    if (!args.json) {
      if (fixedCount > 0) {
        console.log(`✅ ${fixedCount} vulnérabilité(s) corrigée(s) avec succès (sauvegarde .kikard.bak créée pour chaque fichier modifié).`);
        console.log("👉 Relancez 'kikard scan .' pour mettre à jour le rapport.\n");
      } else {
        console.log("ℹ️  Aucun correctif automatique 100 % sûr n'a pu être appliqué aux failles détectées.\n");
      }
      if (skippedRlsCount > 0) {
        console.log(`⚠️  ${skippedRlsCount} finding(s) RLS Supabase non corrigés automatiquement : activer RLS sans policy rendrait la table inaccessible. Traitement manuel requis.\n`);
      }
    }
    process.exit(0);
  }

  const durationMs = Date.now() - startTime;
  const meta = {
    // [20/09/2026] `report.js` (printTerminalReport / buildJsonReport) lit meta.scanned --
    // la clé s'appelait `scannedDependencies` ici, donc la ligne d'intro et le JSON
    // affichaient un compte vide depuis toujours. Constaté sur un vrai `kikard scan`,
    // corrigé ici (pas de `filesScanned` : ce compte n'est pas suivi dans le CLI packagé,
    // report.js l'omet proprement tant que la valeur reste undefined).
    scanned: toCheck.length,
    totalFindings: findings.length,
    premiumScan: premiumScanSummary.length ? premiumScanSummary : undefined,
  };

  // 4. Génération du rapport HTML interactif si --html est spécifié
  if (args.html) {
    try {
      const defaultFileName = "kikard-report.html";
      const userProvidedPath = typeof args.html === "string" ? args.html : defaultFileName;
      
      const outputFile = path.isAbsolute(userProvidedPath)
        ? userProvidedPath
        : path.join(dir, userProvidedPath);

      const { filePath, fileUrl } = await generateHtmlReport(
        {
          findings,
          targetDir: dir,
          durationMs,
          totalDeps: toCheck.length,
        },
        outputFile
      );

      const gen_report = `\n📄 Rapport HTML bien généré : \x1b[4m\x1b[36m${fileUrl}\x1b[0m\n`;

      // S'assure d'afficher l'URL file:// même si args.json est faux
      console.log(gen_report);

      // Ouverture automatique sécurisée sans invocation de shell dangereux
      if (args.open) {
        let command = "";
        let cmdArgs = [];

        if (process.platform === "win32") {
          command = "cmd.exe";
          cmdArgs = ["/c", "start", "", filePath];
        } else if (process.platform === "darwin") {
          command = "open";
          cmdArgs = [filePath];
        } else {
          command = "xdg-open";
          cmdArgs = [filePath];
        }

        execFile(command, cmdArgs, (err) => {
          if (err) console.error("⚠️ Impossible d'ouvrir le navigateur automatique :", err.message);
        });
      }
    } catch (err) {
      console.error("❌ Erreur lors de la génération du rapport HTML :", err.message);
    }
  }

  // 4bis. Génération du prompt de correction si --fix-prompt est spécifié -- GRATUIT,
  // 100% local (voir lib/fixPrompt.js) : aucun appel réseau, aucune clé API, contrairement
  // à --ai-fix ci-dessus. kikard prépare seulement la question à poser à un assistant IA
  // externe de votre choix -- c'est lui (ou vous) qui produit et valide le correctif.
  if (args.fixPrompt) {
    try {
      const snippetsByIndex = await buildCliSnippetsByIndex(findings, dir);
      const document = buildFixPromptDocument(findings, snippetsByIndex);
      if (!document) {
        console.log("\nℹ️  Aucune faille ne se prête à un prompt de correction (les dépendances hallucinées n'ont pas d'emplacement de code à décrire -- retirez/remplacez-les directement).\n");
      } else {
        const defaultFileName = "kikard-fix-prompt.md";
        const userProvidedPath = typeof args.fixPrompt === "string" ? args.fixPrompt : defaultFileName;
        const outputFile = path.isAbsolute(userProvidedPath) ? userProvidedPath : path.join(dir, userProvidedPath);
        await writeFile(outputFile, document, "utf8");
        console.log(`\n📋 Prompt de correction généré : \x1b[4m\x1b[36m${outputFile}\x1b[0m`);
        console.log("👉 Copiez son contenu dans l'assistant IA de votre choix (ChatGPT, Claude, etc.).\n");
      }
    } catch (err) {
      console.error("❌ Erreur lors de la génération du prompt de correction :", err.message);
    }
  }

  // 4ter. Génération d'un SBOM CycloneDX si --sbom est spécifié -- optionnel, opt-in
  // explicite. [19/09/2026] Gratuit, sans compte requis (voir kikard-decision-19092026-
  // modele-final-free-payant-firewall-sbom.md) : le gating Team introduit le 13/09 (feature
  // "export_sbom") est retiré -- la génération tournait déjà 100% en local sans aucun appel
  // serveur, la gate ne protégeait donc aucun revenu réel et le marché entier (Syft, Trivy,
  // cdxgen, CycloneDX CLI) donne déjà cet export gratuitement.
  // Dégradation : toute erreur d'écriture affiche un message ❌ mais le scan et son rapport
  // (terminal/JSON/HTML) restent produits normalement, jamais bloqués par ceci.
  if (args.sbom) {
    try {
      const sbomDoc = buildCycloneDxSbom({ deps, targetDir: dir, toolVersion: getCliVersion() });
      const defaultFileName = "kikard-sbom.json";
      const userProvidedPath = typeof args.sbom === "string" ? args.sbom : defaultFileName;
      const outputFile = path.isAbsolute(userProvidedPath) ? userProvidedPath : path.join(dir, userProvidedPath);
      await writeFile(outputFile, JSON.stringify(sbomDoc, null, 2), "utf8");
      console.log(`\n📦 SBOM (CycloneDX) généré : \x1b[4m\x1b[36m${outputFile}\x1b[0m (${sbomDoc.components.length} composant(s)).`);
      console.log("ℹ️  Les versions listées sont les contraintes déclarées dans vos manifestes, pas des versions résolues depuis un lockfile.\n");
    } catch (err) {
      console.error("❌ Erreur lors de la génération du SBOM :", err.message);
    }
  }

  // 5. Rapport d'exécution Terminal ou JSON
  if (args.json) {
    console.log(JSON.stringify(buildJsonReport(findings, meta), null, 2));
  } else {
    printTerminalReport(findings, meta);
  }

  const failThreshold = SEVERITY_RANK[args.failOn] ?? 0;
  const hasBlockingFinding = findings.some((f) => SEVERITY_RANK[f.severity] <= failThreshold);
  process.exit(hasBlockingFinding ? 1 : 0);
}

main().catch((err) => {
  console.error("kikard: erreur inattendue --", err.message);
  process.exit(2);
});