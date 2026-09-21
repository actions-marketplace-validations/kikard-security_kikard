# kikard

Scanner de sécurité statique (SAST) et d'audit de dépendances conçu pour auditer le code source et détecter les failles critiques, les secrets exposés et le *slopsquatting* (packages hallucinés par les IA).

---

## Ce que kikard détecte

### 1. Sécurité du Code Source & Contextuelle
* **Injections & XSS** : `eval()`, affectations directes à `innerHTML`, `dangerouslySetInnerHTML` et injections SQL par concaténation (avec suggestions adaptées si **Supabase** ou **Prisma** est détecté).
* **Command Injection** : Appel aux fonctions système (`exec`, `spawn`) avec arguments dynamiques.
* **Base de données & BaaS** : Tables **Supabase** sans Row Level Security (RLS) active et règles **Firebase** trop permissives (`allow read, write: if true`).
* **Cryptographie faible** : Utilisation d'algorithmes obsolètes (`MD5`, `SHA1`) et de `Math.random()` pour des données sensibles.
* **Configurations Web** : Wildcards CORS (`*`) et cookies définis sans l'attribut `httpOnly`.
* **Endpoints API non protégés** : Routes API d'un projet sans vérification d'authentification apparente.

### 2. Secrets en clair
* Clés AWS, OpenAI, Stripe, Google, clés privées RSA/SSH et tokens d'API génériques codés en dur.

### 3. Hallucination de packages (Slopsquatting)
* Packages `npm`, `PyPI`, `crates.io`, `Packagist`, modules `Go`, gems `RubyGems` ou dépendances `Maven` inexistants ou suspects, suggérés par des générateurs de code IA.
* Fichiers couverts : `package.json`, `requirements.txt`, `pyproject.toml` (PEP 621 et Poetry), `Cargo.toml`, `composer.json`, `go.mod`, `Gemfile`, `pom.xml`.
* Les dépendances Go marquées `// indirect` sont ignorées : elles sont calculées automatiquement par `go mod tidy`, une IA ne peut pas les halluciner.

### 4. PHP -- failles spécifiques à l'écosystème
* Inclusion de fichier dynamique (LFI/RFI) via `include`/`require` avec `$_GET`/`$_POST`.
* Désérialisation non sûre (`unserialize()` sur une entrée utilisateur -- PHP Object Injection).
* Injection de variables via `extract($_GET)`.
* Exécution de commande système (`system`, `exec`, `shell_exec`, `passthru`...).
* Injection SQL (concaténation/interpolation dans une requête `mysqli`/`PDO`).
* Identifiants de base de données codés en dur (pattern `wp-config.php`).
* Hachage faible (`md5()`/`sha1()`), très courant pour les mots de passe en PHP.
* Détection de stack : **Laravel** (`composer.json`) et **WordPress** (`wp-config.php`), pour des suggestions de correctif adaptées.

### 5. Go -- failles spécifiques à l'écosystème
* Command injection via `exec.Command()` avec argument construit dynamiquement (uniquement si le fichier importe `os/exec`, pour éviter les faux positifs).
* Injection SQL par concaténation ou `fmt.Sprintf`.
* Path traversal : lecture de fichier basée sur `r.URL.Query()`/`r.FormValue()` non validée.
* Hachage faible (`md5`/`sha1`).

### 6. Ruby/Rails -- failles spécifiques à l'écosystème
* Exécution de code arbitraire (`eval`, `instance_eval`, `class_eval`).
* **Mass assignment** : `params.permit!` (contournement total des strong parameters Rails).
* Command injection (`system`, backticks, `%x`, `Kernel#open` avec entrée utilisateur -- une faille classique et documentée de Ruby).
* Désérialisation non sûre : `YAML.load()` sur une source non fiable (au lieu de `YAML.safe_load`).
* Injection SQL dans les requêtes ActiveRecord par interpolation (`where("... #{...}")`).
* Hachage faible (`Digest::MD5`/`Digest::SHA1`).

### 7. Java -- failles spécifiques à l'écosystème
* Injection SQL par concaténation (`Statement` plutôt que `PreparedStatement`).
* Command injection (`Runtime.getRuntime().exec()`, `ProcessBuilder` avec argument dynamique).
* **Désérialisation Java non sûre** (`ObjectInputStream.readObject()` -- vecteur RCE connu, gadget chains).
* **XXE** : `DocumentBuilderFactory` utilisé sans désactiver les DOCTYPE/entités externes.
* Hachage faible (`MessageDigest.getInstance("MD5"/"SHA1")`).

---

## Fonctionnement (compte requis, moteur de scan local)

**[12/09/2026]** Un compte kikard (email ou GitHub, palier Free inclus) est désormais **requis** pour `kikard scan` -- voir "Compte & quota" ci-dessous. Une fois connecté, le moteur de scan lui-même (secrets, injections, hallucination de packages sur 7 écosystèmes) tourne **entièrement en local** : aucune base de données ni serveur tiers, votre code source ne quitte jamais votre machine pour ces détections. Seuls la vérification de compte (mise en cache 1h) et le décompte du quota mensuel (voir plus bas) font l'objet d'un appel réseau à chaque scan.

Vous pouvez **aussi**, une fois connecté avec un compte éligible, activer `--advanced` pour bénéficier d'une vérification supplémentaire côté serveur pour certains langages "premium" (C#/.NET pour l'instant, voir `kikard whoami`). Cette option est un opt-in explicite : sans `--advanced`, kikard n'effectue jamais d'appel réseau supplémentaire au-delà de la vérification de compte/quota déjà nécessaire pour `scan`. Avec `--advanced`, seuls les fichiers de manifeste pertinents (`.csproj`, `packages.config`) sont transmis -- jamais le reste de votre code source -- et kikard vous l'annonce explicitement à chaque exécution avant l'envoi. En cas d'indisponibilité réseau, de compte non éligible ou d'erreur serveur, le scan local complet continue normalement : `--advanced` ne peut jamais faire échouer un scan.

Il s'exécute directement via `npx` dans votre terminal ou dans votre pipeline CI/CD (GitHub Actions, GitLab CI).

## Compte & quota (obligatoire depuis le 12/09/2026)

```bash
# 1. Créez un compte gratuit sur https://app.kikard.com (email ou GitHub)
# 2. Générez une clé API depuis la page Compte, puis connectez le CLI :
npx --yes kikard login <votre-clé-api>
```

- **Palier Free** : 1000 scans/mois, scan complet (y compris la détection slopsquatting), `kikard firewall` et `--sbom` inclus, CLI + rapport local. Voir [kikard.com/pricing](https://kikard.com/pricing) pour les paliers Pro/Team/Enterprise (scans illimités, CI/CD avec blocage de pull request, historique, alertes, dashboard équipe...).
- Le quota est vérifié **à chaque scan**, en ligne -- mais **jamais bloquant en cas de panne réseau ou serveur** : seul un quota réellement dépassé (confirmé par le serveur) arrête un scan. Un compte jamais connecté (`kikard login` jamais exécuté), lui, empêche `kikard scan` de démarrer.
- `kikard whoami` affiche votre plan, votre quota et les fonctions débloquées ; `kikard logout` oublie la clé enregistrée localement.

```bash
# Lancer un audit complet sur le projet courant
npx --yes kikard scan .

# Audit avec rapport HTML interactif
npx --yes kikard scan . --html

# Audit avec rapport HTML interactif selon le nom du fichier spécifié
npx --yes kikard scan . --html nom_du_rapport.html

# Audit avec rapport HTML interactif et ouverture automatique dans le navigateur
npx --yes kikard scan . --html --open

# Audit avec rapport HTML interactif selon le nom du fichier spécifié
# et ouverture automatique dans le navigateur
npx --yes kikard scan . --html nom_rapport.html --open

# Application des correctifs automatiques 100 % sûrs
npx --yes kikard scan . --fix

# Génération de correctifs par IA (aperçu + confirmation avant chaque application),
# compte connecté et éligible requis -- voir "Applicatif de correction de code" plus bas
npx --yes kikard scan . --ai-fix

# Idem, sans demander de confirmation à chaque correctif (utile en script/CI non interactif)
npx --yes kikard scan . --ai-fix --yes

# Exporte le rapport au format JSON brut dans la console
npx --yes kikard scan . --json

# Exporte le rapport au format JSON brut dans la console et l'exporte dans un fichier JSON
npx --yes kikard scan . --json > report.json

```

---

## Guide des Options CLI

Toutes les options d'exécution sont **cumulables** :

| Option | Valeur / Format | Valeur par défaut | Description |
| --- | --- | --- | --- |
| **`--html [fichier]`** | `boolean` ou `string` | `false` | Génère un rapport HTML interactif. Si aucun nom n'est spécifié, crée `kikard-report.html`. |
| **`--open`** | `boolean` | `false` | Ouvre automatiquement le rapport HTML dans votre navigateur par défaut dès la fin du scan (s'utilise avec `--html`). |
| **`--fix`** | `boolean` | `false` | Applique automatiquement les correctifs de sécurité sûrs détectés sur le projet *(interrompt l'exécution après application)*. |
| **`--json`** | `boolean` | `false` | Exporte le rapport au format JSON brut dans la console (idéal pour l'automatisation). |
| **`--fail-on <seuil>`** | `critical` | `high` | `medium` | `low` | `info` | `"critical"` | Définit la sévérité minimale qui renvoie un code d'erreur `1` (fait échouer la CI/CD). |
| **`--allow <fichier>`** | `string` | `".kikardignore"` | Spécifie le chemin d'un fichier d'exclusion personnalisé pour ignorer certaines dépendances. |
| **`--concurrency <nb>`** | `number` | `8` | Nombre de requêtes et vérifications de packages exécutées en parallèle. |
| **`--advanced`** | `boolean` | `false` | Active le scan avancé (langages premium, ex : C#/.NET) pour les comptes éligibles connectés (`kikard login`). Sans effet si non connecté ou si aucun fichier pertinent n'est trouvé -- le scan local reste toujours complet. |
| **`--ai-fix`** | `boolean` | `false` | Génère, pour chaque faille éligible, une suggestion de correctif par IA (compte connecté et éligible requis) -- affiche un aperçu avant/après et demande confirmation avant d'écrire quoi que ce soit *(sauvegarde `.kikard.bak` par fichier modifié, interrompt l'exécution après application, comme `--fix`)*. |
| **`--yes`** | `boolean` | `false` | Utilisé avec `--ai-fix` : applique chaque correctif proposé sans demander de confirmation (utile en script/CI non interactif). Sans effet seul. |
| **`--fix-prompt [fichier]`** | `boolean` ou `string` | `false` | **Gratuit, aucun appel réseau additionnel** (au-delà du compte requis pour `kikard scan`, voir "Compte & quota"). Génère un fichier texte prêt à coller dans l'assistant IA de votre choix (ChatGPT, Claude, etc.), regroupant toutes les failles éligibles avec leur extrait de code réel. Si aucun nom n'est spécifié, crée `kikard-fix-prompt.md`. Contrairement à `--ai-fix`, kikard ne génère ni n'applique lui-même de correctif ici -- il prépare seulement la question à poser. |

---

## Exemples d'Utilisation

### Rapport HTML Interactif

Générez un rapport HTML dynamique avec filtres par sévérité et moteur de recherche, puis ouvrez-le directement :

```bash
npx --yes kikard scan . --html audit-securite.html --open

```

### Intégration CI/CD (Pipeline de Build)

**[13/09/2026] Action GitHub officielle (`action.yml` à la racine du dépôt)** -- la façon
recommandée d'intégrer kikard à une pull request, palier Pro requis (voir
[kikard.com/pricing](https://kikard.com/pricing)) :

```yaml
- uses: kikard-security/kikard@v1
  with:
    api-key: ${{ secrets.KIKARD_API_KEY }}
    fail-on: critical
```

Elle fait échouer le check (code de sortie non nul) et publie un commentaire récapitulatif
sur la pull request. **Important** : GitHub ne permet pas à une Action tierce de "bloquer" une
PR par elle-même -- c'est en ajoutant ce check comme *required status check* dans la
protection de branche du dépôt (Settings > Branches) que l'échec du scan empêche réellement la
fusion. Exemple de workflow complet et instructions pas à pas :
[`examples/github-actions/kikard-pr-check.yml`](../examples/github-actions/kikard-pr-check.yml).

**Sans l'Action** (GitLab CI, Jenkins, ou toute pipeline), le même résultat s'obtient avec le
CLI directement -- un compte est désormais requis (voir "Compte & quota" plus haut), donc
`login` doit précéder `scan` dans le job :

```bash
npx --yes kikard login "$KIKARD_API_KEY"
npx --yes kikard scan . --fail-on medium

```

### Export JSON pour Traitement Automatisé

Redirigez le rapport JSON dans un fichier de logs sans affichage terminal :

```bash
npx --yes kikard scan . --json > audit-result.json

```

---

## Fichier d'Exclusion (`.kikardignore`)

Pour ignorer des dépendances spécifiques lors de l'analyse, créez un fichier `.kikardignore` à la racine de votre projet :

```text
# Exclure des paquets spécifiques
lodash
express
# Les lignes commençant par # sont des commentaires
```

---

## Scan avancé (optionnel, connecté)

kikard reste 100 % fonctionnel hors ligne. `--advanced` ajoute, en plus, une vérification côté serveur pour des langages qui ne font pas partie du moteur open-source local (C#/.NET pour l'instant, via NuGet).

```bash
# Se connecter (clé API générée depuis le tableau de bord kikard)
npx --yes kikard login <votre-clé-api>

# Vérifier son plan et les langages avancés disponibles
npx --yes kikard whoami

# Scanner avec vérification avancée en plus du scan local complet
npx --yes kikard scan . --advanced
```

Ce qui est transmis avec `--advanced` : uniquement les fichiers de manifeste de dépendances du langage concerné (`.csproj`, `packages.config`) -- jamais le reste de votre code source, jamais dans un fichier de log, jamais conservé au-delà du temps de traitement de la requête. Le serveur revérifie systématiquement, à chaque appel, que votre compte est bien éligible -- indépendamment de ce que kikard affiche localement (voir `kikard whoami`), puisque ce dernier ne peut jamais servir de preuve d'autorisation à lui seul.

Sans `--advanced`, kikard n'effectue aucun appel réseau supplémentaire au-delà de la vérification de compte/quota déjà nécessaire pour `kikard scan` (voir "Compte & quota" en tête de ce document).

## Applicatif de correction de code automatique (IA, optionnel, connecté)

`--fix` corrige déjà, gratuitement et hors ligne, une poignée de patterns jugés 100 % sûrs (voir plus haut). `--ai-fix` va plus loin pour toute faille éligible (tout ce qui a un emplacement de code précis -- pas les dépendances hallucinées, qui se corrigent en retirant le paquet, pas le code) : il transmet un **extrait borné** de code (quelques dizaines de lignes autour de la faille, jamais le fichier entier ni le reste du dépôt) à une IA côté serveur, qui propose un correctif ciblé.

```bash
# Se connecter (comme pour --advanced -- même compte, même clé API)
npx --yes kikard login <votre-clé-api>

# Génère un correctif pour chaque faille éligible, avec aperçu avant/après et confirmation
npx --yes kikard scan . --ai-fix
```

**Aperçu + confirmation obligatoire, jamais une application automatique et silencieuse** : pour chaque faille, kikard affiche l'explication du correctif proposé ainsi que le code avant/après, puis demande `Appliquer ce correctif ? (o/N)` avant d'écrire quoi que ce soit. Un correctif accepté est appliqué avec la même sauvegarde `.kikard.bak` que `--fix`. `--yes` saute ces confirmations (utile en script/CI non interactif) -- mais reste un choix explicite fait au moment de l'invocation, jamais un comportement par défaut.

Ce qui est transmis : uniquement un extrait de quelques dizaines de lignes autour de la ligne signalée -- jamais le fichier entier, jamais le reste du dépôt, jamais conservé au-delà du traitement de la requête (voir le récap projet pour l'engagement de sécurité complet, même principe que `cli_advanced_scan_log` pour le scan avancé). Le serveur revérifie systématiquement, à chaque appel, que votre compte est bien éligible.

Un correctif généré par IA peut être imparfait -- relisez toujours l'aperçu avant de confirmer. Sans plan éligible, ou sans `--ai-fix`, kikard n'effectue aucun appel réseau supplémentaire pour cette fonctionnalité, au-delà de ceux déjà nécessaires pour `kikard scan`.

## Prompt de correction (gratuit, sans appel réseau additionnel)

Vous n'utilisez pas `--ai-fix`, ou vous préférez coller vous-même le correctif dans votre assistant IA habituel ? `--fix-prompt` génère un fichier texte prêt à l'emploi, sans aucun appel réseau au-delà de ceux déjà requis pour `kikard scan` (voir "Compte & quota" plus haut) -- contrairement à `--ai-fix`, kikard ne génère ni n'applique ici aucun correctif lui-même, il se contente de mettre en forme la question à poser.

```bash
# Génère kikard-fix-prompt.md dans le dossier scanné
npx --yes kikard scan . --fix-prompt

# Ou un nom de fichier personnalisé
npx --yes kikard scan . --fix-prompt mon-prompt.md
```

Le document généré regroupe toutes les failles éligibles (tout ce qui a un emplacement de code précis -- pas les dépendances hallucinées, qui se corrigent en retirant le paquet), chacune avec sa sévérité, son emplacement, le détail connu de kikard et, quand le fichier concerné est lisible localement, un extrait de code réel autour de la ligne signalée. Copiez-collez le contenu de ce fichier dans ChatGPT, Claude, ou tout autre assistant IA de votre choix.

## Pare-feu registre local (interception avant installation) -- gratuit, sans compte

**[19/09/2026] `kikard firewall` est gratuit, aucun compte requis** (voir [kikard.com/pricing](https://kikard.com/pricing)) -- `kikard firewall start` démarre directement, sans vérification de plan.

`kikard scan` détecte les paquets hallucinés/typosquattés *après coup*, une fois qu'ils sont déjà dans `package.json`/`requirements.txt`. `kikard firewall` va plus loin : il bloque `npm install <paquet>` / `pip install <paquet>` **avant** que le paquet n'atteigne le disque -- y compris si la commande est tapée directement dans un terminal, un IDE ou un script CI, sans jamais passer par kikard.

```bash
# Démarrer le pare-feu en arrière-plan (reconfigure npm/pip pour passer par kikard)
npx --yes kikard firewall start

# Statut
npx --yes kikard firewall status

# Arrêter -- restaure automatiquement la configuration npm/pip d'origine
npx --yes kikard firewall stop
```

Fonctionnement : un petit serveur local se place entre vos commandes `npm`/`pip` et les registres officiels (npmjs.org, PyPI). Chaque résolution de paquet est vérifiée avec **le même moteur de détection que `kikard scan`, entièrement en local** (aucune donnée de code transmise à kikard pour cette vérification) : si le paquet n'existe pas sur le registre ou correspond à une hallucination documentée, l'installation échoue avec un simple "404" -- le détail complet du blocage est dans `~/.kikard/firewall.log`. Un paquet autorisé est téléchargé directement depuis le registre officiel, sans jamais transiter par kikard. Aucun appel réseau vers kikard, ni au démarrage ni pendant la résolution de paquets -- le pare-feu fonctionne entièrement hors ligne.

Options : `--port <n>` (7878 par défaut), `--ecosystems npm,pypi` (les deux par défaut), `--foreground` (reste au premier plan, Ctrl+C pour arrêter -- utile en CI ou pour déboguer).

## Export SBOM (CycloneDX) -- gratuit, sans compte

**[19/09/2026] `--sbom` est gratuit, aucun compte requis.** Génère un inventaire de vos dépendances au format [CycloneDX](https://cyclonedx.org/) JSON, calculé localement à partir de l'inventaire déjà résolu pendant le scan -- aucune donnée transmise à kikard.

```bash
# Génère kikard-sbom.json dans le dossier scanné
npx --yes kikard scan . --sbom

# Ou un nom de fichier personnalisé
npx --yes kikard scan . --sbom mon-sbom.json
```

Les versions listées sont les contraintes déclarées dans vos manifestes (ex. `^4.17.21`), pas des versions résolues depuis un lockfile -- le document reste honnête sur ce qui est réellement connu à ce stade (`kikard:declaredVersionConstraint` dans les métadonnées de chaque composant).

**Portée v1 : npm et PyPI (pip) uniquement.** Ce sont les deux écosystèmes les plus concernés par le slopsquatting assisté par IA et les protocoles de registre les plus simples à reproduire fidèlement. crates.io, Packagist, RubyGems, Go et Maven ont des protocoles plus lourds (index sparse, format Marshal, zips signés...) et ne sont pas encore couverts par le pare-feu (ils le sont déjà par `kikard scan` en mode classique).

**Important** : si le process du pare-feu est tué brutalement (crash, redémarrage de la machine) sans passer par `kikard firewall stop`, votre configuration npm/pip peut rester pointée vers `127.0.0.1` -- relancez `kikard firewall stop` pour la restaurer (il détecte ce cas et restaure directement), ou manuellement via `npm config set registry https://registry.npmjs.org/` et `pip config unset global.index-url`.

## Certification Norme KIKARD (vérification, sans compte)

Un dépôt scanné via le dashboard kikard peut obtenir un certificat "Secure Code" par sous-norme (Slopsquatting, Secrets, Injections, RLS Supabase -- voir le Référentiel technique), à l'un de trois paliers (**Starter / Pro / Expert**). `kikard verify` interroge le serveur de licence pour confirmer qu'un jeton de certificat est authentique, toujours valide, et non révoqué -- **aucun compte requis** pour vérifier, seulement pour émettre.

```bash
npx --yes kikard verify <jeton-de-certificat>
```

`--api-url https://un-autre-serveur` reste disponible en override explicite (ex : futur self-hosted Enterprise), mais n'est plus requis -- kikard interroge par défaut le serveur géré `app.kikard.com`, ou celui déjà configuré via `kikard login` s'il diffère. Le jeton n'est jamais décodé localement : chaque vérification interroge le serveur, systématiquement -- un certificat révoqué ou expiré depuis l'émission du jeton est donc toujours détecté, même si le jeton lui-même n'a pas changé.

Sortie `0` si le certificat est valide, `1` s'il est introuvable/révoqué/expiré, `2` en cas d'erreur réseau -- exploitable directement en CI pour vérifier qu'un certificat tiers (ex : une dépendance) est toujours à jour.

## Badge "Scanné par kikard"

Affichez un badge dans le README de votre dépôt pour montrer que son code est suivi par kikard -- un badge de **confiance statique** : il ne reflète jamais le résultat d'un scan précis, seulement qu'un compte kikard actif existe derrière le dépôt. À ne pas confondre avec la certification Norme KIKARD ci-dessus (qui, elle, exige d'avoir franchi un seuil de qualité pour être émise) : n'importe quel compte peut afficher ce badge, après n'importe quel scan.

Récupérez votre lien depuis [app.kikard.com/account](https://app.kikard.com/account) (section "Badge « Scanné par kikard »"), puis collez le Markdown fourni dans votre `README.md` :

```markdown
[![Scanné par kikard](https://app.kikard.com/badge/<votre-token>.svg)](https://app.kikard.com/badge/<votre-token>)
```

Le lien du badge peut être régénéré à tout moment depuis la page Compte (invalide immédiatement l'ancien lien).
