# kikard

Le scanner de sécurité qui protège tout votre code — secrets exposés, failles d'injection, dépendances à risque — avec une longueur d'avance unique sur les risques du code généré par IA : la détection des packages hallucinés (slopsquatting), qu'aucun scanner généraliste ne cible aujourd'hui par un nom dédié. 7 registres de dépendances (npm, PyPI, crates.io, Packagist, Go, RubyGems, Maven), 5 langages avec règles de code (JS/TS, PHP, Go, Ruby, Java).

## Structure du dépôt

```
kikard/
├── packages/core/    -- moteur de scan, SOURCE UNIQUE (voir ci-dessous)
├── cli/              -- l'outil en ligne de commande
├── scripts/
│   └── sync-core.mjs -- synchronise packages/core vers cli/
└── SECURITY.md         -- état de la sécurité du CLI
```

## Important : où éditer le moteur de scan

**Ne modifiez jamais directement `cli/lib/`.** C'est une copie générée. La seule source à
éditer est `packages/core/src/`. Une fois vos changements faits :

```bash
npm run sync-core
```

Une CI (`.github/workflows/check-core-drift.yml`) échoue automatiquement si `cli/lib` diverge
de la source.

## Démarrage rapide

**[12/09/2026] Un compte kikard est requis dès `kikard scan`** (palier Free inclus, 1000 scans/mois) :

```bash
# 1. Créez un compte gratuit sur https://app.kikard.com, générez une clé API (page Compte)
node bin/kikard.js login <clé-api> --api-url https://app.kikard.com

# 2. Scannez -- le moteur lui-même reste 100 % open source et local (voir cli/lib/)
node bin/kikard.js scan /chemin/vers/un/projet
```

Le moteur de scan est open source et tourne en local (votre code ne quitte jamais votre machine pour la détection elle-même) ; seuls la vérification de compte et le décompte du quota font l'objet d'un appel réseau à chaque scan, jamais bloquant en cas de panne réseau ou serveur (voir `cli/README.md`, section "Compte & quota"). `kikard firewall` (interception d'installation npm/pip) et l'export SBOM (`--sbom`, CycloneDX) sont gratuits, inclus dès le palier Free. Le dashboard kikard.com (historique, export de rapports, intégration CI/CD, certification) suit un modèle Free / Pro / Team / Enterprise — voir [kikard.com/pricing](https://kikard.com/pricing).

**[13/09/2026] Intégration CI/CD (pull request)** -- Action GitHub officielle disponible directement depuis ce dépôt (`action.yml` à la racine, palier Pro requis) : voir `cli/README.md`, section "Intégration CI/CD", et l'exemple complet [`examples/github-actions/kikard-pr-check.yml`](./examples/github-actions/kikard-pr-check.yml).

## Authentification

```bash
node bin/kikard.js login <clé-api> --api-url https://votre-serveur
node bin/kikard.js whoami
node bin/kikard.js logout
```

`login`/`whoami`/`logout` fonctionnent avec tout serveur de licence compatible. Une fois
connecté, le CLI reste tolérant aux pannes réseau ponctuelles (une clé déjà vérifiée
retombe sur le dernier statut connu plutôt que d'échouer) -- mais `kikard scan` nécessite
qu'un compte ait été lié au moins une fois via `login`, voir `cli/README.md`.

## Sécurité

Voir [`SECURITY.md`](./SECURITY.md).

## Licence

**Apache-2.0** -- voir [`LICENSE`](./LICENSE). Usage, modification et redistribution
commerciale autorisés, sans obligation de republier vos changements.
