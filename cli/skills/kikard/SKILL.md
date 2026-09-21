---
name: kikard
description: Scanner de sécurité complet et vérificateur de packages. Détecte les nom hallucinations/slopsquatting (npm/pip) avant l'installation, ainsi que les vulnérabilités de code source (Injections SQL, Supabase RLS manquant, secrets exposés, mauvaises pratiques de sécurité). Permet la correction automatique des failles simples.
---

### Utilisation systématique

Avant d'exécuter `npm install`, `pip install -r requirements.txt`, d'ajouter une nouvelle dépendance ou d'effectuer une revue de sécurité du code, exécutez :

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

# Exporte le rapport au format JSON brut dans la console
npx --yes kikard scan . --json
