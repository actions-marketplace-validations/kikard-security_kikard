// Détection de vulnérabilités courantes en PHP -- volontairement séparé de injections.js
// (qui est spécifique à l'écosystème JS) car PHP a ses propres classes de failles
// (LFI/RFI, désérialisation d'objets, extract()) sans équivalent direct côté JS.

const SUPERGLOBAL = /\$_(GET|POST|REQUEST|COOKIE)\b/;

export async function scanPhp(fileEntries) {
  const findings = [];

  for (const { relativePath, content } of fileEntries) {
    if (!/\.(php|phtml)$/.test(relativePath)) continue;

    const lines = content.split("\n");
    lines.forEach((lineText, idx) => {
      const line = idx + 1;
      const snippet = lineText.trim();

      // eval -- exécution de code arbitraire (PHP)
      if (/\beval\s*\(/.test(lineText)) {
        findings.push({
          category: "Exécution de code arbitraire (PHP)",
          severity: "critical",
          ruleId: "PHP_EVAL",
          title: "Exécution de code arbitraire via la fonction eval",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "La fonction eval exécute une chaîne comme du code PHP -- si elle contient une entrée utilisateur, c'est une exécution de code arbitraire.",
          fix: "Supprimez cet appel à eval. Remplacez par une logique explicite ou une whitelist d'actions autorisées.",
        });
      }

      // Inclusion de fichier dynamique (LFI/RFI)
      if (/\b(include|include_once|require|require_once)\s*\(?\s*\$/.test(lineText) && SUPERGLOBAL.test(lineText)) {
        findings.push({
          category: "Inclusion de fichier (LFI/RFI)",
          severity: "critical",
          ruleId: "PHP_FILE_INCLUSION",
          title: "Inclusion de fichier basée sur une entrée utilisateur",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "include/require avec une variable dérivée de $_GET/$_POST permet à un attaquant de charger un fichier arbitraire local (LFI) ou distant (RFI).",
          fix: "N'utilisez jamais une entrée utilisateur directe dans include/require. Passez par une whitelist stricte de fichiers autorisés.",
        });
      }

      // Désérialisation d'entrée utilisateur (PHP Object Injection)
      if (/\bunserialize\s*\(/.test(lineText) && SUPERGLOBAL.test(lineText)) {
        findings.push({
          category: "Désérialisation non sûre (PHP)",
          severity: "critical",
          ruleId: "PHP_UNSAFE_UNSERIALIZE",
          title: "unserialize() sur une entrée utilisateur",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "Désérialiser une donnée fournie par l'utilisateur peut permettre l'injection d'objets PHP et l'exécution de code arbitraire.",
          fix: "Utilisez json_decode() pour un échange de données simple, ou validez strictement la structure avant unserialize().",
        });
      }

      // extract() sur un superglobal -- injection de variables arbitraires
      if (/\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\b/.test(lineText)) {
        findings.push({
          category: "Injection de variables (PHP)",
          severity: "high",
          ruleId: "PHP_EXTRACT_SUPERGLOBAL",
          title: "extract() appliqué directement à une entrée utilisateur",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "extract() sur $_GET/$_POST crée des variables PHP arbitraires nommées par l'attaquant, pouvant écraser des variables internes.",
          fix: "Accédez aux champs individuellement ($_POST['champ']) plutôt que d'extraire tout le tableau.",
        });
      }

      // Exécution de commande système
      if (/\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(/.test(lineText)) {
        findings.push({
          category: "Command Injection (PHP)",
          severity: "high",
          ruleId: "PHP_CMD_EXEC",
          title: "Exécution de commande système détectée",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "L'exécution de commandes système avec des entrées non filtrées est un vecteur classique de compromission du serveur.",
          fix: "Évitez d'exécuter des commandes système avec des données utilisateur. Si nécessaire, utilisez escapeshellarg() sur chaque argument.",
        });
      }

      // Injection SQL -- détecte la construction d'une requête SQL avec concaténation ou
      // interpolation d'une entrée utilisateur, indépendamment de la ligne où elle est exécutée
      // (le cas le plus courant : $query = "SELECT..." . $_GET[...]; puis mysqli_query($query) plus loin).
      if (/(SELECT|INSERT|UPDATE|DELETE)\b/i.test(lineText) && (/\.\s*\$/.test(lineText) || SUPERGLOBAL.test(lineText))) {
        findings.push({
          category: "Injection SQL (PHP)",
          severity: "critical",
          ruleId: "PHP_SQL_INJECTION",
          title: "Requête SQL construite avec une entrée non échappée",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "Une requête SQL semble intégrer une variable (souvent issue de $_GET/$_POST) sans échappement ni requête préparée.",
          fix: "Utilisez des requêtes préparées PDO (prepare()/bindParam()) ou mysqli_stmt plutôt que de la concaténation.",
        });
      }

      // Identifiants de base de données codés en dur (pattern WordPress/config classique)
      if (/define\s*\(\s*['"]DB_(PASSWORD|USER)['"]\s*,\s*['"][^'"]+['"]/.test(lineText)) {
        findings.push({
          category: "Secrets Scanner",
          severity: "critical",
          ruleId: "PHP_HARDCODED_DB_CREDENTIALS",
          title: "Identifiant de base de données codé en dur",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "Un identifiant ou mot de passe de base de données est écrit en clair dans le code (pattern typique de wp-config.php).",
          fix: "Chargez ces valeurs depuis une variable d'environnement plutôt que de les coder en dur dans le fichier.",
        });
      }

      // Hachage faible -- très courant en PHP pour les mots de passe
      if (/\b(md5|sha1)\s*\(/.test(lineText)) {
        findings.push({
          category: "Crypto faible",
          severity: "high",
          ruleId: "PHP_WEAK_HASH",
          title: "Algorithme de hachage obsolète (MD5/SHA1)",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "MD5 et SHA-1 sont cassés pour un usage sécurité, en particulier pour le hachage de mots de passe.",
          fix: "Utilisez password_hash() (bcrypt/argon2) pour les mots de passe, hash('sha256', ...) pour l'intégrité.",
        });
      }
    });
  }

  return findings;
}
