// Détection de vulnérabilités courantes en Go. Le command injection est gaté sur la présence
// d'un import "os/exec" pour éviter de confondre avec d'autres .Command() sans rapport
// (ex: cobra.Command, testing) -- même logique que le gating child_process côté JS.

export async function scanGo(fileEntries) {
  const findings = [];

  for (const { relativePath, content } of fileEntries) {
    if (!relativePath.endsWith(".go")) continue;

    const usesOsExec = /"os\/exec"/.test(content);
    const lines = content.split("\n");

    lines.forEach((lineText, idx) => {
      const line = idx + 1;
      const snippet = lineText.trim();

      // Command Injection -- uniquement si le fichier importe réellement os/exec
      if (usesOsExec && /\bexec\.Command\s*\(/.test(lineText) && /\+|fmt\.Sprintf/.test(lineText)) {
        findings.push({
          category: "Command Injection (Go)",
          severity: "high",
          ruleId: "GO_CMD_INJECTION",
          title: "exec.Command() avec argument construit dynamiquement",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "Construire la commande ou ses arguments par concaténation/formatage à partir d'une entrée utilisateur permet l'exécution de commandes arbitraires.",
          fix: "Passez les arguments séparément à exec.Command(nom, arg1, arg2) plutôt que de construire une chaîne unique, et validez les entrées.",
        });
      }

      // Injection SQL -- concaténation/formatage dans une requête
      if (/(SELECT|INSERT|UPDATE|DELETE)\b/i.test(lineText) && (/\+/.test(lineText) || /fmt\.Sprintf/.test(lineText))) {
        findings.push({
          category: "Injection SQL (Go)",
          severity: "critical",
          ruleId: "GO_SQL_INJECTION",
          title: "Requête SQL construite par concaténation ou fmt.Sprintf",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "Une requête SQL semble assemblée dynamiquement -- un vecteur classique d'injection SQL.",
          fix: "Utilisez des requêtes paramétrées : db.Query(\"... WHERE id = ?\", id) plutôt que de construire la chaîne.",
        });
      }

      // Cryptographie faible
      if (/\b(md5|sha1)\.(New|Sum)\s*\(/.test(lineText)) {
        findings.push({
          category: "Crypto faible",
          severity: "high",
          ruleId: "GO_WEAK_HASH",
          title: "Algorithme de hachage obsolète (MD5/SHA1)",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "MD5 et SHA-1 sont cassés pour un usage sécurité, en particulier pour le hachage de mots de passe.",
          fix: "Utilisez golang.org/x/crypto/bcrypt pour les mots de passe, crypto/sha256 pour l'intégrité.",
        });
      }

      // Traversée de chemin -- lecture de fichier basée sur une entrée requête
      if (/\b(os\.Open|os\.Create|ioutil\.ReadFile|os\.ReadFile)\s*\(/.test(lineText) && /r\.(URL\.Query|FormValue)/.test(lineText)) {
        findings.push({
          category: "Path Traversal (Go)",
          severity: "high",
          ruleId: "GO_PATH_TRAVERSAL",
          title: "Accès fichier basé sur une entrée requête non validée",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "Utiliser directement une valeur de requête HTTP comme chemin de fichier permet à un attaquant de lire des fichiers arbitraires (../../etc/passwd).",
          fix: "Validez/normalisez le chemin avec filepath.Clean() et vérifiez qu'il reste dans le répertoire attendu.",
        });
      }
    });
  }

  return findings;
}
