// Détection de vulnérabilités courantes en Java. Le check XXE est un check de niveau fichier
// (comme l'absence de CSP côté HTML) plutôt que ligne par ligne : la protection s'active via
// une configuration qui n'est presque jamais sur la même ligne que l'instanciation.

export async function scanJava(fileEntries) {
  const findings = [];

  for (const { relativePath, content } of fileEntries) {
    if (!relativePath.endsWith(".java")) continue;

    const lines = content.split("\n");
    lines.forEach((lineText, idx) => {
      const line = idx + 1;
      const snippet = lineText.trim();

      // Injection SQL -- Statement avec concaténation (par opposition à PreparedStatement)
      if (
        /(executeQuery|executeUpdate|execute)\s*\(/.test(lineText) &&
        /\+/.test(lineText) &&
        /(SELECT|INSERT|UPDATE|DELETE)\b/i.test(lineText)
      ) {
        findings.push({
          category: "Injection SQL (Java)",
          severity: "critical",
          ruleId: "JAVA_SQL_INJECTION",
          title: "Requête SQL construite par concaténation",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "Une requête SQL est assemblée par concaténation de chaînes plutôt que via PreparedStatement -- un vecteur classique d'injection SQL.",
          fix: "Utilisez PreparedStatement avec des paramètres liés (setString(), setInt()...) plutôt que Statement + concaténation.",
        });
      }

      // Command Injection -- exécution de processus avec argument dynamique
      if (/(Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(/.test(lineText) && /\+/.test(lineText)) {
        findings.push({
          category: "Command Injection (Java)",
          severity: "high",
          ruleId: "JAVA_CMD_INJECTION",
          title: "Exécution de commande système avec argument construit dynamiquement",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "Runtime.exec()/ProcessBuilder avec une commande concaténée à partir d'une entrée utilisateur permet l'exécution de commandes arbitraires.",
          fix: "Passez les arguments sous forme de tableau (ProcessBuilder(String...)) plutôt qu'une chaîne unique, et validez les entrées.",
        });
      }

      // Désérialisation Java non sûre -- vecteur RCE connu (gadget chains)
      if (/new\s+ObjectInputStream\s*\(|\.readObject\s*\(/.test(lineText)) {
        findings.push({
          category: "Désérialisation non sûre (Java)",
          severity: "critical",
          ruleId: "JAVA_UNSAFE_DESERIALIZATION",
          title: "Désérialisation Java native détectée",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "ObjectInputStream.readObject() sur une source non fiable est un vecteur d'exécution de code arbitraire bien documenté (gadget chains).",
          fix: "Évitez la désérialisation Java native pour des données externes. Préférez un format sûr (JSON) avec une validation de schéma stricte.",
        });
      }

      // Cryptographie faible
      if (/MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-?1)["']/i.test(lineText)) {
        findings.push({
          category: "Crypto faible",
          severity: "high",
          ruleId: "JAVA_WEAK_HASH",
          title: "Algorithme de hachage obsolète (MD5/SHA1)",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "MD5 et SHA-1 sont cassés pour un usage sécurité, en particulier pour le hachage de mots de passe.",
          fix: "Utilisez BCrypt ou Argon2 pour les mots de passe, SHA-256 pour l'intégrité.",
        });
      }
    });

    // XXE -- vérification au niveau du fichier : DocumentBuilderFactory utilisé
    // sans désactivation explicite des entités externes (DOCTYPE).
    if (/DocumentBuilderFactory\.newInstance\s*\(/.test(content) && !/disallow-doctype-decl/.test(content)) {
      findings.push({
        category: "XXE (Java)",
        severity: "high",
        ruleId: "JAVA_XXE",
        title: "Parseur XML potentiellement vulnérable aux entités externes (XXE)",
        location: relativePath,
        detail: "DocumentBuilderFactory est utilisé sans désactiver explicitement les DOCTYPE/entités externes -- un parseur XML par défaut est vulnérable au XXE (lecture de fichiers, SSRF).",
        fix: 'Ajoutez : factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
      });
    }
  }

  return findings;
}
