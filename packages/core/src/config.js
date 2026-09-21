export async function scanConfig(fileEntries) {
  const findings = [];

  for (const { relativePath, content } of fileEntries) {
    if (!/\.(js|jsx|ts|tsx|mjs|cjs)$/.test(relativePath)) continue;

    // CORS ouvert
    if (/origin\s*:\s*['"]\*['"]/i.test(content) || /Access-Control-Allow-Origin.*?['"]\*['"]/i.test(content)) {
      findings.push({
        category: "CORS ouvert",
        severity: "medium",
        ruleId: "CORS_WILDCARD",
        title: "Configuration CORS trop permissive (*)",
        location: relativePath,
        detail: "Le paramètre origin '*' autorise n'importe quel site web à faire des requêtes vers votre API.",
        fix: "Spécifiez la liste explicite des domaines autorisés au lieu du wildcard (*).",
      });
    }

    // Cookie sans HttpOnly
    if (/res\.cookie\s*\(/.test(content) && !/httpOnly\s*:\s*true/i.test(content)) {
      findings.push({
        category: "Configuration Cookies",
        severity: "low",
        ruleId: "COOKIE_NO_HTTPONLY",
        title: "Cookie défini sans l'option HttpOnly",
        location: relativePath,
        detail: "Un cookie sans le flag HttpOnly peut être lu par du JavaScript exécuté sur le client (XSS).",
        fix: "Ajoutez '{ httpOnly: true, secure: true }' aux options de création du cookie.",
      });
    }
  }

  return findings;
}