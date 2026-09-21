export async function scanAuth(fileEntries) {
  const findings = [];

  // Tolère un chemin relatif sans "/" de tête (ex: "api/users.js") en plus
  // d'un chemin avec (ex: "src/api/users.js").
  const apiPathRegex = /(^|\/)api\//;
  const routesPathRegex = /(^|\/)routes\//;

  for (const { relativePath, content } of fileEntries) {
    if (!apiPathRegex.test(relativePath) && !routesPathRegex.test(relativePath)) continue;

    const definesRoute = /(router\.(get|post|put|delete)|export\s+async\s+function\s+(GET|POST|PUT|DELETE))/i.test(content);
    // Cherche des usages concrets (appels de fonction, accès de propriété), pas un simple mot isolé
    // qui pourrait apparaître dans une chaîne sans rapport (ex: le nom d'un cookie "session").
    const hasAuthCheck = /(req\.(auth|user|session)\b|verifyToken\s*\(|getServerSession\s*\(|protectRoute\s*\(|jwt\.verify\s*\(|passport\.authenticate\s*\(|\.use\(\s*auth)/i.test(content);

    if (definesRoute && !hasAuthCheck) {
      findings.push({
        category: "Endpoints non protégés",
        severity: "high",
        ruleId: "UNPROTECTED_ENDPOINT",
        title: "Route API potentiellement non protégée",
        location: relativePath,
        detail: "La route API est définie sans middleware ou contrôle d'authentification explicite.",
        fix: "Ajoutez un middleware d'authentification (ex: verifyToken) ou vérifiez la session utilisateur.",
      });
    }
  }

  return findings;
}