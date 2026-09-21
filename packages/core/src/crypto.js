export async function scanCrypto(fileEntries) {
  const findings = [];

  const weakRandomPattern = /Math\.random\s*\(\s*\)/;
  const mathRandomStr = "Math.random()";

  for (const { relativePath, content } of fileEntries) {
    if (!/\.(js|jsx|ts|tsx|mjs|cjs)$/.test(relativePath)) continue;

    const lines = content.split("\n");
    lines.forEach((lineText, idx) => {
      const line = idx + 1;
      const snippet = lineText.trim();

      if (/createHash\s*\(\s*['"](md5|sha1)['"]\s*\)/i.test(lineText)) {
        findings.push({
          category: "Crypto faible",
          severity: "high",
          ruleId: "WEAK_HASH",
          title: "Algorithme de hachage obsolète (MD5/SHA1)",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "MD5 et SHA-1 sont faillibles aux collisions et ne doivent plus être utilisés.",
          fix: "Utilisez SHA-256 ou supérieur (ex: crypto.createHash('sha256')).",
        });
      }

      if (weakRandomPattern.test(lineText)) {
        findings.push({
          category: "Crypto faible",
          severity: "low",
          ruleId: "WEAK_RANDOM",
          title: `Utilisation de ${mathRandomStr} pour des opérations sensibles`,
          location: `${relativePath}:${line}`,
          snippet,
          detail: `${mathRandomStr} n'est pas un générateur pseudo-aléatoire cryptographiquement sécurisé (PRNG).`,
          fix: "Utilisez crypto.getRandomValues() ou crypto.randomBytes() pour les jetons et mots de passe.",
        });
      }
    });
  }

  return findings;
}