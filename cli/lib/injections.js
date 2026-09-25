export async function scanInjections(fileEntries, stack = {}) {
  const findings = [];

  const evalRegex = /\beval\s*\(/;
  const execRegex = /\b(exec|execSync|spawn)\s*\(/;
  const childProcessImportRegex = /require\(\s*['"]child_process['"]\s*\)|from\s+['"]child_process['"]/;

  for (const { relativePath, content } of fileEntries) {
    if (!/\.(js|jsx|ts|tsx|mjs|cjs)$/.test(relativePath)) continue;

    // La détection "command injection" ne se déclenche que si le fichier importe
    // réellement child_process -- ça évite de confondre exec()/spawn() système
    // avec RegExp.prototype.exec() ou tout autre .exec() sans rapport (ex: axios, tests).
    const usesChildProcess = childProcessImportRegex.test(content);

    const lines = content.split("\n");
    lines.forEach((lineText, idx) => {
      const line = idx + 1;
      const snippet = lineText.trim();

      // XSS & Eval
      if (evalRegex.test(lineText)) {
        findings.push({
          category: "JSON.parse(), innerHTML, injection XSS",
          severity: "critical",
          ruleId: "NO_EVAL",
          title: "Exécution de code arbitraire via la fonction eval",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "L'appel à la fonction eval permet d'exécuter du code malveillant injecté par l'utilisateur.",
          fix: "Supprimez cet appel à eval. Utilisez JSON.parse() pour manipuler du JSON.",
        });
      }

      const innerHTMLRegex = /innerHTML\s*=/;
      // Construit par concaténation (plutôt que /dangerouslySetInnerHTML/ tel quel) pour que
      // cette ligne ne contienne jamais le motif complet en clair -- sinon kikard se signale
      // lui-même en scannant son propre moteur de détection (faux positif auto-référentiel,
      // découvert le 25/09/2026 via le CI interne kikard.yml). Comportement de détection
      // identique sur le code scanné, seule la représentation en source change.
      const dangerouslyRegex = new RegExp("dangerously" + "SetInnerHTML");

      if (innerHTMLRegex.test(lineText) || dangerouslyRegex.test(lineText)) {
        findings.push({
          category: "JSON.parse(), innerHTML, injection XSS",
          severity: "high",
          ruleId: "DOM_XSS",
          title: "Injection XSS via le DOM",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "Affectation directe de chaîne HTML non assainie dans le DOM.",
          fix: "Utilisez textContent ou un sanitizer comme DOMPurify.",
        });
      }

      // SQL Injection
      if (/(SELECT|INSERT|UPDATE|DELETE)\s+.*?\${/i.test(lineText) || /(SELECT|INSERT|UPDATE|DELETE)\s+.*?\+/i.test(lineText)) {
        let sqlFix = "Utilisez des requêtes préparées avec paramètres (ex: db.query('SELECT * FROM u WHERE id = $1', [id])).";
        
        if (stack.hasSupabase) {
          sqlFix = "Supabase détecté : Remplacez le SQL brut concaténé par le client JS Fluent (ex: await supabase.from('table').select().eq('column', value)).";
        } else if (stack.hasPrisma) {
          sqlFix = "Prisma détecté : Utilisez les méthodes de l'ORM (ex: prisma.user.findMany()) au lieu de requêtes brutes.";
        }

        findings.push({
          category: "Injection SQL par concaténation",
          severity: "critical",
          ruleId: "SQL_CONCAT",
          title: "Requête SQL construite par concaténation",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "Les variables insérées directement dans les requêtes SQL ouvrent des failles majeures.",
          fix: sqlFix,
        });
      }

      // Command Injection -- uniquement si le fichier importe child_process
      if (usesChildProcess && execRegex.test(lineText)) {
        findings.push({
          category: "Command Injection",
          severity: "high",
          ruleId: "CMD_INJECTION",
          title: "Exécution de commande système détectée",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "L'exécution de commandes système avec des entrées utilisateur non filtrées est très risquée.",
          fix: "Validez et assainissez strictly les paramètres passés à la commande.",
        });
      }
    });
  }

  return findings;
}