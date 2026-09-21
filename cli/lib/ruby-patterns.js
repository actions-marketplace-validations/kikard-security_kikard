// Détection de vulnérabilités courantes en Ruby/Rails -- ciblées sur les failles propres
// à cet écosystème (mass assignment, YAML.load, Kernel#open) plutôt que des règles
// génériques qui existent déjà côté secrets.js.

export async function scanRuby(fileEntries) {
  const findings = [];

  for (const { relativePath, content } of fileEntries) {
    if (!relativePath.endsWith(".rb")) continue;

    const lines = content.split("\n");
    lines.forEach((lineText, idx) => {
      const line = idx + 1;
      const snippet = lineText.trim();

      // eval / instance_eval / class_eval -- exécution de code arbitraire
      if (/\b(eval|instance_eval|class_eval)\s*\(/.test(lineText)) {
        findings.push({
          category: "Exécution de code arbitraire (Ruby)",
          severity: "critical",
          ruleId: "RUBY_EVAL",
          title: "Exécution de code arbitraire via eval",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "eval/instance_eval/class_eval exécutent une chaîne comme du code Ruby -- dangereux avec une entrée non fiable.",
          fix: "Remplacez par une logique explicite ou une whitelist d'actions autorisées.",
        });
      }

      // Mass assignment -- contournement total des strong parameters Rails
      if (/\.permit!/.test(lineText)) {
        findings.push({
          category: "Mass Assignment (Rails)",
          severity: "critical",
          ruleId: "RUBY_MASS_ASSIGNMENT",
          title: "params.permit! -- filtrage des paramètres désactivé",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "permit! autorise absolument tous les paramètres de la requête, y compris ceux qu'un attaquant ajouterait pour écraser des attributs sensibles (ex: admin: true).",
          fix: "Listez explicitement les attributs autorisés : params.require(:user).permit(:name, :email).",
        });
      }

      // Command Injection -- system/backticks/%x/exec avec interpolation
      if (/(\bsystem\s*\(|`[^`]*#\{|%x\(|\bKernel\.exec\s*\()/.test(lineText) && /#\{/.test(lineText)) {
        findings.push({
          category: "Command Injection (Ruby)",
          severity: "critical",
          ruleId: "RUBY_CMD_INJECTION",
          title: "Exécution de commande système avec interpolation",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "Une commande système est construite avec de l'interpolation de chaîne (#{...}) -- si la valeur vient d'une entrée utilisateur, c'est une injection de commande.",
          fix: "Utilisez system('cmd', arg1, arg2) avec des arguments séparés plutôt qu'une chaîne interpolée.",
        });
      }

      // Kernel#open -- faille classique Ruby : un argument commençant par "|" exécute une commande
      if (/\bopen\s*\(\s*params/.test(lineText)) {
        findings.push({
          category: "Command Injection (Ruby)",
          severity: "critical",
          ruleId: "RUBY_KERNEL_OPEN",
          title: "Kernel#open avec une entrée utilisateur non filtrée",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "open() interprète un argument commençant par \"|\" comme une commande shell à exécuter -- une faille classique et bien documentée de Ruby.",
          fix: "Utilisez File.open() (qui n'a pas ce comportement) plutôt que Kernel#open, ou validez strictement l'entrée.",
        });
      }

      // YAML.load non sécurisé -- vecteur RCE historique (CVE-2013-0156 et suivants)
      if (/YAML\.load\s*\(/.test(lineText) && !/YAML\.load_file/.test(lineText)) {
        findings.push({
          category: "Désérialisation non sûre (Ruby)",
          severity: "high",
          ruleId: "RUBY_UNSAFE_YAML",
          title: "YAML.load() sur une source potentiellement non fiable",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "YAML.load peut instancier des objets Ruby arbitraires depuis le contenu désérialisé -- un vecteur d'exécution de code connu.",
          fix: "Utilisez YAML.safe_load(data) à la place, qui restreint les types désérialisables.",
        });
      }

      // Injection SQL -- requêtes ActiveRecord avec interpolation
      if (/\.(where|find_by_sql|order|group)\s*\([^)]*#\{/.test(lineText) || /connection\.execute\s*\([^)]*#\{/.test(lineText)) {
        findings.push({
          category: "Injection SQL (Ruby)",
          severity: "critical",
          ruleId: "RUBY_SQL_INJECTION",
          title: "Requête ActiveRecord construite avec interpolation",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "Interpoler une variable directement dans une condition ActiveRecord contourne l'échappement automatique.",
          fix: "Utilisez la syntaxe avec placeholders : where(\"name = ?\", name) plutôt que where(\"name = #{name}\").",
        });
      }

      // Cryptographie faible
      if (/Digest::(MD5|SHA1)\b/.test(lineText)) {
        findings.push({
          category: "Crypto faible",
          severity: "high",
          ruleId: "RUBY_WEAK_HASH",
          title: "Algorithme de hachage obsolète (MD5/SHA1)",
          location: `${relativePath}:${line}`,
          snippet,
          detail: "MD5 et SHA-1 sont cassés pour un usage sécurité, en particulier pour le hachage de mots de passe.",
          fix: "Utilisez bcrypt (gem 'bcrypt') pour les mots de passe, Digest::SHA256 pour l'intégrité.",
        });
      }
    });
  }

  return findings;
}
