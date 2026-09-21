export const SECRET_RULES = [
  {
    id: "aws-key",
    re: /AKIA[0-9A-Z]{16}/g,
    title: "Clé d'accès AWS exposée",
    detail: "Une clé d'accès AWS en clair dans le code donne un accès direct au compte cloud à quiconque lit ce fichier.",
    fix: "Déplacez la clé vers une variable d'environnement / un secret manager, révoquez celle-ci et régénérez-en une nouvelle.",
  },
  {
    id: "openai-key",
    re: /sk-[A-Za-z0-9]{20,}/g,
    title: "Clé API OpenAI exposée",
    detail: "Une clé API en clair permet à n'importe qui de consommer votre quota, voire d'accéder aux données associées.",
    fix: "Stockez la clé côté serveur uniquement, jamais dans du code livré au navigateur.",
  },
  {
    id: "stripe-key",
    re: /sk_live_[A-Za-z0-9]{10,}/g,
    title: "Clé Stripe live exposée",
    detail: "Une clé Stripe \"live\" en clair permet d'effectuer de vraies transactions ou de lire des données de paiement.",
    fix: "Révoquez immédiatement la clé dans le dashboard Stripe et utilisez une variable d'environnement côté serveur.",
  },
  {
    id: "google-key",
    re: /AIza[0-9A-Za-z\-_]{35}/g,
    title: "Clé API Google exposée",
    detail: "Une clé API Google en clair peut être réutilisée par un tiers pour consommer votre quota ou accéder à des services liés.",
    fix: "Restreignez la clé par domaine/IP dans la console Google Cloud et déplacez-la côté serveur.",
  },
  {
    id: "private-key",
    re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    title: "Clé privée en clair",
    detail: "Une clé cryptographique privée est présente directement dans le code source.",
    fix: "Retirez la clé du dépôt, régénérez-la, et chargez-la depuis un secret manager au runtime.",
  },
  {
    id: "generic-secret",
    re: /\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*["'][A-Za-z0-9\-_.]{8,}["']/gi,
    title: "Identifiant ou secret codé en dur",
    detail: "Un mot de passe, token ou clé semble écrit directement dans le code plutôt que chargé dynamiquement.",
    fix: "Utilisez des variables d'environnement (.env, secret manager) et ajoutez ce fichier à .gitignore si nécessaire.",
  },
];

export const SCANNABLE_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".py", ".json", ".yml", ".yaml", ".env", ".txt", ".md", ".html",
  ".sql", ".rules", ".toml",
  ".php", ".phtml",
  ".go", ".rb", ".java",
]);

function lineOfIndex(str, idx) {
  let line = 1;
  for (let i = 0; i < idx; i++) if (str.charCodeAt(i) === 10) line++;
  return line;
}

export function scanSecrets(relativePath, content) {
  const findings = [];

  for (const rule of SECRET_RULES) {
    const re = new RegExp(rule.re.source, rule.re.flags);
    let m;
    while ((m = re.exec(content))) {
      findings.push({
        category: "Secrets & Fuites de Clés",
        severity: "critical",
        ruleId: rule.id.toUpperCase().replace(/-/g, "_"),
        title: rule.title,
        detail: rule.detail,
        fix: rule.fix,
        location: `${relativePath}:${lineOfIndex(content, m.index)}`,
        snippet: m[0].length > 30 ? `${m[0].substring(0, 12)}...${m[0].slice(-6)}` : m[0],
      });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  return findings;
}