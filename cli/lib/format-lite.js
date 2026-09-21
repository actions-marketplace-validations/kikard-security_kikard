// Parseur TOML volontairement minimal : ne comprend que ce qu'il faut pour extraire
// des noms de dépendances depuis pyproject.toml / Cargo.toml. Ce n'est pas un parseur
// TOML conforme à la spec (pas de gestion des tables inline complexes, des dates, etc.)
// -- largement suffisant pour la structure standard de ces deux fichiers.

function stripVersionSpecifier(raw) {
  return raw
    .split(/[=<>!~\s;\[]/)[0]
    .trim()
    .toLowerCase();
}

// Découpe le fichier en sections indexées par leur en-tête [section] ou [[section]]
function splitIntoSections(raw) {
  const sections = [];
  let current = { header: "", lines: [] };
  for (const line of raw.split(/\r?\n/)) {
    const match = line.match(/^\s*\[\[?([^\]]+)\]\]?\s*$/);
    if (match) {
      sections.push(current);
      current = { header: match[1].trim(), lines: [] };
    } else {
      current.lines.push(line);
    }
  }
  sections.push(current);
  return sections;
}

// [13/09/2026] Chaque extracteur ci-dessous renvoyait uniquement le NOM de la dépendance --
// suffisant pour la détection de hallucination (qui ne compare que des noms à un registre),
// mais insuffisant pour un SBOM, où lister un composant sans version n'a guère de sens. Les
// fonctions renvoient désormais { name, version } -- `version` reste la contrainte déclarée
// dans le manifeste (ex: "^2.28", "~> 1.0"), PAS une version résolue depuis un lockfile
// (aucun de ces parseurs ne lit pnpm-lock.yaml/poetry.lock/Cargo.lock/etc.) -- `null` quand
// le fichier ne déclare aucune contrainte exploitable. Tous les appelants existants qui ne
// consomment que le nom (détection de hallucination) continuent de fonctionner à l'identique
// via `.name` -- aucun appelant n'itérait directement sur une chaîne brute auparavant sans
// know déjà qu'il s'agissait d'un nom.

// [project] dependencies = ["requests>=2.28", "flask~=2.0"]  (PEP 621, tableau multi-lignes toléré)
export function extractPep621Dependencies(raw) {
  const deps = [];
  const sections = splitIntoSections(raw);
  for (const section of sections) {
    if (section.header !== "project") continue;
    const text = section.lines.join("\n");
    const match = text.match(/dependencies\s*=\s*\[([\s\S]*?)\]/);
    if (!match) continue;
    const items = match[1].match(/"([^"]+)"|'([^']+)'/g) || [];
    for (const item of items) {
      const raw2 = item.slice(1, -1);
      const name = stripVersionSpecifier(raw2);
      if (!name) continue;
      const version = raw2.slice(name.length).trim() || null;
      deps.push({ name, version });
    }
  }
  return deps;
}

// [tool.poetry.dependencies] \n requests = "^2.28" \n numpy = { version = "^1.24" }
export function extractPoetryDependencies(raw) {
  const deps = [];
  const sections = splitIntoSections(raw);
  for (const section of sections) {
    if (section.header !== "tool.poetry.dependencies" && section.header !== "tool.poetry.group.dev.dependencies") continue;
    for (const line of section.lines) {
      const match = line.match(/^\s*([A-Za-z0-9_.-]+)\s*=\s*(.+)$/);
      if (!match) continue;
      const name = match[1].toLowerCase();
      if (name === "python") continue; // pas un package, c'est la contrainte de version Python elle-même
      const rest = match[2].trim();
      // Forme simple : requests = "^2.28"  --  forme table inline : numpy = { version = "^1.24", ... }
      const simple = rest.match(/^["']([^"']+)["']/);
      const inline = rest.match(/version\s*=\s*["']([^"']+)["']/);
      deps.push({ name, version: simple ? simple[1] : inline ? inline[1] : null });
    }
  }
  return deps;
}

// [dependencies] \n serde = "1.0" \n tokio = { version = "1", features = ["full"] }
export function extractCargoDependencies(raw) {
  const deps = [];
  const sections = splitIntoSections(raw);
  for (const section of sections) {
    if (!/^dependencies$|^dev-dependencies$|^build-dependencies$/.test(section.header)) continue;
    for (const line of section.lines) {
      const match = line.match(/^\s*([A-Za-z0-9_-]+)\s*=\s*(.+)$/);
      if (!match) continue;
      const rest = match[2].trim();
      const simple = rest.match(/^["']([^"']+)["']/);
      const inline = rest.match(/version\s*=\s*["']([^"']+)["']/);
      deps.push({ name: match[1].toLowerCase(), version: simple ? simple[1] : inline ? inline[1] : null });
    }
  }
  return deps;
}

// go.mod : require ( ... ) en bloc, ou "require module version" sur une seule ligne.
// Les dépendances marquées "// indirect" sont exclues : elles sont calculées automatiquement
// par `go mod tidy` à partir des dépendances réelles des dépendances directes -- une IA ne
// peut pas les halluciner, ce n'est pas elle qui les écrit.
export function extractGoModules(raw) {
  const deps = [];
  const lines = raw.split(/\r?\n/);
  let inBlock = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (/^require\s*\(/.test(trimmed)) {
      inBlock = true;
      continue;
    }
    if (inBlock && trimmed === ")") {
      inBlock = false;
      continue;
    }
    if (trimmed.includes("// indirect")) continue;

    if (inBlock) {
      const m = trimmed.match(/^(\S+)\s+(v\S+)/);
      if (m) deps.push({ name: m[1], version: m[2] });
    } else {
      const m = trimmed.match(/^require\s+(\S+)\s+(v\S+)/);
      if (m) deps.push({ name: m[1], version: m[2] });
    }
  }
  return deps;
}

// Gemfile : gem "name", gem 'name', gem("name", "~> 1.0")
export function extractGemfileDependencies(raw) {
  const deps = [];
  const re = /\bgem\s*\(?\s*['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/g;
  let m;
  while ((m = re.exec(raw))) deps.push({ name: m[1].toLowerCase(), version: m[2] || null });
  return deps;
}

// pom.xml : extrait groupId:artifactId (+ version si présente dans le même bloc -- souvent
// absente quand elle est héritée d'un <parent>/BOM, ce parseur minimal ne résout pas cet
// héritage) depuis chaque bloc <dependency>...</dependency>.
export function extractMavenDependencies(raw) {
  const deps = [];
  const blockRe = /<dependency>([\s\S]*?)<\/dependency>/g;
  let block;
  while ((block = blockRe.exec(raw))) {
    const g = block[1].match(/<groupId>\s*([^<]+?)\s*<\/groupId>/);
    const a = block[1].match(/<artifactId>\s*([^<]+?)\s*<\/artifactId>/);
    const v = block[1].match(/<version>\s*([^<]+?)\s*<\/version>/);
    if (g && a) deps.push({ name: `${g[1]}:${a[1]}`, version: v ? v[1] : null });
  }
  return deps;
}
