export function detectStack(fileEntries) {
  const stack = {
    hasSupabase: false,
    hasFirebase: false,
    hasExpress: false,
    hasPrisma: false,
    hasDrizzle: false,
    hasLaravel: false,
    hasWordPress: false,
  };

  const pkgEntry = fileEntries.find((f) => f.relativePath === "package.json");
  if (pkgEntry) {
    try {
      const pkg = JSON.parse(pkgEntry.content);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };

      if (deps["@supabase/supabase-js"]) stack.hasSupabase = true;
      if (deps["firebase"] || deps["firebase-admin"]) stack.hasFirebase = true;
      if (deps["express"]) stack.hasExpress = true;
      if (deps["@prisma/client"] || deps["prisma"]) stack.hasPrisma = true;
      if (deps["drizzle-orm"]) stack.hasDrizzle = true;
    } catch {}
  }

  const composerEntry = fileEntries.find((f) => f.relativePath === "composer.json");
  if (composerEntry) {
    try {
      const composer = JSON.parse(composerEntry.content);
      const deps = { ...composer.require, ...composer["require-dev"] };
      if (deps["laravel/framework"]) stack.hasLaravel = true;
    } catch {}
  }

  // Détection complémentaire par présence de dossiers/fichiers spécifiques
  if (fileEntries.some((f) => f.relativePath.startsWith("supabase/"))) {
    stack.hasSupabase = true;
  }
  if (fileEntries.some((f) => f.relativePath.includes("firestore.rules"))) {
    stack.hasFirebase = true;
  }
  if (fileEntries.some((f) => /(^|\/)wp-config\.php$/.test(f.relativePath))) {
    stack.hasWordPress = true;
  }

  return stack;
}