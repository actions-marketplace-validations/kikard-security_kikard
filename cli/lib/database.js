function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export async function scanDatabase(fileEntries) {
  const findings = [];

  for (const { relativePath, content } of fileEntries) {
    // 1. Supabase RLS sur les fichiers SQL -- vérifié table par table, pas au niveau du fichier entier
    if (relativePath.endsWith(".sql")) {
      const createMatches = content.match(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([^\s\();]+)/gi);

      if (createMatches) {
        for (const match of createMatches) {
          const tableName = match.split(/\s+/).pop()?.replace(/["`]/g, "");
          if (!tableName) continue;

          // Le nom peut être qualifié par un schéma (ex: public.users) -- on compare sur le nom nu,
          // et on tolère un préfixe de schéma optionnel dans le ALTER TABLE correspondant.
          const bareName = tableName.includes(".") ? tableName.split(".").pop() : tableName;
          const rlsForThisTable = new RegExp(
            `ALTER\\s+TABLE\\s+(?:[\\w"\`]+\\.)?["\`]?${escapeRegex(bareName)}["\`]?\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`,
            "i"
          );

          if (!rlsForThisTable.test(content)) {
            findings.push({
              category: "RLS Supabase",
              severity: "critical",
              ruleId: "SUPABASE_RLS_DISABLED",
              title: `Row Level Security (RLS) désactivée sur '${tableName}'`,
              location: relativePath,
              detail: "Sans RLS, cette table Supabase est totalement accessible en lecture/écriture via l'API publique.",
              fix: `Ajoutez 'ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;' ainsi qu'au moins une policy pour cette table.`,
            });
          }
        }
      }
    }

    // 2. Firebase Security Rules
    if (relativePath.endsWith("firestore.rules")) {
      if (/allow\s+read,\s*write\s*:\s*if\s+true\s*;/i.test(content)) {
        findings.push({
          category: "Firebase Rules",
          severity: "critical",
          ruleId: "FIREBASE_OPEN",
          title: "Règles Firestore ouvertes à tous",
          location: relativePath,
          detail: "La règle 'allow read, write: if true' autorise la lecture et modification anonyme de toute la BDD.",
          fix: "Restreignez les droits (ex: 'allow read, write: if request.auth != null;').",
        });
      }
    }
  }

  return findings;
}