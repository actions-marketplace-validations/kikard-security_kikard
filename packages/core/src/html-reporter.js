import { writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Toutes les valeurs ci-dessous peuvent contenir du contenu contrôlé par le dépôt scanné
// (nom de package depuis package.json, nom de table depuis un fichier SQL, chemin de
// fichier...). AUCUNE ne doit être insérée dans le HTML sans passer par escapeHtml --
// c'est précisément le bug XSS corrigé ici (le "snippet" seul était échappé avant).
export async function generateHtmlReport(scanResults, outputPath = "kikard-report.html") {
  const htmlContent = buildHtmlReportString(scanResults);
  const absolutePath = path.resolve(outputPath);
  await writeFile(absolutePath, htmlContent, "utf8");

  return {
    filePath: absolutePath,
    fileUrl: pathToFileURL(absolutePath).href,
  };
}

export function buildHtmlReportString(scanResults) {
  const { findings = [], targetDir, durationMs, scannedFilesCount, totalDeps } = scanResults;

  const stats = {
    critical: findings.filter((f) => f.severity === "critical").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };

  const findingsHtml = findings
    .map((f) => {
      const severity = ["critical", "medium", "low", "info"].includes(f.severity) ? f.severity : "info";
      const searchBlob = escapeHtml(`${f.title || ""} ${f.location || ""} ${f.ruleId || ""}`.toLowerCase());
      return `
        <div class="finding-card" data-severity="${severity}" data-search="${searchBlob}">
          <div class="finding-header">
            <span class="finding-title">${escapeHtml(f.title)}</span>
            <span class="severity-badge severity-${severity}">${escapeHtml(f.severity)}</span>
          </div>
          <div class="location">📍 ${escapeHtml(f.location)} ${f.ruleId ? `[${escapeHtml(f.ruleId)}]` : ""}</div>
          <div class="detail">${escapeHtml(f.detail)}</div>
          ${f.snippet ? `<div class="snippet-box"><code>${escapeHtml(f.snippet)}</code></div>` : ""}
          ${f.fix ? `<div class="fix-box">💡 <strong>Correction suggérée :</strong> ${escapeHtml(f.fix)}</div>` : ""}
        </div>`;
    })
    .join("");

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Rapport de Sécurité kikard</title>
  <style>
    :root {
      --bg-primary: #0f172a;
      --bg-secondary: #1e293b;
      --bg-card: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --border-color: #475569;
      --crit-color: #ef4444;
      --med-color: #f59e0b;
      --low-color: #3b82f6;
      --info-color: #64748b;
      --success-color: #10b981;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background-color: var(--bg-primary); color: var(--text-main); padding: 2rem; line-height: 1.5; }
    .container { max-width: 1200px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-color); }
    h1 { font-size: 1.8rem; display: flex; align-items: center; gap: 0.5rem; }
    .badge-kikard { background: #6366f1; font-size: 0.8rem; padding: 0.2rem 0.6rem; border-radius: 9999px; text-transform: uppercase; }
    .meta { font-size: 0.9rem; color: var(--text-muted); }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .stat-card { background: var(--bg-secondary); padding: 1.2rem; border-radius: 8px; border-left: 4px solid var(--border-color); }
    .stat-card.critical { border-left-color: var(--crit-color); }
    .stat-card.medium { border-left-color: var(--med-color); }
    .stat-card.low { border-left-color: var(--low-color); }
    .stat-card.info { border-left-color: var(--info-color); }
    .stat-value { font-size: 2rem; font-weight: bold; margin-top: 0.2rem; }
    .controls { display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
    .search-box { flex: 1; min-width: 250px; background: var(--bg-secondary); border: 1px solid var(--border-color); padding: 0.6rem 1rem; border-radius: 6px; color: var(--text-main); }
    .filter-btn { background: var(--bg-secondary); border: 1px solid var(--border-color); color: var(--text-main); padding: 0.6rem 1rem; border-radius: 6px; cursor: pointer; transition: 0.2s; }
    .filter-btn.active, .filter-btn:hover { background: #475569; }
    .findings-list { display: flex; flex-direction: column; gap: 1rem; }
    .finding-card { background: var(--bg-secondary); border-radius: 8px; padding: 1.2rem; border: 1px solid var(--border-color); }
    .finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem; }
    .finding-title { font-size: 1.1rem; font-weight: 600; }
    .severity-badge { text-transform: uppercase; font-size: 0.75rem; font-weight: bold; padding: 0.2rem 0.5rem; border-radius: 4px; color: #fff; }
    .severity-critical { background: var(--crit-color); }
    .severity-medium { background: var(--med-color); }
    .severity-low { background: var(--low-color); }
    .severity-info { background: var(--info-color); }
    .location { font-family: monospace; font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.8rem; }
    .detail { margin-bottom: 0.8rem; font-size: 0.95rem; }
    .fix-box { background: rgba(16, 185, 129, 0.1); border: 1px solid var(--success-color); padding: 0.8rem; border-radius: 6px; font-size: 0.9rem; color: #a7f3d0; }
    .snippet-box { background: #000; font-family: monospace; padding: 0.6rem; border-radius: 4px; margin: 0.5rem 0; overflow-x: auto; color: #f1f5f9; }
    .empty-state { text-align: center; padding: 3rem; color: var(--text-muted); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>kikard <span class="badge-kikard">Security Scan</span></h1>
        <div class="meta">Cible : ${escapeHtml(targetDir)} | Fichiers scannés : ${Number(scannedFilesCount) || 0} | Dépendances vérifiées : ${Number(totalDeps) || 0}</div>
      </div>
      <div class="meta">Durée : ${(Number(durationMs) / 1000 || 0).toFixed(2)}s</div>
    </header>

    <div class="stats-grid">
      <div class="stat-card critical"><div>CRITIQUE</div><div class="stat-value">${stats.critical}</div></div>
      <div class="stat-card medium"><div>MOYEN</div><div class="stat-value">${stats.medium}</div></div>
      <div class="stat-card low"><div>FAIBLE</div><div class="stat-value">${stats.low}</div></div>
      <div class="stat-card info"><div>INFO</div><div class="stat-value">${stats.info}</div></div>
    </div>

    <div class="controls">
      <input type="text" id="search" class="search-box" placeholder="Rechercher par règle, chemin, mot-clé...">
      <button class="filter-btn active" data-severity-filter="all">Tous (${findings.length})</button>
      <button class="filter-btn" data-severity-filter="critical">Critiques</button>
      <button class="filter-btn" data-severity-filter="medium">Moyens</button>
      <button class="filter-btn" data-severity-filter="low">Faibles</button>
    </div>

    <div id="findings" class="findings-list">
      ${findings.length === 0 ? '<div class="empty-state">✅ Aucun problème détecté. Votre projet est propre !</div>' : ""}
      ${findingsHtml}
    </div>
  </div>

  <script>
    // Pas de onclick/oninput inline -- addEventListener uniquement, compatible avec une
    // Content-Security-Policy stricte sans 'unsafe-inline'.
    let currentSeverity = 'all';

    document.querySelectorAll('[data-severity-filter]').forEach((btn) => {
      btn.addEventListener('click', () => {
        currentSeverity = btn.dataset.severityFilter;
        document.querySelectorAll('.filter-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        filterFindings();
      });
    });

    const searchInput = document.getElementById('search');
    if (searchInput) searchInput.addEventListener('input', filterFindings);

    function filterFindings() {
      const q = (searchInput ? searchInput.value : '').toLowerCase();
      document.querySelectorAll('.finding-card').forEach((card) => {
        const matchesSev = currentSeverity === 'all' || card.dataset.severity === currentSeverity;
        const matchesSearch = !q || card.dataset.search.includes(q);
        card.style.display = matchesSev && matchesSearch ? 'block' : 'none';
      });
    }
  </script>
</body>
</html>`;
}
