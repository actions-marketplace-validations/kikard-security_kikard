// Norme KIKARD -- vérification publique d'un certificat depuis le CLI (`kikard verify
// <jeton>`, 03/09/2026). Même principe que local/licensing.js:getLicenseStatus pour la forme
// (timeout court, jamais d'exception qui remonte à l'appelant), mais SANS clé API : la route
// GET /api/certify/verify/:token (dashboard/routes/certification.js) est volontairement
// publique et sans compte (article 8.3 du Référentiel technique -- vérifiable depuis le CLI,
// le dashboard, le site public, l'app mobile, sans authentification), donc rien ici ne lit ni
// n'envoie ~/.kikard/config.json. Jeton opaque + revérification serveur systématique
// (article 8.2, CWE-602) : cette fonction ne fait JAMAIS confiance à un jeton en le décodant
// localement -- elle interroge le serveur à chaque appel, sans exception.
const VERIFY_TIMEOUT_MS = 5000;

export async function verifyCertificateToken(token, apiUrl) {
  try {
    const res = await fetch(`${apiUrl.replace(/\/$/, "")}/api/certify/verify/${encodeURIComponent(token)}`, {
      signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
    });
    if (!res.ok && res.status !== 429) {
      // Un 404/400/500 renvoie quand même un corps JSON exploitable côté serveur
      // (dashboard/lib/certification.js:verifyCertificate renvoie toujours { found: false }
      // ou { found: true, ... }, jamais un statut HTTP seul) -- mais on ne présume jamais du
      // format d'une réponse non-2xx inattendue (proxy, pare-feu, serveur non-kikard).
      return { found: false, error: "http_error", status: res.status };
    }
    const data = await res.json();
    if (res.status === 429) return { found: false, error: "rate_limited", retryInMinutes: data?.error };
    return data;
  } catch (err) {
    return { found: false, error: "network" };
  }
}
