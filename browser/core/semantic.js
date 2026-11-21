/* Small, deterministic native-ad classifier. No browser APIs, model calls, network or storage.
 * Page text is evidence, never an instruction. The content adapter owns opaque candidate IDs,
 * protected-node checks, staleness and the only permitted action: a reversible local hide. */
(function (root) {
  "use strict";
  const CATEGORIES = Object.freeze(["paid-placement", "organic", "essential-commerce", "uncertain"]);
  const DISCLOSURES = new Set([
    "sponsored", "promoted", "advertisement", "paid advertisement", "paid partnership", "paid promotion", "sponsored content",
    "promoted content", "contenu sponsorisé", "sponsorisé", "sponsorisée", "publicité", "gesponsert", "anzeige",
    "publicidad", "patrocinado", "patrocinada", "contenido patrocinado", "conteúdo patrocinado", "publicidade",
  ]);
  const normal = (s) => typeof s === "string" ? s.replace(/\s+/g, " ").trim().toLowerCase() : "";
  const disclosure = (s) => typeof s === "string" && s.length <= 80 && DISCLOSURES.has(normal(s));
  const SENSITIVE_PATH = /(?:^|\/)(?:log-?in|sign-?in|checkout|payments?|banking|inbox|messages?|messaging|mail|chats?|conversations?|accounts?|settings|private|patients?|medical|health|health-?records?|patient-?portal|prescriptions?|appointments?)(?:\/|[._-]|$)/i;
  const PRIVATE_APPS = ["slack.com", "discord.com", "discordapp.com", "teams.microsoft.com", "teams.live.com", "whatsapp.com", "web.telegram.org", "messenger.com", "outlook.office365.com"];
  function sensitiveLocation(href) {
    if (!href) return false;
    try {
      const u = new URL(href);
      if (!/^https?:$/.test(u.protocol)) return true;
      return SENSITIVE_PATH.test(u.pathname) || /^(?:mail|webmail|banking)\./i.test(u.hostname) || /(^|\.)outlook\.(?:live|office)\.com$/i.test(u.hostname) || PRIVATE_APPS.some((h) => u.hostname === h || u.hostname.endsWith(`.${h}`));
    } catch { return true; }
  }
  function sanitizeText(text, limit = 400) {
    return String(text || "").replace(/https?:\/\/\S+/gi, "[link]")
      .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[email]")
      .replace(/\b[A-Za-z0-9_+-]{32,}\b/g, "[identifier]").replace(/\b\d{12,}\b/g, "[number]")
      .replace(/\s+/g, " ").trim().slice(0, limit);
  }
  function classify(candidate) {
    if (!candidate || typeof candidate !== "object") return {category: "uncertain", confidence: "low"};
    if (candidate.protected || candidate.commerce || candidate.sensitive) return {category: "essential-commerce", confidence: "high"};
    const labels = Array.isArray(candidate.disclosures) ? candidate.disclosures.filter(disclosure) : [];
    const s = candidate.structure || {};
    if (labels.length && !s.nestedCards && s.hasLink === true && Number.isInteger(s.repeatedPeers) && s.repeatedPeers >= 1 && s.textLength >= 12 && s.textLength <= 1200) {
      return {category: "paid-placement", confidence: "high"};
    }
    if (candidate.explicitOrganic === true) return {category: "organic", confidence: "high"};
    return {category: "uncertain", confidence: "low"};
  }
  const api = Object.freeze({CATEGORIES, normal, disclosure, classify, sensitiveLocation, sanitizeText});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGSemantic = api;
})(globalThis);
