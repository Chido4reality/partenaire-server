// DOZIE-BILINGUAL-SEARCH — shared search logic (ONE source of truth).
//
// Loaded by BOTH:
//   • the server (partenaire_server.js: require('./dozie_search.js')) for the
//     /api/dozie/search-products endpoint + miss logging, and
//   • the buyer marketplace feed (PARTENAIRE_Buyer.html:
//     <script src="/dozie_search.js"> → window.DozieSearch), which expands the
//     query and matches the published catalogue CLIENT-SIDE against Supabase.
//
// Having one module means the two paths can't drift apart: the same normalize()
// and the same synonym expansion run no matter which path serves a search. The
// synonym groups live in data/dozie_synonyms.json (also one source); both sides
// pass that array to buildIndex().
//
// UMD: works under Node (module.exports) and the browser (window.DozieSearch).
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.DozieSearch = factory();
})(typeof self !== 'undefined' ? self : this, function () {

  // Lowercase, strip accents/diacritics (NFD → drop combining marks), collapse
  // whitespace. So "Chambre à air", "chambre a air" and "CHAMBRE  À  AIR" all
  // compare equal. Applied to BOTH the query and the product searchable text.
  function normalize(s) {
    return String(s == null ? '' : s)
      .toLowerCase()
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
      .replace(/\s+/g, ' ')
      .trim();
  }

  // Pre-normalize every term of every group into fast lookups:
  //   single : normalized single-word term  → [groupIndex,…]
  //   phrase : { t: normalized multiword term, gi: groupIndex }
  function buildIndex(groups) {
    const normGroups = (groups || []).map(function (g) {
      var seen = {}, out = [];
      (g || []).forEach(function (term) {
        var t = normalize(term);
        if (t && !seen[t]) { seen[t] = 1; out.push(t); }
      });
      return out;
    });
    var single = new Map();
    var phrase = [];
    normGroups.forEach(function (terms, gi) {
      terms.forEach(function (t) {
        if (t.indexOf(' ') >= 0) phrase.push({ t: t, gi: gi });
        else { if (!single.has(t)) single.set(t, []); single.get(t).push(gi); }
      });
    });
    return { groups: normGroups, single: single, phrase: phrase };
  }

  // Expand a raw query into the set of normalized terms to match against.
  // ALWAYS includes the raw normalized query + its tokens (ADDITIVE: anything
  // that matched the plain query before still matches), then unions in every
  // term of any group triggered by an exact token, the full query, or a
  // multiword phrase appearing inside the query.
  function expand(rawQ, index) {
    var norm = normalize(rawQ);
    var tokens = norm ? norm.split(' ').filter(Boolean) : [];
    var terms = new Set();
    if (norm) terms.add(norm);
    tokens.forEach(function (t) { terms.add(t); });
    if (index) {
      var triggered = new Set();
      [norm].concat(tokens).forEach(function (cand) {
        var gis = index.single.get(cand);
        if (gis) gis.forEach(function (gi) { triggered.add(gi); });
      });
      index.phrase.forEach(function (p) {
        if (norm === p.t || norm.indexOf(p.t) >= 0) triggered.add(p.gi);
      });
      triggered.forEach(function (gi) {
        index.groups[gi].forEach(function (t) { terms.add(t); });
      });
    }
    var arr = [];
    terms.forEach(function (t) { if (t && t.length >= 2) arr.push(t); });
    return { norm: norm, terms: arr };
  }

  // Does an ALREADY-normalized product text contain any expanded term?
  function matchNorm(normText, terms) {
    for (var i = 0; i < terms.length; i++) {
      if (normText.indexOf(terms[i]) >= 0) return true;
    }
    return false;
  }

  // Convenience: normalize raw product text, then match.
  function productMatches(rawText, terms) {
    return matchNorm(normalize(rawText), terms);
  }

  return {
    normalize: normalize,
    buildIndex: buildIndex,
    expand: expand,
    matchNorm: matchNorm,
    productMatches: productMatches,
  };
});
