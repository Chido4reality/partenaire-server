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

  // Expand a raw query into the term sets used for matching + ranking.
  // ADDITIVE (anything that matched before still matches). Returns:
  //   direct   : the raw query + its tokens (matched directly against listings;
  //              score() ranks exact-word > prefix-of-word > mid-substring)
  //   synExact : every term of any group triggered by an EXACT token, the full
  //              query, or a multiword phrase appearing inside the query
  //   synPrefix: every term of any group triggered because a query token (>=2
  //              chars) is a PREFIX of a synonym term — this is what lets a
  //              partial like "cha"/"cham" reach the chambre->tube cluster
  //              before the whole word "chambre" is typed
  //   terms    : back-compat union (direct + synExact, len>=2) for matchNorm()
  function expand(rawQ, index) {
    var norm = normalize(rawQ);
    var tokens = norm ? norm.split(' ').filter(Boolean) : [];
    var directSet = new Set();
    if (norm) directSet.add(norm);
    tokens.forEach(function (t) { directSet.add(t); });

    var synExact = new Set();
    var synPrefix = new Set();
    if (index) {
      var exactGroups = new Set();
      // EXACT single-term triggers (full query or any token equals a term).
      [norm].concat(tokens).forEach(function (cand) {
        var gis = index.single.get(cand);
        if (gis) gis.forEach(function (gi) { exactGroups.add(gi); });
      });
      // Multiword synonym term appearing inside the query (also "exact").
      index.phrase.forEach(function (p) {
        if (norm === p.t || norm.indexOf(p.t) >= 0) exactGroups.add(p.gi);
      });
      exactGroups.forEach(function (gi) {
        index.groups[gi].forEach(function (t) { synExact.add(t); });
      });
      // PREFIX triggers: a query token (>=2 chars; 1-letter stays whole-word)
      // is a PREFIX of a synonym term. Only groups not already exact-triggered.
      var prefixGroups = new Set();
      tokens.forEach(function (tok) {
        if (tok.length < 2) return;
        index.single.forEach(function (gis, term) {
          if (term.length > tok.length && term.indexOf(tok) === 0) {
            gis.forEach(function (gi) { if (!exactGroups.has(gi)) prefixGroups.add(gi); });
          }
        });
        index.phrase.forEach(function (p) {
          if (p.t.length > tok.length && p.t.indexOf(tok) === 0 && !exactGroups.has(p.gi)) {
            prefixGroups.add(p.gi);
          }
        });
      });
      prefixGroups.forEach(function (gi) {
        index.groups[gi].forEach(function (t) { synPrefix.add(t); });
      });
    }

    var direct = [];
    directSet.forEach(function (t) { if (t) direct.push(t); });
    var synExactArr = [], synPrefixArr = [];
    synExact.forEach(function (t) { if (t.length >= 2) synExactArr.push(t); });
    synPrefix.forEach(function (t) { if (t.length >= 2) synPrefixArr.push(t); });

    // Back-compat union for any matchNorm() caller (direct + synExact, len>=2).
    var termsSet = new Set();
    direct.forEach(function (t) { if (t.length >= 2) termsSet.add(t); });
    synExactArr.forEach(function (t) { termsSet.add(t); });
    var terms = [];
    termsSet.forEach(function (t) { terms.push(t); });

    return {
      norm: norm, tokens: tokens, direct: direct,
      synExact: synExactArr, synPrefix: synPrefixArr, terms: terms,
    };
  }

  // DOZIE-BILINGUAL: the raw searchable text for a marketplace row — ALL FOUR
  // language fields (FR + EN name + description), plus the legacy name/description
  // as a fallback so a pre-backfill row still matches. ONE place so the server
  // (_norm) and the client (_n) can't drift on which fields are searched.
  function searchableText(p) {
    if (!p) return '';
    return [p.name_fr, p.name_en, p.description_fr, p.description_en, p.name, p.description]
      .filter(Boolean).join(' ');
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

  // Rank a listing's ALREADY-normalized text against an expand() result.
  // Returns 0 (no match) or a tier — higher = more relevant. Tiers, so a loose
  // prefix can never outrank a direct name hit:
  //   100 direct exact whole-word        80 direct prefix-of-word
  //    60 direct mid-word substring       40 synonym (exact-trigger)
  //    20 synonym (prefix-trigger, loosest)
  // Guardrail: 1-letter query tokens match WHOLE-WORD only (no prefix/substring/
  // synonym) so single keystrokes don't flood.
  function score(normText, ex) {
    if (!normText || !ex) return 0;
    var words = normText.split(' ');
    var best = 0;
    var direct = ex.direct || [];
    for (var i = 0; i < direct.length; i++) {
      var t = direct[i];
      if (!t) continue;
      if (words.indexOf(t) >= 0) { best = 100; break; }   // exact whole word
      if (t.length < 2) continue;                         // 1-letter: whole-word only
      var pref = false, sub = false;
      for (var w = 0; w < words.length; w++) {
        var pos = words[w].indexOf(t);
        if (pos === 0) { pref = true; break; }
        if (pos > 0) sub = true;
      }
      if (pref) { if (best < 80) best = 80; }
      else if (sub) { if (best < 60) best = 60; }
    }
    if (best >= 100) return best;
    var se = ex.synExact || [];
    for (var j = 0; j < se.length; j++) {
      if (se[j].length >= 2 && normText.indexOf(se[j]) >= 0) { if (best < 40) best = 40; break; }
    }
    if (best >= 40) return best;
    var sp = ex.synPrefix || [];
    for (var k = 0; k < sp.length; k++) {
      if (sp[k].length >= 2 && normText.indexOf(sp[k]) >= 0) { best = 20; break; }
    }
    return best;
  }

  return {
    normalize: normalize,
    buildIndex: buildIndex,
    expand: expand,
    matchNorm: matchNorm,
    productMatches: productMatches,
    searchableText: searchableText,
    score: score,
  };
});
