// Azure Translator helper (Dozie) — FR<->EN, FAIL-OPEN. Identical behaviour to
// the MP backend's backend/src/lib/azureTranslate.js — keep the two in lockstep.
// Key + region from env, NEVER hardcoded (AZURE_TRANSLATOR_KEY /
// AZURE_TRANSLATOR_REGION, default "westcentralus"). Global endpoint.
//
// translateToFrEn(texts) -> Promise<Array<{fr, en}>>, one entry per input, in
// order. One call returns BOTH targets per input (?to=fr&to=en) over an
// auto-detected source; the same-language target echoes the original so both
// fields fill in one round trip.
//
// Blank/empty input -> {fr:'', en:''} without calling the API.
// FAIL-OPEN: key unset, or request error/timeout -> {fr:t, en:t} per input +
// console.warn; NEVER throws. A translation problem must never block a publish.

const ENDPOINT = 'https://api.cognitive.microsofttranslator.com';

async function translateToFrEn(texts) {
  const arr = Array.isArray(texts) ? texts : [];
  const items = arr.map(function (t) { return { src: (t == null ? '' : String(t)), fr: '', en: '' }; });

  const sendIdx = [];
  const body = [];
  items.forEach(function (it, i) { if (it.src.trim() !== '') { sendIdx.push(i); body.push({ Text: it.src }); } });
  if (!body.length) return items.map(function (it) { return { fr: it.fr, en: it.en }; });

  const key = process.env.AZURE_TRANSLATOR_KEY;
  const region = process.env.AZURE_TRANSLATOR_REGION || 'westcentralus';
  if (!key) {
    console.warn('[dozie-translate] AZURE_TRANSLATOR_KEY unset — storing source text in both languages');
    return items.map(function (it) { return { fr: it.src, en: it.src }; });
  }

  try {
    const ctrl = new AbortController();
    const timer = setTimeout(function () { ctrl.abort(); }, 8000);
    let resp;
    try {
      resp = await fetch(ENDPOINT + '/translate?api-version=3.0&to=fr&to=en', {
        method: 'POST',
        headers: {
          'Ocp-Apim-Subscription-Key': key,
          'Ocp-Apim-Subscription-Region': region,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
    } finally { clearTimeout(timer); }
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const data = await resp.json();

    sendIdx.forEach(function (origI, j) {
      const it = items[origI];
      let fr = it.src, en = it.src;
      const tr = data && data[j] && Array.isArray(data[j].translations) ? data[j].translations : null;
      if (tr) for (const t of tr) {
        if (t.to === 'fr') fr = t.text;
        else if (t.to === 'en') en = t.text;
      }
      it.fr = fr; it.en = en;
    });
    return items.map(function (it) { return { fr: it.fr, en: it.en }; });
  } catch (e) {
    console.warn('[dozie-translate] translate failed (' + (e && e.message) + ') — storing source text in both languages');
    return items.map(function (it) { return { fr: it.src, en: it.src }; });
  }
}

module.exports = { translateToFrEn };
