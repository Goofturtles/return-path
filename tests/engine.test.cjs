/* node tests/engine.test.cjs   — no dependencies, no network. */

const RP = require('../js/engine.js');
const { SAMPLES } = require('../js/samples.js');

let pass = 0, fail = 0;
const failures = [];

function t(name, fn) {
  try {
    fn();
    pass++;
  } catch (e) {
    fail++;
    failures.push(name + '\n      ' + e.message);
  }
}
function eq(actual, expected, msg) {
  const a = JSON.stringify(actual), b = JSON.stringify(expected);
  if (a !== b) throw new Error((msg ? msg + ': ' : '') + `expected ${b}, got ${a}`);
}
function ok(cond, msg) { if (!cond) throw new Error(msg || 'expected truthy'); }

const sample = id => SAMPLES.find(s => s.id === id).raw;
const ids = r => r.findings.map(f => f.id);
const has = (r, id) => r.findings.some(f => f.id === id || f.id.startsWith(id));
const sev = (r, id) => (r.findings.find(f => f.id === id || f.id.startsWith(id)) || {}).severity;

/* ---------- address parsing ---------- */

t('parseAddress takes the LAST angle-addr, not the first', () => {
  const a = RP.parseAddress('"PayPal <service@paypal.com>" <alerts@paypa1.com>');
  eq(a.address, 'alerts@paypa1.com');
  eq(a.domain, 'paypa1.com');
  eq(a.displayAddresses, ['service@paypal.com']);
});

t('parseAddress handles a bare address', () => {
  const a = RP.parseAddress('someone@example.org');
  eq(a.address, 'someone@example.org');
  eq(a.domain, 'example.org');
  eq(a.display, '');
});

t('parseAddress strips quotes from the display name', () => {
  eq(RP.parseAddress('"Dana Whitfield" <d@w.org>').display, 'Dana Whitfield');
});

t('parseAddress decodes RFC 2047 base64 display names', () => {
  // =?UTF-8?B?...?= for "Sécurité"
  const enc = '=?UTF-8?B?' + Buffer.from('Sécurité', 'utf8').toString('base64') + '?= <a@b.com>';
  eq(RP.parseAddress(enc).display, 'Sécurité');
});

t('parseAddress decodes RFC 2047 quoted-printable display names', () => {
  eq(RP.parseAddress('=?UTF-8?Q?Bank_Alert?= <a@b.com>').display, 'Bank Alert');
});

/* ---------- header parsing ---------- */

t('parseHeaders unfolds continuation lines', () => {
  const h = RP.parseHeaders('Subject: one\n  two\n\tthree\nFrom: a@b.c');
  eq(h.length, 2);
  eq(h[0].value, 'one two three');
  eq(h[1].key, 'from');
});

t('splitMessage separates headers from body on the first blank line', () => {
  const s = RP.splitMessage('A: 1\nB: 2\n\nbody here\n\nmore');
  eq(s.headerBlock, 'A: 1\nB: 2');
  eq(s.body, 'body here\n\nmore');
});

t('splitMessage normalises CRLF', () => {
  eq(RP.splitMessage('A: 1\r\n\r\nbody').body, 'body');
});

/* ---------- domains ---------- */

t('registrableDomain handles plain and multi-part TLDs', () => {
  eq(RP.registrableDomain('mail.accounts.google.com'), 'google.com');
  eq(RP.registrableDomain('foo.bar.co.uk'), 'bar.co.uk');
  eq(RP.registrableDomain('example.com'), 'example.com');
});

t('punycode decoder round-trips a real IDN label', () => {
  eq(RP.decodePunycodeHost('xn--pypal-4ve.com'), 'pаypal.com');
  eq(RP.decodePunycodeHost('xn--netflx-tvf.com'), 'netflіx.com');
  eq(RP.decodePunycodeHost('xn--microsft-secure-esm.com'), 'microsоft-secure.com');
});

t('punycode decoder returns null for ordinary hosts', () => {
  eq(RP.decodePunycodeHost('example.com'), null);
});

t('skeleton folds confusables to ASCII', () => {
  eq(RP.skeleton('pаypal.com'), 'paypal.com');   // Cyrillic а
  eq(RP.skeleton('paypa1.com'), 'paypal.com');   // digit one
  eq(RP.skeleton('rnicrosoft.com'), 'microsoft.com'); // rn -> m
});

t('lookalike catches digit substitution', () => {
  const l = RP.lookalike('paypa1.com');
  eq(l.brand, 'paypal.com');
  eq(l.kind, 'identical-skeleton');
});

t('lookalike catches a brand name on the wrong registrable domain', () => {
  const l = RP.lookalike('paypal.account-verify.mailer-7f2a.top');
  ok(l, 'expected a lookalike hit');
  eq(l.brand, 'paypal.com');
});

t('lookalike catches near-miss typos', () => {
  const l = RP.lookalike('micrsoft.com');
  ok(l && l.brand === 'microsoft.com', 'expected microsoft.com near-miss');
});

t('lookalike does NOT fire on the brand itself', () => {
  eq(RP.lookalike('paypal.com'), null);
  eq(RP.lookalike('accounts.google.com'), null);
});

t('lookalike does NOT fire on brand-owned secondary domains', () => {
  eq(RP.lookalike('amazonaws.com'), null, 'amazonaws.com is Amazon');
  eq(RP.lookalike('googleapis.com'), null);
  eq(RP.lookalike('githubusercontent.com'), null);
  eq(RP.lookalike('facebookmail.com'), null);
});

t('lookalike does NOT fire on unrelated domains', () => {
  eq(RP.lookalike('harbourbooks.com'), null);
  eq(RP.lookalike('westbrook-district.org'), null);
  eq(RP.lookalike('example.com'), null);
});

/* ---------- URLs ---------- */

t('parseUrl isolates userinfo from the real host', () => {
  const u = RP.parseUrl('https://www.paypal.com@203.0.113.77/secure/confirm');
  eq(u.host, '203.0.113.77');
  eq(u.userinfo, 'www.paypal.com');
});

t('parseUrl reads scheme and host normally', () => {
  const u = RP.parseUrl('https://Example.COM/a/b?c=1');
  eq(u.scheme, 'https');
  eq(u.host, 'example.com');
});

/* ---------- auth results ---------- */

t('parseAuthResults reads spf, dkim, dmarc and their domains', () => {
  const h = RP.parseHeaders([
    'Authentication-Results: mx.example.com;',
    '       dkim=pass header.d=accounts.google.com;',
    '       spf=pass smtp.mailfrom=3x@gaia.bounces.google.com;',
    '       dmarc=pass (p=REJECT dis=NONE) header.from=accounts.google.com'
  ].join('\n'));
  const a = RP.parseAuthResults(h);
  eq(a.dkim.result, 'pass');
  eq(a.dkim.domain, 'accounts.google.com');
  eq(a.spf.result, 'pass');
  eq(a.spf.domain, 'gaia.bounces.google.com');
  eq(a.dmarc.result, 'pass');
});

t('parseAuthResults falls back to Received-SPF', () => {
  const h = RP.parseHeaders('Received-SPF: fail (example.com: domain of b@c.top does not designate)');
  eq(RP.parseAuthResults(h).spf.result, 'fail');
});

/* ---------- hops ---------- */

t('parseHops orders oldest-first and computes deltas', () => {
  const h = RP.parseHeaders([
    'Received: from b.com (b.com. [1.2.3.4]) by c.com; Thu, 17 Sep 2026 03:12:44 -0700',
    'Received: from a.com (a.com. [5.6.7.8]) by b.com; Thu, 17 Sep 2026 03:12:40 -0700'
  ].join('\n'));
  const hops = RP.parseHops(h);
  eq(hops.length, 2);
  eq(hops[0].from, 'a.com', 'first hop should be the oldest Received');
  eq(hops[1].delta, 4);
});

/* ---------- links ---------- */

t('extractLinks pairs anchor text with href', () => {
  const parts = [{ type: 'text/html', decoded: '<a href="https://evil.test/x">https://www.paypal.com/signin</a>' }];
  const l = RP.extractLinks(parts)[0];
  eq(l.host, 'evil.test');
  eq(l.claimedRegistrable, 'paypal.com');
});

t('extractLinks finds bare URLs in plain text', () => {
  const parts = [{ type: 'text/plain', decoded: 'go to https://example.org/a now' }];
  eq(RP.extractLinks(parts)[0].host, 'example.org');
});

/* ---------- full analysis: credential phish ---------- */

const phish = RP.analyze(sample('credential-phish'));

t('phish: verdict is Forged', () => eq(phish.verdict.level, 'forged'));
t('phish: DMARC fail is caught', () => eq(sev(phish, 'dmarc-fail'), 'critical'));
t('phish: SPF fail is caught', () => ok(has(phish, 'spf-fail')));
t('phish: display name carrying a fake address is caught', () => {
  eq(sev(phish, 'display-name-address'), 'critical');
});
t('phish: lookalike From domain is caught', () => ok(has(phish, 'lookalike-From address')));
t('phish: envelope mismatch is high (nothing vouches for it)', () => {
  eq(sev(phish, 'envelope-mismatch'), 'high');
});
t('phish: Reply-To divergence is caught', () => ok(has(phish, 'reply-to-divergence')));
t('phish: link text/href mismatch is caught', () => ok(has(phish, 'link-mismatch')));
t('phish: @-in-URL trick is caught', () => ok(has(phish, 'link-userinfo')));
t('phish: shortener is caught', () => ok(has(phish, 'link-short')));
t('phish: pressure tactics are counted', () => ok(phish.pressure.length >= 2, 'pressure=' + phish.pressure));
t('phish: quoted-printable body was decoded', () => {
  ok(phish.parts[0].decoded.indexOf('=\n') === -1, 'soft line breaks should be gone');
});

/* ---------- full analysis: BEC ---------- */

const bec = RP.analyze(sample('bec'));

t('bec: authentication genuinely passes', () => {
  eq(bec.auth.dmarc.result, 'pass');
  ok(has(bec, 'auth-pass'), 'the good finding should be present');
});
t('bec: still reaches Suspicious', () => eq(bec.verdict.level, 'suspicious'));
t('bec: Reply-To divergence is the high finding', () => {
  eq(sev(bec, 'reply-to-divergence'), 'high');
});
t('bec: pressure stack is detected', () => ok(bec.pressure.length >= 2, 'pressure=' + bec.pressure));
t('bec: no link findings (there are no links)', () => {
  eq(bec.findings.filter(f => f.tag === 'Links').length, 0);
});

/* ---------- full analysis: homograph ---------- */

const homo = RP.analyze(sample('homograph'));

t('homo: verdict is Forged', () => eq(homo.verdict.level, 'forged'));
t('homo: punycode From domain is caught', () => ok(has(homo, 'punycode-From address')));
t('homo: punycode link is caught', () => ok(has(homo, 'link-puny')));
t('homo: the decoded display form is shown as evidence', () => {
  const f = homo.findings.find(x => x.id.startsWith('punycode-'));
  ok(f.evidence.some(e => e.text.indexOf('microsоft-secure.com') !== -1), 'should show the unicode form');
});

/* ---------- full analysis: payload ---------- */

const payload = RP.analyze(sample('payload'));

t('payload: double extension is caught', () => ok(has(payload, 'att-double')));
t('payload: macro document is caught', () => ok(has(payload, 'att-macro')));
t('payload: both attachments are listed', () => eq(payload.attachments.length, 2));
t('payload: verdict is Forged', () => eq(payload.verdict.level, 'forged'));

/* ---------- full analysis: genuine ---------- */

const good = RP.analyze(sample('genuine'));

t('genuine: verdict is Authenticated', () => {
  eq(good.verdict.level, 'authenticated', 'findings were: ' + ids(good).join(', '));
});
t('genuine: zero critical/high/medium findings', () => {
  const c = good.verdict.counts;
  eq([c.critical, c.high, c.medium], [0, 0, 0], 'findings: ' + ids(good).join(', '));
});
t('genuine: risk score is 0', () => eq(good.verdict.score, 0));
t('genuine: alignment is reported as aligned', () => eq(good.alignment.dkim, 'aligned'));

/* ---------- full analysis: legitimate bulk ---------- */

const bulk = RP.analyze(sample('newsletter'));

t('bulk: third-party Return-Path is downgraded to info, not high', () => {
  eq(sev(bulk, 'envelope-mismatch'), 'info');
});
t('bulk: verdict is not alarming', () => {
  ok(bulk.verdict.level === 'authenticated' || bulk.verdict.level === 'unverified',
    'got ' + bulk.verdict.level + ' from ' + ids(bulk).join(', '));
});
t('bulk: unsubscribe link on the ESP domain is not flagged', () => {
  eq(bulk.findings.filter(f => f.tag === 'Links').length, 0, ids(bulk).join(', '));
});

/* ---------- robustness ---------- */

t('empty input is rejected cleanly', () => {
  eq(RP.analyze('').ok, false);
  eq(RP.analyze('   ').error, 'empty');
});

t('prose with no headers is rejected with guidance', () => {
  const r = RP.analyze('hey can you check if this email is real? thanks');
  eq(r.ok, false);
  eq(r.error, 'no-headers');
  ok(/Show original/.test(r.message), 'should tell the user where to find the source');
});

t('headers only, no body, does not throw', () => {
  const r = RP.analyze('From: a@b.com\nSubject: hi\nDate: Thu, 17 Sep 2026 06:12:40 -0400');
  eq(r.ok, true);
  eq(r.links.length, 0);
});

t('a malformed mess does not throw', () => {
  const junk = 'From: <<>>@@\nReceived: nonsense ;;; not a date\nContent-Type: multipart/mixed; boundary=\n\n--\n';
  const r = RP.analyze(junk);
  ok(r.ok === true || r.ok === false);
});

t('every sample analyses without throwing', () => {
  SAMPLES.forEach(s => {
    const r = RP.analyze(s.raw);
    ok(r.ok, s.id + ' failed to parse');
    ok(r.verdict && r.verdict.label, s.id + ' produced no verdict');
  });
});

t('every finding has a title, a why, and a severity', () => {
  SAMPLES.forEach(s => {
    RP.analyze(s.raw).findings.forEach(f => {
      ok(f.title && f.title.length > 5, s.id + '/' + f.id + ' missing title');
      ok(f.why && f.why.length > 30, s.id + '/' + f.id + ' missing explanation');
      ok(['critical', 'high', 'medium', 'low', 'info', 'good'].includes(f.severity),
        s.id + '/' + f.id + ' bad severity ' + f.severity);
    });
  });
});

/* ---------- false positives on legitimate mail ---------- */

t('regional brand domains are not lookalikes', () => {
  ['amazon.ca', 'paypal.co.uk', 'netflix.de', 'apple.fr', 'microsoft.com.au']
    .forEach(d => eq(RP.lookalike(d), null, d + ' should be treated as the brand'));
});

t('a brand name on an implausible TLD still fires', () => {
  const l = RP.lookalike('paypal.top');
  ok(l && l.brand === 'paypal.com', 'paypal.top should be flagged');
});

t('brand names embedded in ordinary words do not fire', () => {
  ['purchase.com', 'pineapple.com', 'canadagoose.com', 'chasing-cars.com', 'applesauce.org']
    .forEach(d => eq(RP.lookalike(d), null, d + ' should not be a lookalike'));
});

t('short brands do not generate nonsense near-misses', () => {
  ['ample.com', 'case.com', 'black.com', 'pple.com']
    .forEach(d => eq(RP.lookalike(d), null, d + ' is too far from a short brand'));
  // Kept deliberately: 6+ char brands still catch one-character typos.
  ok(RP.lookalike('amazn.com'), 'amazn.com should still be caught');
});

t('long-brand typos are still caught', () => {
  ok(RP.lookalike('micrsoft.com'), 'micrsoft.com');
  ok(RP.lookalike('paypa1.com'), 'paypa1.com');
  ok(RP.lookalike('paypal.account-verify.evil.top'), 'brand as a subdomain label');
});

t('a plain internationalised domain is not critical', () => {
  // xn--mller-kva.de is müller.de — a real German domain, single script.
  const r = RP.analyze([
    'From: "Firma" <post@xn--mller-kva.de>',
    'Subject: Rechnung',
    'Date: Thu, 17 Sep 2026 06:12:40 -0400',
    ''
  ].join('\n'));
  const f = r.findings.find(x => x.id.startsWith('punycode-'));
  ok(f, 'the IDN should still be reported');
  eq(f.severity, 'low', 'but not as an attack');
  ok(r.verdict.level !== 'forged', 'got ' + r.verdict.level);
});

t('accented Latin IDNs are not treated as homographs', () => {
  // cafe with an accent, and muller with an umlaut - both ordinary domains.
  ['xn--caf-dma.fr', 'xn--mller-kva.de'].forEach(host => {
    const d = RP.decodePunycodeHost(host);
    ok(d, host + ' should decode');
    ok(!/[\u0400-\u04FF\u0370-\u03FF]/.test(d), d + ' is Latin, not another alphabet');
  });
});

t('a homograph mixing scripts is critical', () => {
  const f = RP.analyze([
    'From: "Microsoft" <a@xn--microsft-secure-esm.com>',
    'Subject: hi',
    'Date: Thu, 17 Sep 2026 06:12:40 -0400',
    ''
  ].join('\n')).findings.find(x => x.id.startsWith('punycode-'));
  eq(f.severity, 'critical');
});

/* ---------- parser robustness ---------- */

t('a MIME preamble is not treated as a body part', () => {
  const r = RP.analyze([
    'From: a@b.com',
    'Subject: hi',
    'Date: Thu, 17 Sep 2026 06:12:40 -0400',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="X"',
    '',
    'This is a multi-part message in MIME format.',
    '--X',
    'Content-Type: text/plain; charset=UTF-8',
    '',
    'the actual body',
    '--X--'
  ].join('\n'));
  eq(r.parts.length, 1, 'preamble should not become a part');
  ok(r.parts[0].decoded.indexOf('the actual body') !== -1);
});

t('Received id fragments are not mistaken for IP addresses', () => {
  const h = RP.parseHeaders(
    'Received: from a.com (a.com. [203.0.113.9]) by mx.google.com with SMTPS ' +
    'id k7si2839201pfc.88.2026.09.17.03.12.43; Thu, 17 Sep 2026 03:12:44 -0700'
  );
  eq(RP.parseHops(h)[0].ip, '203.0.113.9');
});

t('an octet over 255 is not accepted as an IP', () => {
  const h = RP.parseHeaders('Received: from a.com ([999.1.1.1]) by b.com; Thu, 17 Sep 2026 03:12:44 -0700');
  eq(RP.parseHops(h)[0].ip, '');
});

t('prototype keys in the body do not leak', () => {
  const r = RP.analyze([
    'From: a@b.com', 'Subject: hi', 'Date: Thu, 17 Sep 2026 06:12:40 -0400',
    'Content-Type: text/html', '',
    '<p>&constructor; &toString; hello</p>'
  ].join('\n'));
  ok(r.ok);
  ok(r.parts[0].decoded.indexOf('constructor') !== -1, 'left as literal text');
});

/* ---------- renderer/engine link agreement ---------- */

t('engine and renderer agree on which anchors count', () => {
  // An anchor inside a comment, and one whose inner content is enormous.
  const huge = 'x'.repeat(9000);
  const html = '<!-- <a href="https://ignored.test">skip</a> -->' +
    '<p><a href="https://evil.test/login">https://www.paypal.com/signin</a></p>' +
    '<p><a href="https://second.test/a">second</a></p>';
  const parts = [{ type: 'text/html', decoded: html }];
  const links = RP.extractLinks(parts);
  eq(links.length, 2, 'the commented-out anchor must not count');
  eq(links[0].host, 'evil.test');
  eq(links[1].host, 'second.test');

  // The renderer tokenises with the SAME regex over the SAME stripped source,
  // so its token count must match the engine's link count exactly.
  let n = 0;
  RP.stripNonContent(html).replace(RP.anchorRegex(), () => { n++; return ''; });
  eq(n, links.length, 'token count must equal link count');
  void huge;
});

t('stripNonContent removes script and comment regions', () => {
  const out = RP.stripNonContent('<script>var a="<a href=x>y</a>";</script><p>keep</p><!-- gone -->');
  ok(out.indexOf('href') === -1, 'anchors inside <script> are gone');
  ok(out.indexOf('gone') === -1, 'comments are gone');
  ok(out.indexOf('keep') !== -1);
});

t('a pathological run of unclosed anchors completes quickly', () => {
  const evil = '<a href=x>'.repeat(20000);
  const started = Date.now();
  RP.extractLinks([{ type: 'text/html', decoded: evil }]);
  const ms = Date.now() - started;
  ok(ms < 3000, 'took ' + ms + 'ms — the anchor regex is backtracking');
});

t('analysis is deterministic', () => {
  const a = RP.analyze(sample('credential-phish'));
  const b = RP.analyze(sample('credential-phish'));
  eq(ids(a), ids(b));
  eq(a.verdict.score, b.verdict.score);
});

/* ---------- report ---------- */

console.log('');
failures.forEach(f => console.log('  FAIL  ' + f));
console.log('');
console.log(`  ${pass} passed, ${fail} failed`);
console.log('');
process.exit(fail ? 1 : 0);
