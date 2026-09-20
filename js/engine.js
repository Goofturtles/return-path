/* Return Path — email envelope forensics engine.
   Pure functions. No network, no DOM, no dependencies.
   Runs identically in the browser and in node (tests/engine.test.cjs). */

(function (root) {
  'use strict';

  /* ------------------------------------------------------------------ *
   * 1. Low-level decoding
   * ------------------------------------------------------------------ */

  function b64(str) {
    try {
      if (typeof atob === 'function') return atob(str.replace(/\s+/g, ''));
      return Buffer.from(str.replace(/\s+/g, ''), 'base64').toString('binary');
    } catch (e) {
      return '';
    }
  }

  // Interpret a binary string as UTF-8 where possible.
  function utf8(bin) {
    try {
      return decodeURIComponent(
        bin.split('').map(function (c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join('')
      );
    } catch (e) {
      return bin;
    }
  }

  // RFC 2047 encoded-words:  =?UTF-8?B?...?=   =?UTF-8?Q?...?=
  function decodeEncodedWords(s) {
    if (!s || s.indexOf('=?') === -1) return s;
    return s.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, function (m, charset, enc, text) {
      if (enc.toUpperCase() === 'B') return utf8(b64(text));
      var q = text.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, function (_, hex) {
        return String.fromCharCode(parseInt(hex, 16));
      });
      return utf8(q);
    });
  }

  function decodeQuotedPrintable(s) {
    return s
      .replace(/=(?:\r\n|\n|\r)/g, '')
      .replace(/=([0-9A-Fa-f]{2})/g, function (_, hex) {
        return String.fromCharCode(parseInt(hex, 16));
      });
  }

  /* ------------------------------------------------------------------ *
   * 2. RFC 5322 parsing
   * ------------------------------------------------------------------ */

  function splitMessage(raw) {
    var text = String(raw || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    // Strip a leading "From " mbox separator if present.
    text = text.replace(/^From \S+.*\n/, '');
    var idx = text.indexOf('\n\n');
    if (idx === -1) return { headerBlock: text, body: '' };
    return { headerBlock: text.slice(0, idx), body: text.slice(idx + 2) };
  }

  // Unfold continuation lines and split into ordered header records.
  function parseHeaders(headerBlock) {
    var lines = headerBlock.split('\n');
    var out = [];
    var cur = null;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (!line.length) continue;
      if (/^[ \t]/.test(line) && cur) {
        cur.value += ' ' + line.replace(/^[ \t]+/, '');
        cur.raw += '\n' + line;
        continue;
      }
      var m = line.match(/^([!-9;-~]+)[ \t]*:(.*)$/);
      if (!m) continue;
      cur = { name: m[1], key: m[1].toLowerCase(), value: m[2].replace(/^\s+/, ''), raw: line };
      out.push(cur);
    }
    return out;
  }

  function headerValue(headers, key) {
    for (var i = 0; i < headers.length; i++) if (headers[i].key === key) return headers[i].value;
    return null;
  }

  function headerRecord(headers, key) {
    for (var i = 0; i < headers.length; i++) if (headers[i].key === key) return headers[i];
    return null;
  }

  function headersAll(headers, key) {
    return headers.filter(function (h) { return h.key === key; });
  }

  /* ------------------------------------------------------------------ *
   * 3. Address parsing
   * ------------------------------------------------------------------ */

  // Take the LAST angle-addr. A display name may itself contain "<a@b.com>"
  // purely to fool a reader (or a naive parser) — the real mailbox is the
  // final <...> group on the line.
  function parseAddress(value) {
    if (!value) return null;
    var decoded = decodeEncodedWords(value);
    var display = '';
    var addr = '';

    var angles = decoded.match(/<([^<>]*)>/g);
    if (angles && angles.length) {
      var last = angles[angles.length - 1];
      addr = last.slice(1, -1).trim();
      display = decoded.slice(0, decoded.lastIndexOf(last)).trim();
    } else {
      addr = decoded.trim().split(/[,;]/)[0].trim();
    }

    display = display.replace(/^["']|["']$/g, '').replace(/^["']|["']$/g, '').trim();
    addr = addr.replace(/^mailto:/i, '').trim();

    var at = addr.lastIndexOf('@');
    var domain = at === -1 ? '' : addr.slice(at + 1).toLowerCase().replace(/[>\s.]+$/, '');
    var local = at === -1 ? addr : addr.slice(0, at);

    return {
      raw: value,
      display: display,
      address: addr,
      local: local,
      domain: domain,
      // Any address-looking text that appears *inside* the display name.
      displayAddresses: (display.slice(0, 2000).match(/[\w.+-]{1,64}@[\w.-]{1,255}\.[a-z]{2,}/gi) || [])
    };
  }

  /* ------------------------------------------------------------------ *
   * 4. Domain utilities
   * ------------------------------------------------------------------ */

  var MULTI_PART_TLDS = [
    'co.uk', 'ac.uk', 'gov.uk', 'org.uk', 'co.jp', 'co.nz', 'co.za', 'com.au',
    'net.au', 'org.au', 'com.br', 'com.mx', 'co.in', 'gc.ca', 'on.ca'
  ];

  function registrableDomain(host) {
    if (!host) return '';
    var parts = String(host).toLowerCase().replace(/\.$/, '').split('.');
    if (parts.length <= 2) return parts.join('.');
    var lastTwo = parts.slice(-2).join('.');
    if (MULTI_PART_TLDS.indexOf(lastTwo) !== -1) return parts.slice(-3).join('.');
    return lastTwo;
  }

  // RFC 3492 punycode decoder — turns xn--pypal-4ve into the real unicode label.
  function adaptBias(delta, numPoints, first) {
    delta = first ? Math.floor(delta / 700) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    var k = 0;
    while (delta > 455) { delta = Math.floor(delta / 35); k += 36; }
    return k + Math.floor(36 * delta / (delta + 38));
  }

  function punyDecodeLabel(input) {
    var output = [];
    var i = 0, n = 128, bias = 72;
    var basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (var j = 0; j < basic; j++) {
      if (input.charCodeAt(j) >= 128) return null;
      output.push(input.charCodeAt(j));
    }
    for (var index = basic > 0 ? basic + 1 : 0; index < input.length;) {
      var oldi = i, w = 1;
      for (var k = 36; ; k += 36) {
        if (index >= input.length) return null;
        var c = input.charCodeAt(index++);
        var digit;
        if (c >= 48 && c <= 57) digit = c - 22;
        else if (c >= 65 && c <= 90) digit = c - 65;
        else if (c >= 97 && c <= 122) digit = c - 97;
        else return null;
        i += digit * w;
        var t = k <= bias ? 1 : (k >= bias + 26 ? 26 : k - bias);
        if (digit < t) break;
        w *= (36 - t);
      }
      var out = output.length + 1;
      bias = adaptBias(i - oldi, out, oldi === 0);
      n += Math.floor(i / out);
      i %= out;
      output.splice(i, 0, n);
      i++;
    }
    try { return String.fromCodePoint.apply(String, output); } catch (e) { return null; }
  }

  function decodePunycodeHost(host) {
    if (!host || host.indexOf('xn--') === -1) return null;
    var labels = String(host).toLowerCase().split('.');
    var changed = false;
    var decoded = labels.map(function (l) {
      if (l.indexOf('xn--') !== 0) return l;
      var d = punyDecodeLabel(l.slice(4));
      if (d === null) return l;
      changed = true;
      return d;
    });
    return changed ? decoded.join('.') : null;
  }

  // Unicode characters that render like ASCII letters.
  var CONFUSABLES = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'һ': 'h',
    'ѕ': 's', 'к': 'k', 'м': 'm', 'т': 't', 'в': 'b',
    'ο': 'o', 'α': 'a', 'ε': 'e', 'ι': 'i', 'ρ': 'p',
    'ν': 'v', 'υ': 'u', 'ı': 'i', 'ɡ': 'g', '‐': '-',
    'ẞ': 's', 'ł': 'l', 'à': 'a', 'á': 'a', 'é': 'e',
    'í': 'i', 'ó': 'o', 'ú': 'u', 'ç': 'c', 'ñ': 'n'
  };

  // ASCII shapes that read like other ASCII shapes at a glance.
  var ASCII_SHAPES = { '0': 'o', '1': 'l', '5': 's', '3': 'e', '4': 'a', '@': 'a' };

  function hasNonAscii(s) { return /[^\x00-\x7F]/.test(String(s || '')); }

  function skeleton(s) {
    var out = '';
    var str = String(s || '').toLowerCase();
    for (var i = 0; i < str.length; i++) {
      var ch = str[i];
      if (CONFUSABLES[ch]) out += CONFUSABLES[ch];
      else if (ASCII_SHAPES[ch]) out += ASCII_SHAPES[ch];
      else out += ch;
    }
    return out.replace(/rn/g, 'm').replace(/vv/g, 'w');
  }

  function levenshtein(a, b) {
    a = String(a); b = String(b);
    if (a === b) return 0;
    var prev = [], i, j;
    for (j = 0; j <= b.length; j++) prev[j] = j;
    for (i = 1; i <= a.length; i++) {
      var cur = [i];
      for (j = 1; j <= b.length; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[b.length];
  }

  // Brands worth impersonating. Impersonation only matters for brands the
  // recipient already trusts, so this list is deliberately short.
  var BRANDS = [
    'paypal.com', 'microsoft.com', 'office365.com', 'outlook.com', 'google.com',
    'apple.com', 'icloud.com', 'amazon.com', 'netflix.com', 'dhl.com', 'fedex.com',
    'ups.com', 'usps.com', 'irs.gov', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
    'docusign.com', 'dropbox.com', 'linkedin.com', 'instagram.com', 'facebook.com',
    'coinbase.com', 'binance.com', 'steampowered.com', 'discord.com', 'github.com',
    'adobe.com', 'zoom.us', 'slack.com', 'shopify.com', 'stripe.com', 'canada.ca',
    'cra-arc.gc.ca', 'rbc.com', 'td.com', 'scotiabank.com'
  ];

  var BRAND_WORDS = Object.create(null);
  BRANDS.forEach(function (b) { BRAND_WORDS[b.split('.')[0]] = b; });

  // Second domains the brands genuinely own and send from. Without these,
  // amazonaws.com reads as a lookalike of amazon.com and the tool cries wolf
  // on half of all legitimate corporate mail.
  var BRAND_OWNED = [
    'amazonaws.com', 'awsstatic.com', 'amazonses.com', 'googleapis.com', 'googlemail.com',
    'googleusercontent.com', 'gstatic.com', 'google.ca', 'google.co.uk', 'youtube.com',
    'microsoftonline.com', 'microsoftstore.com', 'office.com', 'live.com', 'msn.com',
    'sharepointonline.com', 'icloud.com', 'apple.news', 'paypalobjects.com',
    'paypal-communication.com', 'paypal.ca', 'fbcdn.net', 'facebookmail.com',
    'licdn.com', 'linkedin-ei.com', 'netflix.net', 'nflxext.com', 'githubusercontent.com',
    'githubassets.com', 'github.io', 'discordapp.com', 'discord.gg', 'slack-edge.com',
    'adobelogin.com', 'adobe.io', 'zoomgov.com', 'stripe.network', 'shopifycdn.com',
    'dropboxusercontent.com', 'docusign.net', 'coinbase-mail.com', 'canada.ca'
  ];

  // TLDs a real company plausibly uses for a country storefront. amazon.ca is
  // Amazon; amazon.top is not. Without this the From check calls legitimate
  // regional mail "Forged", which is the worst error this tool can make.
  var SAFE_TLDS = [
    'com', 'net', 'org', 'ca', 'uk', 'co.uk', 'de', 'fr', 'es', 'it', 'nl', 'be',
    'ch', 'at', 'se', 'no', 'dk', 'fi', 'ie', 'pl', 'pt', 'cz', 'gr', 'au',
    'com.au', 'nz', 'co.nz', 'jp', 'co.jp', 'in', 'co.in', 'br', 'com.br', 'mx',
    'com.mx', 'za', 'co.za', 'sg', 'hk', 'kr', 'tw', 'eu', 'us', 'gov', 'gc.ca'
  ];

  function tldOf(reg) {
    var parts = String(reg).split('.');
    if (parts.length <= 1) return '';
    var lastTwo = parts.slice(-2).join('.');
    if (MULTI_PART_TLDS.indexOf(lastTwo) !== -1) return lastTwo;
    return parts[parts.length - 1];
  }

  function lookalike(domain) {
    if (!domain) return null;
    var reg = registrableDomain(domain);
    if (BRANDS.indexOf(reg) !== -1) return null; // it *is* the brand
    if (BRAND_OWNED.indexOf(reg) !== -1) return null; // brand's own secondary domain

    var skel = skeleton(reg);
    var skelName = skel.split('.')[0];

    for (var i = 0; i < BRANDS.length; i++) {
      var brand = BRANDS[i];
      var brandName = brand.split('.')[0];
      if (skel === skeleton(brand)) return { brand: brand, kind: 'identical-skeleton', distance: 0 };
      // Same second-level name on another TLD. paypal.ca is fine; paypal.top is not.
      if (skelName === brandName && reg !== brand) {
        if (SAFE_TLDS.indexOf(tldOf(reg)) !== -1) return null;
        return { brand: brand, kind: 'brand-name-wrong-domain', distance: 0 };
      }
      // Short brands generate nonsense near-misses (case/chase, ample/apple,
      // black/slack), so only names long enough for a typo to be meaningful.
      if (brandName.length >= 6) {
        var d = levenshtein(skelName, brandName);
        if (d > 0 && d <= (brandName.length >= 9 ? 2 : 1)) {
          return { brand: brand, kind: 'near-miss', distance: d };
        }
      }
    }

    // Brand name buried in a subdomain or hyphenated prefix of an unrelated domain.
    var full = skeleton(String(domain).toLowerCase());
    var keys = Object.keys(BRAND_WORDS);
    for (var k = 0; k < keys.length; k++) {
      var word = keys[k];
      if (word.length < 5) continue;
      // Bounded by a separator or the ends of the host. A bare substring test
      // reads "chase" out of purchase.com and "apple" out of pineapple.com.
      var bounded = new RegExp('(^|[^a-z0-9])' + word + '([^a-z0-9]|$)');
      if (bounded.test(full) && registrableDomain(BRAND_WORDS[word]) !== reg) {
        return { brand: BRAND_WORDS[word], kind: 'brand-in-subdomain', distance: 0 };
      }
    }
    return null;
  }

  /* ------------------------------------------------------------------ *
   * 5. Authentication results
   * ------------------------------------------------------------------ */

  function parseAuthResults(headers) {
    var res = {
      spf: { result: 'none', domain: '', source: null },
      dkim: { result: 'none', domain: '', source: null },
      dmarc: { result: 'none', domain: '', source: null },
      compauth: null,
      present: false
    };

    headersAll(headers, 'authentication-results').forEach(function (h) {
      res.present = true;
      var v = h.value;
      var spf = v.match(/\bspf\s*=\s*([a-z]+)/i);
      if (spf && res.spf.result === 'none') {
        res.spf.result = spf[1].toLowerCase();
        res.spf.source = h;
        var sd = v.match(/smtp\.(?:mailfrom|helo)\s*=\s*([^\s;]+)/i);
        if (sd) res.spf.domain = String(sd[1]).toLowerCase().replace(/^.*@/, '');
      }
      var dkim = v.match(/\bdkim\s*=\s*([a-z]+)/i);
      if (dkim && res.dkim.result === 'none') {
        res.dkim.result = dkim[1].toLowerCase();
        res.dkim.source = h;
        var dd = v.match(/header\.(?:d|i)\s*=\s*([^\s;]+)/i);
        if (dd) res.dkim.domain = String(dd[1]).toLowerCase().replace(/^@/, '');
      }
      var dmarc = v.match(/\bdmarc\s*=\s*([a-z]+)/i);
      if (dmarc && res.dmarc.result === 'none') {
        res.dmarc.result = dmarc[1].toLowerCase();
        res.dmarc.source = h;
        var md = v.match(/header\.from\s*=\s*([^\s;]+)/i);
        if (md) res.dmarc.domain = String(md[1]).toLowerCase();
      }
      var ca = v.match(/compauth\s*=\s*([a-z]+)/i);
      if (ca) res.compauth = ca[1].toLowerCase();
    });

    // Fall back to Received-SPF when Authentication-Results is absent.
    var rspf = headerRecord(headers, 'received-spf');
    if (rspf && res.spf.result === 'none') {
      var m = rspf.value.match(/^\s*([a-z]+)/i);
      if (m) { res.spf.result = m[1].toLowerCase(); res.spf.source = rspf; res.present = true; }
      var d = rspf.value.match(/domain of ([^\s)]+)/i);
      if (d) res.spf.domain = String(d[1]).toLowerCase().replace(/^.*@/, '');
    }

    // DKIM-Signature gives us d= even if no verifier reported a result.
    var sig = headerRecord(headers, 'dkim-signature');
    if (sig && !res.dkim.domain) {
      var sd2 = sig.value.match(/(?:^|;)\s*d\s*=\s*([^;\s]+)/i);
      if (sd2) res.dkim.domain = String(sd2[1]).toLowerCase();
    }
    res.dkimSignaturePresent = !!sig;
    return res;
  }

  /* ------------------------------------------------------------------ *
   * 6. Received chain
   * ------------------------------------------------------------------ */

  function parseHops(headers) {
    var recs = headersAll(headers, 'received');
    // Received headers are prepended, so the last one is the first hop.
    var hops = recs.slice().reverse().map(function (h, i) {
      var v = h.value;
      var from = (v.match(/\bfrom\s+([^\s;()]+)/i) || [])[1] || '';
      var by = (v.match(/\bby\s+([^\s;()]+)/i) || [])[1] || '';
      // Only a bracketed or parenthesised address. A bare dotted run matches
      // fragments of Received ids like "k7si28.88.2026.09.17.03.12.43".
      var ipm = v.match(/[[(]((?:\d{1,3}\.){3}\d{1,3})[\])]/);
      var ip = ipm && ipm[1].split('.').every(function (o) { return Number(o) <= 255; })
        ? ipm[1] : '';
      var dpart = v.split(';').pop();
      var date = null;
      if (dpart) {
        var t = Date.parse(dpart.trim());
        if (!isNaN(t)) date = new Date(t);
      }
      var withProto = (v.match(/\bwith\s+([A-Za-z0-9]+)/i) || [])[1] || '';
      return { index: i, from: from, by: by, ip: ip, date: date, with: withProto, raw: h.raw, header: h };
    });

    for (var i = 0; i < hops.length; i++) {
      hops[i].delta = (i > 0 && hops[i].date && hops[i - 1].date)
        ? (hops[i].date - hops[i - 1].date) / 1000
        : null;
    }
    return hops;
  }

  function isPrivateIp(ip) {
    if (!ip) return false;
    var p = ip.split('.').map(Number);
    if (p.length !== 4 || p.some(isNaN)) return false;
    return p[0] === 10 ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      p[0] === 127;
  }

  /* ------------------------------------------------------------------ *
   * 7. Body, links and attachments
   * ------------------------------------------------------------------ */

  function extractParts(body, headers) {
    var ctype = headerValue(headers, 'content-type') || '';
    var boundary = (ctype.match(/boundary\s*=\s*"?([^";\s]+)"?/i) || [])[1];
    var parts = [];

    if (boundary) {
      var chunks = body.split('--' + boundary);
      // chunks[0] is the preamble ("This is a multi-part message..."), which is
      // not a part. Treating it as one made it win the render as an empty
      // text/plain and hid the message panel on ordinary multipart mail.
      chunks.slice(1).forEach(function (chunk) {
        var t = chunk.replace(/^\n+/, '');
        if (!t || t.indexOf('--') === 0) return;
        var split = splitMessage(t);
        var ph = parseHeaders(split.headerBlock);
        parts.push({
          type: (headerValue(ph, 'content-type') || 'text/plain').split(';')[0].trim().toLowerCase(),
          encoding: (headerValue(ph, 'content-transfer-encoding') || '').trim().toLowerCase(),
          disposition: headerValue(ph, 'content-disposition') || '',
          contentType: headerValue(ph, 'content-type') || '',
          body: split.body
        });
      });
    }

    if (!parts.length) {
      parts.push({
        type: (ctype.split(';')[0] || 'text/plain').trim().toLowerCase(),
        encoding: (headerValue(headers, 'content-transfer-encoding') || '').trim().toLowerCase(),
        disposition: '',
        contentType: ctype,
        body: body
      });
    }

    parts.forEach(function (p) {
      var d = p.body;
      if (p.encoding === 'quoted-printable') d = decodeQuotedPrintable(d);
      else if (p.encoding === 'base64') d = utf8(b64(d));
      p.decoded = d;
    });
    return parts;
  }

  function filenameOf(part) {
    var m = (part.disposition + ' ' + part.contentType)
      .match(/(?:file)?name\s*=\s*"?([^";\r\n]+)"?/i);
    return m ? decodeEncodedWords(m[1].trim()) : '';
  }

  var DANGEROUS_EXT = [
    'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'msi', 'vbs', 'vbe', 'js', 'jse',
    'wsf', 'wsh', 'hta', 'lnk', 'ps1', 'jar', 'iso', 'img', 'reg', 'cpl', 'dll', 'msc'
  ];
  var MACRO_EXT = ['docm', 'xlsm', 'pptm', 'dotm', 'xlam', 'xls', 'doc', 'slk', 'xlsb'];
  var ARCHIVE_EXT = ['zip', 'rar', '7z', 'gz', 'tar', 'cab', 'ace'];

  function extOf(name) {
    var m = String(name || '').toLowerCase().match(/\.([a-z0-9]{1,5})$/);
    return m ? m[1] : '';
  }

  var SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'lnkd.in', 'trib.al'
  ];

  function parseUrl(href) {
    var m = String(href).match(/^([a-z][a-z0-9+.-]*):(\/\/)?([^\s]*)$/i);
    if (!m) return null;
    var scheme = m[1].toLowerCase();
    var rest = m[3] || '';
    var authority = rest.split(/[/?#]/)[0];
    var userinfo = '';
    if (authority.indexOf('@') !== -1) {
      userinfo = authority.slice(0, authority.lastIndexOf('@'));
      authority = authority.slice(authority.lastIndexOf('@') + 1);
    }
    var host = authority.split(':')[0].toLowerCase();
    return {
      href: href,
      scheme: scheme,
      host: host,
      userinfo: userinfo,
      path: rest.slice(rest.split(/[/?#]/)[0].length) || ''
    };
  }

  // Regions whose anchors are not part of the visible message. The renderer
  // must strip exactly the same regions, or its placeholders line up with the
  // wrong links and the annotated view reports a false destination.
  function stripNonContent(html) {
    return String(html)
      .replace(/<!--[\s\S]{0,20000}?-->/g, ' ')
      .replace(/<(script|style|head|title|noscript)\b[^>]{0,2000}>[\s\S]{0,200000}?<\/\1\s*>/gi, ' ');
  }

  // Bounded body so a pathological run of unclosed <a> cannot make the lazy
  // quantifier rescan to EOF from every match position and hang the tab.
  function anchorRegex() {
    return /<a\b[^>]{0,2000}?href\s*=\s*("([^"]{0,2000})"|'([^']{0,2000})'|([^\s">]{0,2000}))[^>]{0,2000}>([\s\S]{0,8000}?)<\/a\s*>/gi;
  }

  function extractLinks(parts) {
    var links = [];
    var seen = 0;

    parts.forEach(function (p, partIndex) {
      // inPart counts links within this part, so the renderer can line its
      // placeholders up with the right link even in a multi-part message.
      var inPart = 0;
      if (p.type === 'text/html') {
        var re = anchorRegex();
        var m;
        var src = stripNonContent(p.decoded);
        while ((m = re.exec(src)) !== null) {
          var href = (m[2] || m[3] || m[4] || '').trim();
          var text = m[5].replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
          links.push({ href: href, text: text, index: seen++, partIndex: partIndex, inPart: inPart++, source: 'anchor' });
        }
      } else if (p.type === 'text/plain') {
        var re2 = /\bhttps?:\/\/[^\s<>"')\]]+/gi;
        var m2;
        while ((m2 = re2.exec(p.decoded)) !== null) {
          links.push({ href: m2[0], text: m2[0], index: seen++, partIndex: partIndex, inPart: inPart++, source: 'plain' });
        }
      }
    });

    links.forEach(function (l) {
      var u = parseUrl(l.href);
      l.url = u;
      l.host = u ? u.host : '';
      l.registrable = u ? registrableDomain(u.host) : '';
      // Does the visible text claim to be a different destination?
      var claim = l.text.match(/(?:https?:\/\/)?((?:[\w-]+\.)+[a-z]{2,})/i);
      l.claimedHost = claim ? claim[1].toLowerCase() : '';
      l.claimedRegistrable = l.claimedHost ? registrableDomain(l.claimedHost) : '';
    });

    return links;
  }

  /* ------------------------------------------------------------------ *
   * 8. Findings
   * ------------------------------------------------------------------ */

  var WEIGHT = { critical: 45, high: 28, medium: 14, low: 6, info: 0, good: 0 };

  function Findings() {
    var list = [];
    return {
      add: function (f) { list.push(f); return f; },
      list: list
    };
  }

  function short(s, n) {
    s = String(s == null ? '' : s);
    n = n || 300;
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }

  /* ------------------------------------------------------------------ *
   * 9. Main analysis
   * ------------------------------------------------------------------ */

  function analyze(raw) {
    var input = String(raw || '');
    if (!input.trim()) {
      return { ok: false, error: 'empty', message: 'Nothing to analyse yet.' };
    }

    var split = splitMessage(input);
    var headers = parseHeaders(split.headerBlock);

    if (!headers.length || (!headerValue(headers, 'from') && !headerValue(headers, 'received') && !headerValue(headers, 'subject'))) {
      return {
        ok: false,
        error: 'no-headers',
        message: 'That does not look like raw message source. Paste everything from "Delivered-To:" or "Received:" down — in Gmail that is Show original, in Outlook it is View › Message source.'
      };
    }

    var F = Findings();
    var from = parseAddress(headerValue(headers, 'from'));
    var returnPath = parseAddress(headerValue(headers, 'return-path'));
    var replyTo = parseAddress(headerValue(headers, 'reply-to'));
    var sender = parseAddress(headerValue(headers, 'sender'));
    var auth = parseAuthResults(headers);
    var hops = parseHops(headers);
    var parts = extractParts(split.body, headers);
    var links = extractLinks(parts);

    var fromDomain = from ? registrableDomain(from.domain) : '';
    var rpDomain = returnPath ? registrableDomain(returnPath.domain) : '';
    var dkimDomain = auth.dkim.domain ? registrableDomain(auth.dkim.domain) : '';
    var spfDomain = auth.spf.domain ? registrableDomain(auth.spf.domain) : '';

    /* --- 9a. Authentication ---------------------------------------- */

    if (!auth.present) {
      F.add({
        id: 'auth-missing', severity: 'medium', tag: 'Authentication',
        title: 'No authentication results in this copy',
        why: 'Your mail provider normally stamps an Authentication-Results header recording whether SPF, DKIM and DMARC passed. It is missing here, which usually means the message was forwarded or saved before delivery. Everything below is still valid, but nobody has cryptographically checked the sender.',
        evidence: []
      });
    }

    if (auth.spf.result === 'fail' || auth.spf.result === 'softfail') {
      F.add({
        id: 'spf-fail', severity: auth.spf.result === 'fail' ? 'high' : 'medium', tag: 'Authentication',
        title: 'SPF ' + auth.spf.result + ' — the sending server was not authorised',
        why: 'SPF is a list, published by the domain owner, of servers allowed to send mail for that domain. This message came from a server that is not on the list. Legitimate mail almost never fails SPF outright.',
        evidence: auth.spf.source ? [{ label: auth.spf.source.name, text: short(auth.spf.source.value) }] : []
      });
    }

    if (auth.dkim.result === 'fail') {
      F.add({
        id: 'dkim-fail', severity: 'high', tag: 'Authentication',
        title: 'DKIM signature failed to verify',
        why: 'DKIM is a cryptographic signature over the message. A failure means the content or headers were altered after signing, or the signature was forged outright.',
        evidence: auth.dkim.source ? [{ label: auth.dkim.source.name, text: short(auth.dkim.source.value) }] : []
      });
    }

    if (auth.dmarc.result === 'fail') {
      F.add({
        id: 'dmarc-fail', severity: 'critical', tag: 'Authentication',
        title: 'DMARC fail — the domain owner disowns this message',
        why: 'DMARC is the domain owner’s own policy: it ties SPF and DKIM back to the address you actually see in the From line. A fail means the organisation named in the From header has effectively said "this did not come from us."',
        evidence: auth.dmarc.source ? [{ label: auth.dmarc.source.name, text: short(auth.dmarc.source.value) }] : []
      });
    }

    if (auth.dmarc.result === 'pass' && auth.spf.result === 'pass' && (auth.dkim.result === 'pass' || !auth.dkimSignaturePresent)) {
      F.add({
        id: 'auth-pass', severity: 'good', tag: 'Authentication',
        title: 'SPF, DKIM and DMARC all pass',
        why: 'The message genuinely originates from ' + (fromDomain || 'the From domain') + '. Note what this does *not* prove: that the domain is trustworthy, or that the account behind it has not been compromised. An attacker who owns a domain can pass every check.',
        evidence: auth.dmarc.source ? [{ label: auth.dmarc.source.name, text: short(auth.dmarc.source.value) }] : []
      });
    }

    /* --- 9b. Alignment --------------------------------------------- */

    var alignment = { spf: 'unknown', dkim: 'unknown' };

    // A mail provider that sends on a brand's behalf will always show its own
    // Return-Path. That is only interesting when nothing else vouches for the
    // sender — if DMARC passed, the mismatch is the system working as designed.
    var bulkSender = !!headerValue(headers, 'list-unsubscribe');
    var vouched = auth.dmarc.result === 'pass' ||
      (auth.dkim.result === 'pass' && dkimDomain && dkimDomain === fromDomain);

    if (fromDomain && rpDomain) {
      alignment.spf = fromDomain === rpDomain ? 'aligned' : 'misaligned';
      if (alignment.spf === 'misaligned') {
        F.add({
          id: 'envelope-mismatch',
          severity: vouched ? 'info' : 'high',
          tag: 'Alignment',
          title: vouched
            ? 'Sent through a third party, but signed by ' + fromDomain
            : 'The envelope sender does not match the From address',
          why: vouched
            ? 'Every email has two senders: the one your client displays (From) and the one the servers actually spoke to (Return-Path). They differ here because the mail went out through ' + rpDomain + ' on behalf of ' + fromDomain + ' — normal for newsletters and receipts. It is harmless in this case only because a valid signature from ' + fromDomain + ' ties the two together.'
            : 'Every email has two senders: the one your client displays (From) and the one the servers actually spoke to (Return-Path). Only the second one is checked by SPF. Here they are different domains and nothing else vouches for the sender — which is how a message can pass SPF while still appearing to come from someone else.',
          evidence: [
            { label: 'From', text: short(from.raw) },
            { label: 'Return-Path', text: short(returnPath.raw) }
          ]
        });
      }
    }

    if (fromDomain && dkimDomain) {
      alignment.dkim = fromDomain === dkimDomain ? 'aligned' : 'misaligned';
      if (alignment.dkim === 'misaligned' && auth.dkim.result === 'pass') {
        F.add({
          id: 'dkim-misaligned',
          severity: auth.dmarc.result === 'pass' ? 'info' : 'medium',
          tag: 'Alignment',
          title: 'DKIM passes, but for a different domain than the From address',
          why: 'The signature is valid — for ' + dkimDomain + ', not ' + fromDomain + '. A green "DKIM: pass" badge on its own therefore says nothing about whether ' + fromDomain + ' authorised this' +
            (auth.dmarc.result === 'pass'
              ? '. Here DMARC still passes, so SPF must be carrying the alignment instead.'
              : ', and nothing else closes the gap.'),
          evidence: [
            { label: 'From domain', text: fromDomain },
            { label: 'DKIM d=', text: dkimDomain }
          ]
        });
      }
    }

    /* --- 9c. Display-name and Reply-To tricks ---------------------- */

    if (from) {
      if (from.displayAddresses.length) {
        var fake = from.displayAddresses.filter(function (a) {
          return a.toLowerCase() !== String(from.address).toLowerCase();
        });
        if (fake.length) {
          F.add({
            id: 'display-name-address', severity: 'critical', tag: 'Impersonation',
            title: 'The display name is itself a fake email address',
            why: 'Mobile clients show the display name and hide the real address entirely. Putting "' + short(fake[0], 80) + '" in the name field means the phone shows that address while the mail actually comes from ' + (from.address || 'somewhere else') + '. Nothing in the email is technically lying — the interface is.',
            evidence: [
              { label: 'Display name', text: short(from.display) },
              { label: 'Real mailbox', text: short(from.address) }
            ]
          });
        }
      }

      var nameBrand = null;
      var dn = skeleton(from.display);
      Object.keys(BRAND_WORDS).forEach(function (word) {
        if (nameBrand || word.length < 4) return;
        if (new RegExp('\\b' + word + '\\b').test(dn)) nameBrand = BRAND_WORDS[word];
      });
      if (nameBrand && fromDomain && registrableDomain(nameBrand) !== fromDomain) {
        F.add({
          id: 'display-name-brand', severity: 'high', tag: 'Impersonation',
          title: 'Display name claims a brand the domain does not belong to',
          why: 'The name field says ' + JSON.stringify(short(from.display, 60)) + ', but the message comes from ' + fromDomain + '. The display name is free text. Anyone can type anything there; it is never verified by anything.',
          evidence: [
            { label: 'Display name', text: short(from.display) },
            { label: 'Actual domain', text: fromDomain }
          ]
        });
      }
    }

    var replyDomain = replyTo ? registrableDomain(replyTo.domain) : '';
    if (replyDomain && fromDomain && replyDomain !== fromDomain) {
      // A reply address on the same infrastructure that signed or bounced the
      // message is routine (support desks, ESPs). One on a third domain is the
      // whole BEC mechanic. Shared infrastructure only reassures if something
      // vouches for that infrastructure — otherwise the attacker owns both ends.
      var sameInfra = vouched && (replyDomain === dkimDomain || replyDomain === rpDomain);
      F.add({
        id: 'reply-to-divergence',
        severity: sameInfra ? 'low' : (bulkSender ? 'medium' : 'high'),
        tag: 'Impersonation',
        title: 'Your reply would go to a different domain than the sender',
        why: 'Hitting Reply sends to ' + replyTo.address + ', not back to ' + (from ? from.address : 'the sender') + '. ' +
          (sameInfra
            ? 'Here the reply address sits on the same infrastructure that handled the message, which is ordinary for support and no-reply addresses.'
            : 'The reply domain is unrelated to both the sender and the servers that carried this message. That is the mechanism behind almost every invoice-redirect and gift-card scam: the first message only has to survive long enough for you to start a thread with the attacker.'),
        evidence: [
          { label: 'From', text: short(from ? from.raw : '') },
          { label: 'Reply-To', text: short(replyTo.raw) }
        ]
      });
    }

    /* --- 9d. Lookalike domains ------------------------------------- */

    var checkedDomains = Object.create(null);
    function checkDomain(domain, where, severity) {
      // Key on the domain alone: when From and Return-Path share a domain there
      // is one fact to report, not two.
      if (!domain || checkedDomains[domain]) return;
      checkedDomains[domain] = true;

      var puny = decodePunycodeHost(domain);
      if (puny) {
        // Plenty of legitimate domains are internationalised. What makes one
        // an attack is imitating a known brand, or mixing scripts inside a
        // single label so it reads as Latin but is not.
        // Latin letters with diacritics (muller.de, cafe.fr) are ordinary.
        // The homograph trick is a NON-Latin alphabet wearing Latin clothes:
        // a Cyrillic a or a Greek omicron sitting inside an ASCII word.
        var OTHER_SCRIPT = /[\u0370-\u03FF\u0400-\u04FF\u0500-\u052F\u0530-\u058F\u10A0-\u10FF\u2C00-\u2C5F]/;
        var mixedScript = puny.split('.').some(function (label) {
          return /[a-z]/.test(label) && OTHER_SCRIPT.test(label);
        });
        var deceptive = mixedScript || !!lookalike(puny);
        F.add({
          id: 'punycode-' + where,
          severity: deceptive ? 'critical' : 'low',
          tag: 'Lookalike',
          title: deceptive
            ? 'Homograph domain in the ' + where
            : 'Internationalised domain in the ' + where,
          why: deceptive
            ? 'The domain is registered as ' + domain + ' but your browser and mail client will render it as "' + puny + '". Those are different domains that look identical on screen' + (mixedScript ? ', because the label mixes alphabets — some of those letters are not the Latin characters they appear to be' : '') + '. Reading carefully cannot defeat this; the characters really are different.'
            : 'The domain is registered as ' + domain + ' and displays as "' + puny + '". That is ordinary internationalised naming rather than an attack by itself — but it is worth seeing the real registration, because this is also the mechanism a homograph attack uses.',
          evidence: [
            { label: 'Registered as', text: domain },
            { label: 'Displays as', text: puny }
          ]
        });
        domain = puny;
      }

      // Only worth its own finding when the header carried raw unicode. If we
      // got here by decoding punycode, that finding already said this.
      if (!puny && hasNonAscii(domain)) {
        F.add({
          id: 'nonascii-' + where, severity: 'high', tag: 'Lookalike',
          title: 'Non-Latin characters inside the ' + where + ' domain',
          why: 'At least one character in "' + domain + '" is not the ASCII letter it appears to be — for example a Cyrillic а in place of an a. Visually identical, technically a completely different domain owned by someone else.',
          evidence: [{ label: 'Domain', text: domain }, { label: 'Reads as', text: skeleton(domain) }]
        });
      }

      var look = lookalike(domain);
      if (look) {
        var explain = {
          'identical-skeleton': 'It is character-for-character confusable with ' + look.brand + '.',
          'brand-name-wrong-domain': 'It uses the name "' + look.brand.split('.')[0] + '" on a domain that is not ' + look.brand + '. The real company only sends from ' + look.brand + '.',
          'near-miss': 'It is ' + look.distance + ' character' + (look.distance === 1 ? '' : 's') + ' away from ' + look.brand + ' — a typo you would not notice unless you were looking for it.',
          'brand-in-subdomain': 'The brand name appears as a label inside a domain owned by someone else. Only the part immediately before the TLD identifies the owner; everything to the left of it is chosen freely by whoever registered it.'
        }[look.kind];
        F.add({
          id: 'lookalike-' + where + '-' + registrableDomain(domain), severity: severity || 'high', tag: 'Lookalike',
          title: 'Lookalike domain in the ' + where + ': ' + registrableDomain(domain),
          why: explain,
          evidence: [
            { label: 'Seen', text: domain },
            { label: 'Impersonating', text: look.brand }
          ]
        });
      }
    }

    if (from) checkDomain(from.domain, 'From address', 'critical');
    if (returnPath) checkDomain(returnPath.domain, 'Return-Path');
    if (replyTo) checkDomain(replyTo.domain, 'Reply-To');

    /* --- 9e. Links -------------------------------------------------- */

    var linkHosts = Object.create(null);
    links.forEach(function (l) {
      l.flags = [];
      if (!l.url) return;

      if (l.registrable) linkHosts[l.registrable] = (linkHosts[l.registrable] || 0) + 1;

      if (l.url.scheme === 'javascript' || l.url.scheme === 'data') {
        l.flags.push('scheme');
        F.add({
          id: 'link-scheme-' + l.index, severity: 'critical', tag: 'Links',
          title: 'Link uses a ' + l.url.scheme + ': URL',
          why: 'This is not a web address. A ' + l.url.scheme + ': link runs content the message carries with it, rather than taking you to a site. There is no legitimate reason for one of these in an email.',
          evidence: [{ label: 'href', text: short(l.href, 160) }]
        });
      }

      if (l.url.userinfo) {
        l.flags.push('userinfo');
        F.add({
          id: 'link-userinfo-' + l.index, severity: 'critical', tag: 'Links',
          title: 'Link hides its real destination behind an @',
          why: 'Everything before the @ in a URL is a username, not a destination. This link reads as "' + short(l.url.userinfo, 40) + '" but goes to ' + l.host + '. The part you read is discarded by the browser.',
          evidence: [{ label: 'href', text: short(l.href, 160) }, { label: 'Actually goes to', text: l.host }]
        });
      }

      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(l.host)) {
        l.flags.push('ip');
        F.add({
          id: 'link-ip-' + l.index, severity: 'high', tag: 'Links',
          title: 'Link points at a bare IP address',
          why: 'Real organisations send you to a named domain they own. A raw IP address means there is no domain registration behind the destination — and nothing to check.',
          evidence: [{ label: 'href', text: short(l.href, 160) }]
        });
      }

      if (SHORTENERS.indexOf(l.registrable) !== -1) {
        l.flags.push('shortener');
        F.add({
          id: 'link-short-' + l.index, severity: 'medium', tag: 'Links',
          title: 'Link is hidden behind a URL shortener',
          why: 'A shortener means the destination cannot be inspected before you click. That is convenient in a tweet and a red flag in a message asking you to log in.',
          evidence: [{ label: 'href', text: short(l.href, 160) }]
        });
      }

      var puny = decodePunycodeHost(l.host);
      if (puny || hasNonAscii(l.host)) {
        l.flags.push('punycode');
        l.punyDisplay = puny || l.host;
        F.add({
          id: 'link-puny-' + l.index, severity: 'critical', tag: 'Links',
          title: 'Link domain is a homograph',
          why: 'The link is registered as ' + l.host + ' and will be displayed as "' + (puny || l.host) + '". Two different domains, one appearance.',
          evidence: [{ label: 'Registered', text: l.host }, { label: 'Displays as', text: puny || l.host }]
        });
      }

      // Visible text claims one destination, href goes elsewhere.
      if (l.claimedRegistrable && l.registrable && l.claimedRegistrable !== l.registrable) {
        l.flags.push('text-mismatch');
        F.add({
          id: 'link-mismatch-' + l.index, severity: 'critical', tag: 'Links',
          title: 'Link text and link destination disagree',
          why: 'The message shows you "' + short(l.text, 60) + '" and sends you to ' + l.registrable + '. The text of a link is decoration; only the href is real, and only a hover (or this tool) reveals it.',
          evidence: [
            { label: 'You see', text: short(l.text, 120) },
            { label: 'You get', text: short(l.href, 160) }
          ]
        });
      }

      var lk = lookalike(l.host);
      if (lk && !l.flags.length) {
        l.flags.push('lookalike');
        F.add({
          id: 'link-lookalike-' + l.index, severity: 'high', tag: 'Links',
          title: 'Link goes to a lookalike of ' + lk.brand,
          why: 'The destination ' + l.registrable + ' is designed to be mistaken for ' + lk.brand + '.',
          evidence: [{ label: 'href', text: short(l.href, 160) }]
        });
      }

      // Credential-harvest shaped paths on a domain unrelated to the sender.
      if (/\b(login|signin|verify|secure|account|password|auth|update|confirm|unlock|billing)\b/i.test(l.url.path) &&
        fromDomain && l.registrable && l.registrable !== fromDomain && !l.flags.length) {
        l.flags.push('credential-path');
      }
    });

    /* --- 9f. Received chain ---------------------------------------- */

    hops.forEach(function (h) {
      if (h.delta !== null && h.delta < -60) {
        F.add({
          id: 'hop-time-' + h.index, severity: 'medium', tag: 'Routing',
          title: 'A relay in the chain reports a time before the hop that preceded it',
          why: 'Received headers are added in order by each server that touches the message. A timestamp that runs backwards means one of them is lying, most likely a hop invented to make the path look plausible.',
          evidence: [{ label: 'Received', text: short(h.raw, 200) }]
        });
      }
      if (isPrivateIp(h.ip) && h.index === 0 && hops.length > 1) {
        F.add({
          id: 'hop-private', severity: 'low', tag: 'Routing',
          title: 'First hop originates from a private network address',
          why: 'The message entered the public internet from inside a private network (' + h.ip + '). Common for internal mail and for scripts running on a compromised host or home machine.',
          evidence: [{ label: 'Received', text: short(h.raw, 200) }]
        });
      }
    });

    if (hops.length === 0) {
      F.add({
        id: 'no-hops', severity: 'medium', tag: 'Routing',
        title: 'No Received headers at all',
        why: 'Every server that handles a message adds one. A message with none has either been stripped down before you got it, or was never actually delivered through the internet.',
        evidence: []
      });
    }

    /* --- 9g. Attachments -------------------------------------------- */

    var attachments = [];
    parts.forEach(function (p) {
      var name = filenameOf(p);
      if (!name && !/attachment/i.test(p.disposition)) return;
      var ext = extOf(name);
      var a = { name: name || '(unnamed)', type: p.type, ext: ext, risk: 'low' };
      attachments.push(a);

      var doubleExt = /\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|csv)\.[a-z0-9]{1,5}$/i.test(name);
      if (doubleExt) {
        a.risk = 'critical';
        F.add({
          id: 'att-double-' + name, severity: 'critical', tag: 'Attachment',
          title: 'Attachment uses a double extension: ' + name,
          why: 'Windows hides known file extensions by default, so "' + name + '" appears in the file list as "' + name.replace(/\.[a-z0-9]{1,5}$/i, '') + '". The file that actually runs is the last extension, not the one you read.',
          evidence: [{ label: 'Filename', text: name }, { label: 'Real type', text: '.' + ext }]
        });
      } else if (DANGEROUS_EXT.indexOf(ext) !== -1) {
        a.risk = 'critical';
        F.add({
          id: 'att-exec-' + name, severity: 'critical', tag: 'Attachment',
          title: 'Executable attachment: ' + name,
          why: 'A .' + ext + ' file runs code the moment it is opened. No legitimate invoice, receipt or delivery notice has ever needed one.',
          evidence: [{ label: 'Filename', text: name }]
        });
      } else if (MACRO_EXT.indexOf(ext) !== -1) {
        a.risk = 'high';
        F.add({
          id: 'att-macro-' + name, severity: 'high', tag: 'Attachment',
          title: 'Macro-capable document: ' + name,
          why: 'The .' + ext + ' format can carry executable macros. If opening it produces a yellow "Enable Content" bar, that bar is the attack.',
          evidence: [{ label: 'Filename', text: name }]
        });
      } else if (ARCHIVE_EXT.indexOf(ext) !== -1) {
        a.risk = 'medium';
        F.add({
          id: 'att-archive-' + name, severity: 'medium', tag: 'Attachment',
          title: 'Archive attachment: ' + name,
          why: 'Archives are used to smuggle file types that mail filters would otherwise strip, and password-protected ones cannot be scanned at all.',
          evidence: [{ label: 'Filename', text: name }]
        });
      }
    });

    /* --- 9h. Header consistency ------------------------------------- */

    var msgId = headerValue(headers, 'message-id');
    if (msgId && fromDomain) {
      var midDomain = registrableDomain((msgId.match(/@([^>\s]+)/) || [])[1] || '');
      if (midDomain && midDomain !== fromDomain && midDomain !== rpDomain && midDomain !== dkimDomain) {
        F.add({
          id: 'msgid-mismatch', severity: 'low', tag: 'Routing',
          title: 'Message-ID was generated by an unrelated domain',
          why: 'The unique ID stamped on this message was issued by ' + midDomain + ', not ' + fromDomain + '. Weak on its own — mailing lists and relays do it too — but it corroborates the rest.',
          evidence: [{ label: 'Message-ID', text: short(msgId) }]
        });
      }
    }

    if (!headerValue(headers, 'date')) {
      F.add({
        id: 'no-date', severity: 'low', tag: 'Routing',
        title: 'No Date header',
        why: 'Required by the standard and added automatically by every real mail client. Missing ones point at a script composing the message directly.',
        evidence: []
      });
    }

    /* --- 9i. Urgency, in plain sight -------------------------------- */

    var subject = decodeEncodedWords(headerValue(headers, 'subject') || '');
    var textBody = parts.map(function (p) {
      return p.type === 'text/html' ? p.decoded.replace(/<[^>]+>/g, ' ') : p.decoded;
    }).join(' ');
    var corpus = (subject + ' ' + textBody).toLowerCase();

    var PRESSURE = [
      { re: /\b(within|in)\s+\d+\s*(hours?|minutes?|days?)\b/, label: 'a countdown' },
      { re: /\b(immediately|urgent(ly)?|right away|as soon as possible)\b/, label: 'urgency' },
      { re: /\b(suspend|suspended|terminat|deactivat|clos(e|ed|ing) your account|locked)\b/, label: 'threatened loss of access' },
      { re: /\b(verify|confirm|re-?enter|update) your (account|identity|password|details|information|payment)\b/, label: 'a credential request' },
      { re: /\b(do not (tell|share|discuss)|keep this (confidential|between)|discreet)\b/, label: 'a secrecy instruction' },
      { re: /\b(gift cards?|wire transfer|bitcoin|crypto|western union|zelle)\b/, label: 'an unrecoverable payment rail' },
      { re: /\b(unusual|suspicious) (sign-?in|activity|login)\b/, label: 'a manufactured security scare' }
    ];
    var pressure = PRESSURE.filter(function (p) { return p.re.test(corpus); }).map(function (p) { return p.label; });

    if (pressure.length >= 2) {
      F.add({
        id: 'pressure', severity: 'medium', tag: 'Pretext',
        title: 'The message combines ' + pressure.length + ' pressure tactics',
        why: 'Present here: ' + pressure.join(', ') + '. These are social-engineering levers, not proof of forgery — real security alerts use some of the same words. They matter because they explain what the message wants you to do before you think.',
        evidence: [{ label: 'Subject', text: short(subject) }]
      });
    }

    /* --- 9j. Verdict ------------------------------------------------- */

    var score = 0;
    F.list.forEach(function (f) { score += WEIGHT[f.severity] || 0; });
    score = Math.min(100, score);

    var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, good: 0 };
    F.list.forEach(function (f) { counts[f.severity]++; });

    var verdict;
    if (counts.critical > 0) {
      verdict = {
        level: 'forged',
        label: 'Forged',
        summary: 'At least one part of this message is provably impersonating someone else.',
        action: 'Do not click anything, reply, or open attachments. If it claims to be from a company you use, go to their site by typing the address yourself and check your account there. Then report the message to your mail provider as phishing.'
      };
    } else if (counts.high > 0) {
      verdict = {
        level: 'suspicious',
        label: 'Suspicious',
        summary: 'Nothing here is conclusive on its own, but the envelope does not hold together the way genuine mail does.',
        action: 'Verify through a channel you choose yourself — a phone number from the organisation’s website, or a direct message to the person on a system you already trust. Never the number, link or reply address in this message.'
      };
    } else if (counts.medium > 0) {
      verdict = {
        level: 'unverified',
        label: 'Unverified',
        summary: 'No impersonation detected, but not enough authentication to vouch for the sender either.',
        action: 'Treat it as you would an unsigned letter. Being unremarkable is not the same as being verified — if it asks you for money, credentials or urgency, confirm it another way first.'
      };
    } else if (auth.dmarc.result === 'pass') {
      verdict = {
        level: 'authenticated',
        label: 'Authenticated',
        summary: 'The envelope checks out: this really was sent by ' + fromDomain + '.',
        action: 'That is a statement about the domain, not about the request. A real account that has been broken into sends perfectly authenticated mail — so judge what it is asking you to do on its own merits.'
      };
    } else {
      verdict = {
        level: 'unverified',
        label: 'Unverified',
        summary: 'Nothing suspicious found, but nothing proves the sender either — the authentication results were absent or incomplete.',
        action: 'This often means the message was forwarded, which strips the original verification. Ask the sender to send it to you directly if it matters.'
      };
    }
    verdict.score = score;
    verdict.counts = counts;

    var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4, good: 5 };
    var findings = F.list.slice().sort(function (a, b) { return order[a.severity] - order[b.severity]; });

    return {
      ok: true,
      raw: input,
      headers: headers,
      subject: subject,
      date: headerValue(headers, 'date'),
      to: parseAddress(headerValue(headers, 'to')),
      from: from,
      sender: sender,
      returnPath: returnPath,
      replyTo: replyTo,
      auth: auth,
      alignment: alignment,
      hops: hops,
      parts: parts,
      links: links,
      linkHosts: linkHosts,
      attachments: attachments,
      pressure: pressure,
      findings: findings,
      verdict: verdict,
      domains: { from: fromDomain, returnPath: rpDomain, dkim: dkimDomain, spf: spfDomain }
    };
  }

  var API = {
    analyze: analyze,
    parseAddress: parseAddress,
    parseHeaders: parseHeaders,
    splitMessage: splitMessage,
    registrableDomain: registrableDomain,
    decodePunycodeHost: decodePunycodeHost,
    punyDecodeLabel: punyDecodeLabel,
    lookalike: lookalike,
    skeleton: skeleton,
    decodeEncodedWords: decodeEncodedWords,
    decodeQuotedPrintable: decodeQuotedPrintable,
    parseUrl: parseUrl,
    extractLinks: extractLinks,
    extractParts: extractParts,
    parseAuthResults: parseAuthResults,
    stripNonContent: stripNonContent,
    anchorRegex: anchorRegex,
    parseHops: parseHops,
    levenshtein: levenshtein,
    BRANDS: BRANDS
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = API;
  root.ReturnPath = API;
})(typeof globalThis !== 'undefined' ? globalThis : this);
