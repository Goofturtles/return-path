/* Return Path — view layer.
   Deliberate constraint: the analysed message is untrusted input, so nothing
   derived from it is ever assigned through innerHTML. Every value reaches the
   page as a text node. The email's own HTML is never rendered — the "annotated"
   view is a reconstruction built from text plus link elements we create. */

(function () {
  'use strict';

  var RP = window.ReturnPath;
  var SAMPLES = window.ReturnPathSamples.SAMPLES;

  var $ = function (id) { return document.getElementById(id); };

  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'class') n.className = attrs[k];
        else if (k === 'text') n.textContent = attrs[k];
        else if (attrs[k] !== null && attrs[k] !== undefined && attrs[k] !== false) {
          n.setAttribute(k, attrs[k]);
        }
      });
    }
    (kids || []).forEach(function (c) {
      if (c === null || c === undefined || c === false) return;
      n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return n;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  /* ------------------------------------------------------------ input */

  var input = $('input');
  var drop = $('drop');
  var errorBox = $('error');

  SAMPLES.forEach(function (s) {
    var chip = el('button', {
      'class': 'chip', type: 'button', 'aria-pressed': 'false',
      title: s.blurb + ' — ' + s.teaches, 'data-id': s.id, text: s.name
    });
    chip.addEventListener('click', function () {
      input.value = s.raw;
      Array.prototype.forEach.call(document.querySelectorAll('.chip'), function (c) {
        c.setAttribute('aria-pressed', c === chip ? 'true' : 'false');
      });
      run();
    });
    $('sampleRow').appendChild(chip);
  });

  $('run').addEventListener('click', run);
  $('clear').addEventListener('click', function () {
    input.value = '';
    $('results').hidden = true;
    errorBox.hidden = true;
    $('winStatus').removeAttribute('data-s');
    $('winStatus').textContent = 'idle';
    if (location.hash) history.replaceState(null, '', location.pathname + location.search);
    Array.prototype.forEach.call(document.querySelectorAll('.chip'), function (c) {
      c.setAttribute('aria-pressed', 'false');
    });
    input.focus();
  });

  $('pick').addEventListener('click', function () { $('file').click(); });
  $('file').addEventListener('change', function (e) {
    if (e.target.files && e.target.files[0]) readFile(e.target.files[0]);
  });

  // Tabs: "Paste source" focuses the box, "Upload .eml" opens the picker.
  // The upload tab is an action, so it hands selection straight back.
  var tabs = document.querySelectorAll('.tab');
  function selectTab(which) {
    Array.prototype.forEach.call(tabs, function (t) {
      var on = t.getAttribute('data-mode') === which;
      t.classList.toggle('is-on', on);
      t.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
  }
  Array.prototype.forEach.call(tabs, function (t) {
    t.addEventListener('click', function () {
      var mode = t.getAttribute('data-mode');
      if (mode === 'file') {
        selectTab('file');
        $('file').click();
        // Nothing is chosen yet; the paste view stays usable underneath.
        setTimeout(function () { selectTab('paste'); }, 400);
      } else {
        selectTab('paste');
        input.focus();
      }
    });
  });

  ['dragenter', 'dragover'].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('over'); });
  });
  ['dragleave', 'drop'].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('over'); });
  });
  drop.addEventListener('drop', function (e) {
    var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) readFile(f);
  });

  function readFile(f) {
    if (/\.msg$/i.test(f.name)) {
      showError('That is an Outlook .msg file — a binary format this page cannot read. ' +
        'Open the message in Outlook and use File › Properties › Internet headers, ' +
        'or forward it to yourself and save the result as .eml.');
      return;
    }
    var r = new FileReader();
    r.onload = function () { input.value = String(r.result || ''); run(); };
    r.onerror = function () { showError('That file could not be read.'); };
    r.readAsText(f);
  }

  function showError(msg) {
    clear(errorBox);
    errorBox.appendChild(document.createTextNode(msg));
    errorBox.hidden = false;
    $('results').hidden = true;
  }

  /* ------------------------------------------------------------ run */

  function run() {
    var result;
    try {
      result = RP.analyze(input.value);
    } catch (e) {
      showError('Something in that message broke the parser: ' + e.message +
        ' — which is a bug worth knowing about, not a verdict on the email.');
      return;
    }
    if (!result.ok) { showError(result.message); return; }

    errorBox.hidden = true;
    render(result);
    $('results').hidden = false;
    var calm = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    $('results').scrollIntoView({ behavior: calm ? 'auto' : 'smooth', block: 'start' });
    $('results').focus({ preventScroll: true });
  }

  /* ------------------------------------------------------------ render */

  function render(r) {
    renderVerdict(r);
    renderEnvelope(r);
    renderAuth(r);
    renderFindings(r);
    renderMessage(r);
    renderLinks(r);
    renderHops(r);
    renderRaw(r);
  }

  function renderVerdict(r) {
    var v = r.verdict;
    $('verdict').setAttribute('data-level', v.level);

    var status = $('winStatus');
    status.setAttribute('data-s', v.level);
    status.textContent = v.label;

    $('verdictLabel').textContent = v.label;
    $('verdictSummary').textContent = v.summary;
    $('verdictAction').textContent = v.action || '';

    var tally = $('verdictTally');
    clear(tally);
    [['critical', 'critical', 'critical'],
     ['high', 'high', 'high'],
     ['medium', 'medium', 'medium'],
     ['good', 'check passed', 'checks passed']]
      .forEach(function (row) {
        var n = v.counts[row[0]];
        if (!n) return;
        tally.appendChild(el('span', { 'class': 'tally', 'data-s': row[0] }, [
          el('b', { text: String(n) }), ' ' + (n === 1 ? row[1] : row[2])
        ]));
      });

    var meta = $('verdictSubject');
    clear(meta);
    function row(k, val) {
      if (!val) return;
      meta.appendChild(el('b', { text: k }));
      meta.appendChild(el('span', { text: val }));
    }
    row('Subject', r.subject || '(none)');
    row('From', r.from ? (r.from.display ? r.from.display + ' <' + r.from.address + '>' : r.from.address) : '(none)');
    row('Date', r.date || '');

    var counted = r.headers.length + ' headers · ' + r.hops.length + ' hops · ' +
      r.links.length + ' links · ' + r.attachments.length + ' attachments';
    $('reportMeta').textContent = counted + '  —  analysed locally, nothing sent';
  }

  function renderEnvelope(r) {
    var box = $('envelope');
    clear(box);

    function addr(a, bad) {
      if (!a || !a.address) return el('span', { 'class': 'env-none', text: 'not present' });
      var wrap = el('span', {});
      if (a.display) wrap.appendChild(el('span', { 'class': 'muted', text: a.display + ' ' }));
      var at = a.address.lastIndexOf('@');
      if (at === -1) { wrap.appendChild(document.createTextNode(a.address)); return wrap; }
      wrap.appendChild(document.createTextNode(a.address.slice(0, at + 1)));
      wrap.appendChild(el('span', { 'class': 'dom' + (bad ? ' bad' : ''), text: a.address.slice(at + 1) }));
      return wrap;
    }

    function row(label, sub, valueNode, verdict, vText) {
      box.appendChild(el('div', { 'class': 'env-row' }, [
        el('div', { 'class': 'env-label' }, [el('b', { text: label }), sub]),
        el('div', { 'class': 'env-value' }, [valueNode]),
        verdict ? el('span', { 'class': 'env-verdict', 'data-v': verdict, text: vText }) : null
      ]));
    }

    var forged = r.findings.some(function (f) {
      return f.severity === 'critical' && (f.tag === 'Impersonation' || f.tag === 'Lookalike');
    });
    // Only paint a domain red when the verdict actually indicts it — a bulk
    // sender's Return-Path is a different domain and perfectly fine.
    var alarming = r.verdict.level === 'forged' || r.verdict.level === 'suspicious';

    row('From:', 'what you are shown', addr(r.from, forged),
      forged ? 'forged' : null, forged ? 'impersonation' : '');

    row('Return-Path:', 'what the servers saw',
      addr(r.returnPath, alarming && r.alignment.spf === 'misaligned'),
      r.alignment.spf === 'unknown' ? null : r.alignment.spf,
      r.alignment.spf === 'aligned' ? 'same domain' : 'different domain');

    var dkimNode = r.domains.dkim
      ? el('span', {}, [el('span', { 'class': 'muted', text: 'd=' }), el('span', { 'class': 'dom', text: r.auth.dkim.domain })])
      : el('span', { 'class': 'env-none', text: r.auth.dkimSignaturePresent ? 'signature present, domain unreadable' : 'unsigned' });
    row('DKIM signature:', 'who cryptographically signed it', dkimNode,
      r.alignment.dkim === 'unknown' ? null : r.alignment.dkim,
      r.alignment.dkim === 'aligned' ? 'matches From' : 'signs for another domain');

    if (r.replyTo && r.replyTo.address) {
      var rd = RP.registrableDomain(r.replyTo.domain);
      var same = rd === r.domains.from;
      row('Reply-To:', 'where your answer goes', addr(r.replyTo, alarming && !same),
        same ? 'aligned' : 'misaligned', same ? 'same domain' : 'different domain');
    }
  }

  function renderAuth(r) {
    var box = $('authstrip');
    clear(box);
    [
      ['SPF', r.auth.spf, 'the server was on the approved list'],
      ['DKIM', r.auth.dkim, 'the signature verified'],
      ['DMARC', r.auth.dmarc, 'the two above line up with the From address']
    ].forEach(function (row) {
      var a = row[1];
      box.appendChild(el('div', { 'class': 'auth', 'data-r': a.result, title: row[2] }, [
        el('span', { 'class': 'auth-k', text: row[0] }),
        el('span', { 'class': 'auth-v', text: a.result }),
        a.domain ? el('span', { 'class': 'auth-d', text: a.domain }) : null
      ]));
    });
  }

  // A disclosure that animates. <details> can't be transitioned in every
  // browser, so this is a button plus a 0fr→1fr grid row, which can.
  function toggle(root, head) {
    var open = root.getAttribute('data-open') === '1';
    root.setAttribute('data-open', open ? '0' : '1');
    head.setAttribute('aria-expanded', open ? 'false' : 'true');
  }

  function initDisclosure(root) {
    var head = root.querySelector('.disclosure-head, .finding-head');
    if (!head) return;
    if (!root.hasAttribute('data-open')) root.setAttribute('data-open', '0');
    head.addEventListener('click', function () { toggle(root, head); });
  }

  function findingNode(f, open) {
    var d = el('div', {
      'class': 'finding disclosure',
      'data-s': f.severity,
      'data-open': open ? '1' : '0'
    });

    var head = el('button', {
      'class': 'finding-head', type: 'button',
      'aria-expanded': open ? 'true' : 'false'
    }, [
      el('span', { 'class': 'sev-dot' }),
      el('span', { 'class': 'finding-title', text: f.title }),
      el('span', { 'class': 'finding-right' }, [
        el('span', { 'class': 'pill', text: f.severity === 'good' ? 'passed' : f.severity }),
        el('span', { 'class': 'finding-tag', text: f.tag })
      ])
    ]);
    head.addEventListener('click', function () { toggle(d, head); });
    d.appendChild(head);

    var body = el('div', { 'class': 'finding-body' }, [
      el('p', { 'class': 'finding-why', text: f.why })
    ]);

    if (f.evidence && f.evidence.length) {
      var ev = el('div', { 'class': 'evidence' });
      f.evidence.forEach(function (e) {
        ev.appendChild(el('div', { 'class': 'ev' }, [
          el('span', { 'class': 'ev-k', text: e.label }),
          el('span', { 'class': 'ev-v', text: e.text })
        ]));
      });
      body.appendChild(ev);
    }

    d.appendChild(el('div', { 'class': 'disclosure-wrap' }, [
      el('div', { 'class': 'disclosure-body' }, [body])
    ]));
    return d;
  }

  function renderFindings(r) {
    var box = $('findings');
    var passedBox = $('passed');
    clear(box);
    clear(passedBox);

    // Problems and passed checks are different kinds of statement, so they get
    // different places. Burying "DMARC fail" in a list that also says "SPF pass"
    // is how a report stops being read.
    var problems = r.findings.filter(function (f) { return f.severity !== 'good'; });
    var passed = r.findings.filter(function (f) { return f.severity === 'good'; });

    $('findingCount').textContent = problems.length
      ? problems.length + (problems.length === 1 ? ' problem' : ' problems')
      : 'no problems found';

    if (!problems.length) {
      box.appendChild(el('div', { 'class': 'finding', 'data-s': 'good' }, [
        el('div', { 'class': 'finding-body', style: 'padding:16px' }, [
          el('p', {
            'class': 'finding-why',
            style: 'margin:0',
            text: passed.length
              ? 'No impersonation, lookalike domain, link trick or dangerous attachment found in this message.'
              : 'Nothing to report — and nothing that vouches for the sender either.'
          })
        ])
      ]));
    } else {
      var criticals = 0;
      problems.forEach(function (f) {
        var open = f.severity === 'critical' && criticals < 3;
        if (open) criticals++;
        box.appendChild(findingNode(f, open));
      });
    }

    if (passed.length) {
      $('passedWrap').hidden = false;
      $('passedCount').textContent = passed.length === 1
        ? '1 check passed'
        : passed.length + ' checks passed';
      passed.forEach(function (f) { passedBox.appendChild(findingNode(f, false)); });
    } else {
      $('passedWrap').hidden = true;
    }
  }

  /* ------------------------------------------------------------ annotated body */

  function riskOf(link) {
    var f = link.flags || [];
    if (f.indexOf('text-mismatch') !== -1 || f.indexOf('userinfo') !== -1 ||
      f.indexOf('punycode') !== -1 || f.indexOf('scheme') !== -1) return 'bad';
    if (f.length) return 'warn';
    return '';
  }

  var FLAG_TEXT = {
    'text-mismatch': 'the text and the destination name different sites',
    'userinfo': 'everything before the @ is discarded by the browser',
    'punycode': 'the domain will be displayed as different characters',
    'scheme': 'not a web address',
    'ip': 'a bare IP address with no domain behind it',
    'shortener': 'destination hidden behind a shortener',
    'lookalike': 'the destination imitates a known brand',
    'credential-path': 'a login-shaped path on a domain unrelated to the sender'
  };

  function linkNote(l) {
    var note = el('span', { 'class': 'lnk-note' });
    note.appendChild(el('b', { text: 'Shows  ' }));
    note.appendChild(document.createTextNode((l.text || '(no text)') + '\n'));
    note.appendChild(el('b', { text: 'Opens  ' }));
    note.appendChild(el('span', {
      'class': riskOf(l) === 'bad' ? 'bad' : '',
      text: l.href || '(empty)'
    }));
    if (l.punyDisplay && l.punyDisplay !== l.host) {
      note.appendChild(document.createTextNode('\n'));
      note.appendChild(el('b', { text: 'Reads as  ' }));
      note.appendChild(el('span', { 'class': 'bad', text: l.punyDisplay }));
    }
    (l.flags || []).forEach(function (f) {
      if (!FLAG_TEXT[f]) return;
      note.appendChild(document.createTextNode('\n→ ' + FLAG_TEXT[f]));
    });
    if (!(l.flags || []).length) {
      note.appendChild(document.createTextNode('\n→ nothing structurally wrong with this one'));
    }
    return note;
  }

  function renderMessage(r) {
    var box = $('message');
    clear(box);

    var htmlIdx = -1, plainIdx = -1;
    r.parts.forEach(function (p, i) {
      if (htmlIdx === -1 && p.type === 'text/html') htmlIdx = i;
      if (plainIdx === -1 && p.type === 'text/plain') plainIdx = i;
    });
    var partIndex = htmlIdx !== -1 ? htmlIdx : plainIdx;
    var html = htmlIdx !== -1 ? r.parts[htmlIdx] : null;
    var plain = plainIdx !== -1 ? r.parts[plainIdx] : null;
    var source = html || plain;

    if (!source || !String(source.decoded || '').trim()) {
      $('messagePanel').hidden = true;
      return;
    }
    $('messagePanel').hidden = false;

    var text = html
      ? RP.flattenBody(html.decoded)
      : String(plain.decoded).replace(/\n{3,}/g, '\n\n').trim();

    // Only the links from the part being shown, in the order they appear in it.
    var linksForPart = r.links.filter(function (l) { return l.partIndex === partIndex; })
      .sort(function (a, b) { return a.inPart - b.inPart; });

    if (!html) {
      // Plain text: highlight each URL occurrence in place.
      var remaining = text;
      linksForPart.forEach(function (l) {
        var at = remaining.indexOf(l.href);
        if (at === -1) return;
        box.appendChild(document.createTextNode(remaining.slice(0, at)));
        box.appendChild(makeLinkButton(l, l.href));
        remaining = remaining.slice(at + l.href.length);
      });
      box.appendChild(document.createTextNode(remaining));
      return;
    }

    var re = new RegExp(RP.TOKEN_OPEN + '(\\d+)' + RP.TOKEN_CLOSE, 'g');
    var last = 0, m;
    while ((m = re.exec(text)) !== null) {
      if (m.index > last) box.appendChild(document.createTextNode(text.slice(last, m.index)));
      var l = linksForPart[Number(m[1])];
      box.appendChild(l ? makeLinkButton(l, l.text || l.href) : document.createTextNode(''));
      last = m.index + m[0].length;
    }
    if (last < text.length) box.appendChild(document.createTextNode(text.slice(last)));
  }

  function makeLinkButton(l, label) {
    var risk = riskOf(l);
    var btn = el('button', {
      'class': 'lnk', type: 'button',
      'data-risk': risk || null,
      'aria-expanded': 'false',
      title: 'Show where this really goes',
      text: label || '(link)'
    });
    var note = null;
    btn.addEventListener('click', function () {
      if (note) {
        note.remove();
        note = null;
        btn.setAttribute('aria-expanded', 'false');
      } else {
        note = linkNote(l);
        btn.parentNode.insertBefore(note, btn.nextSibling);
        btn.setAttribute('aria-expanded', 'true');
      }
    });
    return btn;
  }

  /* ------------------------------------------------------------ links table */

  function renderLinks(r) {
    var box = $('links');
    clear(box);
    if (!r.links.length) { $('linkPanel').hidden = true; return; }
    $('linkPanel').hidden = false;

    var hosts = Object.keys(r.linkHosts);
    $('linkCount').textContent = r.links.length + ' link' + (r.links.length === 1 ? '' : 's') +
      ' across ' + hosts.length + ' domain' + (hosts.length === 1 ? '' : 's');

    r.links.forEach(function (l) {
      var row = el('div', { 'class': 'link-row' });

      function line(k, v, danger) {
        row.appendChild(el('div', { 'class': 'link-line' }, [
          el('span', { 'class': 'k', text: k }),
          el('span', { 'class': 'v' + (danger ? ' danger' : ''), text: v })
        ]));
      }
      line('Text', l.text || '(no visible text)');
      line('Destination', l.href || '(empty)', riskOf(l) === 'bad');
      if (l.punyDisplay && l.punyDisplay !== l.host) line('Displays as', l.punyDisplay, true);
      line('Domain', l.registrable || l.host || '(none)');

      var flags = el('div', { 'class': 'link-flags' });
      if ((l.flags || []).length) {
        l.flags.forEach(function (f) {
          flags.appendChild(el('span', { 'class': 'flag', text: FLAG_TEXT[f] || f }));
        });
      } else {
        flags.appendChild(el('span', { 'class': 'flag', 'data-ok': '1', text: 'no structural problem found' }));
      }
      row.appendChild(flags);
      box.appendChild(row);
    });
  }

  /* ------------------------------------------------------------ hops */

  function renderHops(r) {
    var box = $('hops');
    clear(box);
    if (!r.hops.length) { $('hopPanel').hidden = true; return; }
    $('hopPanel').hidden = false;

    r.hops.forEach(function (h, i) {
      var main = el('div', { 'class': 'hop-main' }, [
        h.from || '(unstated)',
        el('span', { 'class': 'arrow', text: '  →  ' }),
        h.by || '(unstated)'
      ]);

      var bits = [];
      if (h.ip) bits.push(h.ip);
      if (h.with) bits.push('via ' + h.with);
      if (h.date) bits.push(h.date.toISOString().replace('T', ' ').slice(0, 19) + 'Z');

      var meta = el('div', { 'class': 'hop-meta', text: bits.join('  ·  ') });
      if (h.delta !== null && h.delta !== undefined) {
        meta.appendChild(el('span', { 'class': 'delta', text: '  ·  +' + h.delta + 's' }));
      }

      box.appendChild(el('div', { 'class': 'hop' }, [
        el('span', { 'class': 'hop-num', text: String(i + 1) }),
        el('div', { 'class': 'hop-body' }, [main, meta])
      ]));
    });
  }

  /* ------------------------------------------------------------ raw */

  var WATCHED = {
    'from': 1, 'return-path': 1, 'reply-to': 1, 'sender': 1,
    'authentication-results': 1, 'received-spf': 1, 'dkim-signature': 1,
    'message-id': 1, 'subject': 1, 'list-unsubscribe': 1
  };

  function renderRaw(r) {
    var pre = $('raw');
    clear(pre);

    var alarming = r.verdict.level === 'forged' || r.verdict.level === 'suspicious';
    var HOT = { 'from': 1, 'return-path': 1, 'reply-to': 1, 'authentication-results': 1, 'received-spf': 1 };

    var block = RP.splitMessage(r.raw).headerBlock;
    var lines = block.split('\n');
    var currentKey = '';

    lines.forEach(function (line) {
      if (!/^[ \t]/.test(line)) {
        var m = line.match(/^([!-9;-~]+)[ \t]*:/);
        currentKey = m ? m[1].toLowerCase() : '';
      }
      if (WATCHED[currentKey]) {
        pre.appendChild(el('span', {
          'class': 'hl' + (alarming && HOT[currentKey] ? ' hl-bad' : ''),
          text: line
        }));
      } else {
        pre.appendChild(document.createTextNode(line));
      }
      pre.appendChild(document.createTextNode('\n'));
    });
  }

  /* ------------------------------------------------------------ boot */

  // Deep link: #sample=bec loads a specimen directly, for the demo. Changing
  // the hash is a same-document navigation, so this has to run on hashchange
  // too or the second link in a walkthrough silently does nothing.
  function loadFromHash() {
    var m = (location.hash || '').match(/sample=([\w-]+)/);
    if (!m) return;
    var s = SAMPLES.filter(function (x) { return x.id === m[1]; })[0];
    if (!s) return;
    input.value = s.raw;
    Array.prototype.forEach.call(document.querySelectorAll('.chip'), function (c) {
      c.setAttribute('aria-pressed', c.getAttribute('data-id') === s.id ? 'true' : 'false');
    });
    run();
  }
  loadFromHash();
  window.addEventListener('hashchange', loadFromHash);

  input.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); run(); }
  });

  Array.prototype.forEach.call(document.querySelectorAll('[data-disclosure]'), initDisclosure);

  // Parallax and scroll-driven depth.
  //
  // Every value is LERPED toward its target each frame rather than snapped to
  // the scroll position. That is what makes it feel smooth and weighted: the
  // page stops, the motion keeps settling for a few frames. Native scrolling is
  // left completely alone - hijacking the wheel would break the report's own
  // scroll-into-view, keyboard paging and the scrollbar.
  (function () {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    var sky = document.querySelector('.sky');
    var SKY_FADE = 980;
    var SKY_LAG = 0.80;   // keeps 80% of the page's movement, so it really hangs

    var items = [];
    Array.prototype.forEach.call(document.querySelectorAll('[data-par]'), function (n) {
      items.push({
        node: n,
        rate: parseFloat(n.getAttribute('data-par')) || 0.2,
        tilt: parseFloat(n.getAttribute('data-tilt')) || 0,
        cur: 0, curTilt: 0
      });
    });

    var skyCur = 0, skyOpCur = 1;
    var EASE = 0.15;      // how hard each frame pulls toward the target
    var running = true;

    function lerp(a, b, t) { return a + (b - a) * t; }

    function frame() {
      var y = window.scrollY || window.pageYOffset;
      var vh = window.innerHeight;

      if (sky) {
        var skyTarget = y * SKY_LAG;
        var t = Math.min(y / SKY_FADE, 1);
        var opTarget = 1 - t * t;
        skyCur = lerp(skyCur, skyTarget, EASE);
        skyOpCur = lerp(skyOpCur, opTarget, EASE);
        if (opTarget <= 0.002 && skyOpCur < 0.01) {
          sky.style.visibility = 'hidden';
        } else {
          sky.style.visibility = 'visible';
          // Positive translate: pushed back down as the page rises, so it holds
          // in frame and lingers. Negative would rush it off the top.
          sky.style.transform = 'translate3d(0,' + skyCur.toFixed(2) + 'px,0)';
          sky.style.opacity = skyOpCur.toFixed(3);
        }
      }

      for (var i = 0; i < items.length; i++) {
        var it = items[i];
        var r = it.node.getBoundingClientRect();
        if (r.bottom < -300 || r.top > vh + 300) continue;

        // -1 above the fold, 0 centred, +1 below: the element's progress
        // through the viewport.
        var mid = (r.top + r.height / 2 - vh / 2) / (vh / 2 + r.height / 2);
        mid = Math.max(-1, Math.min(1, mid));

        it.cur = lerp(it.cur, mid * it.rate * 100, EASE);
        var css = 'translate3d(0,' + it.cur.toFixed(2) + 'px,0)';

        if (it.tilt) {
          // A little rotation about X as it passes, so the plate reads as a
          // surface in space rather than a flat rectangle sliding by.
          it.curTilt = lerp(it.curTilt, mid * it.tilt, EASE);
          css += ' perspective(1400px) rotateX(' + it.curTilt.toFixed(2) + 'deg)' +
                 ' scale(' + (1 - Math.abs(it.curTilt) * 0.004).toFixed(4) + ')';
        }
        it.node.style.transform = css;
      }

      if (running) requestAnimationFrame(frame);
    }

    // Pause the loop when the tab is hidden; nothing is moving to look at.
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) { running = false; }
      else if (!running) { running = true; requestAnimationFrame(frame); }
    });

    requestAnimationFrame(frame);
  })();

  // Scroll reveal. Anything already on screen at load stays put rather than
  // animating in behind the fold.
  var reveals = document.querySelectorAll('.reveal, .reveal-l, .reveal-r');
  var calmed = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  if (!window.IntersectionObserver || calmed) {
    Array.prototype.forEach.call(reveals, function (n) { n.classList.add('in'); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        entry.target.classList.add('in');
        io.unobserve(entry.target);
      });
    }, { rootMargin: '0px 0px -12% 0px', threshold: 0.08 });
    Array.prototype.forEach.call(reveals, function (n) { io.observe(n); });
  }

  // The privacy figures count up the first time they are seen. They are all
  // zero, so this counts *down* to nothing — which is the point being made.
  (function () {
    var stats = document.querySelectorAll('.privacy-stats b');
    if (!stats.length) return;
    if (calmed || !window.IntersectionObserver) return;

    var spin = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        var node = entry.target;
        spin.unobserve(node);
        var target = node.textContent.trim();
        var from = 24;
        var start = null;

        function step(now) {
          if (start === null) start = now;
          var t = Math.min((now - start) / 900, 1);
          var eased = 1 - Math.pow(1 - t, 3);
          node.textContent = t >= 1 ? target : String(Math.round(from * (1 - eased)));
          if (t < 1) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
      });
    }, { threshold: 0.6 });

    Array.prototype.forEach.call(stats, function (n) { spin.observe(n); });
  })();
})();
