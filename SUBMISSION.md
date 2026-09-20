# TLN Cybersecurity Challenge — submission kit

**Deadline: Sunday 20 September 2026, 10:00 AM EDT.**

- Live demo: https://goofturtles.github.io/return-path/
- Repository: https://github.com/Goofturtles/return-path
- Video: *(record from the script below, must be under 5 minutes)*

---

## Devpost fields

### Project name

**Return Path**

### Tagline (short description)

> Read the envelope, not the letter. Paste a suspicious email and see who really sent it — entirely in your browser, with nothing uploaded.

### Built with

`javascript` · `html` · `css` · `rfc-5322` · `spf` · `dkim` · `dmarc` · `punycode` ·
`node` · `github-pages`

### Try it out links

- https://goofturtles.github.io/return-path/
- https://github.com/Goofturtles/return-path

---

## Inspiration

For twenty years, every anti-phishing training slide said the same thing: *look for bad
spelling and bad grammar.* That advice is now dead. A language model writes a more
fluent password-reset notice than most companies' real one, and the tells people were
trained to spot are gone.

But a language model only rewrites the letter. It doesn't change the envelope. Every
email carries a record of the servers that actually handled it, the domain that
cryptographically signed it, and the address a reply would really go to — and that
record is much harder to fake than a paragraph. Mail administrators have read it for
decades. Almost nobody else ever has, because it looks like this:

```
Authentication-Results: mx.example.com; dkim=none;
   spf=fail smtp.mailfrom=bounce@mailer-7f2a.top;
   dmarc=fail (p=REJECT) header.from=paypa1.com
```

Return Path exists to make that paragraph readable by the person who received the email.

## What it does

You paste an email's raw source — or drop a `.eml` file — and it reports who really
sent it, with the evidence.

- **The two senders.** Every email has the address you're shown (`From:`) and the
  address the servers actually spoke to (`Return-Path:`). Only the second is checked by
  SPF. Return Path puts them side by side, because that gap is how a message passes
  authentication while still appearing to come from someone else.
- **Impersonation.** A real address hidden inside the display name is invisible on every
  mobile mail client, which shows the name and hides the address. A brand name on a
  domain that doesn't own it. A `Reply-To` quietly pointing at a third party.
- **Lookalike domains.** Punycode is decoded, so a domain registered as
  `xn--pypal-4ve.com` is shown as the `pаypal.com` you'd have seen on screen — with a
  Cyrillic **а**. Confusable characters are folded before comparison, catching
  `paypa1.com` and `rnicrosoft.com` too.
- **Links.** Anchor text compared against the real destination, `@`-in-URL misdirection,
  bare IPs, shorteners, `javascript:` URLs. Click any link in the annotated message to
  see where it actually goes.
- **Attachments and route.** Double extensions like `invoice.pdf.js` — which work
  because Windows hides the real extension — macro-capable formats, and the full
  `Received` chain with time deltas.

The verdict is **Forged**, **Suspicious**, **Unverified** or **Authenticated**. Never
"safe". Every finding opens to show the exact header it came from, and ends with a
plain-language *What to do*.

## How I built it

Vanilla JavaScript, HTML and CSS. No framework, no build step, no dependencies, no
backend.

`js/engine.js` is the whole product: an RFC 5322 header parser (with unfolding and
RFC 2047 encoded-word decoding), an RFC 3492 punycode decoder written from the spec, a
Unicode confusable-folding table, `Authentication-Results` parsing, a MIME part walker,
and about thirty detection rules that each emit a finding with a severity, a
plain-English explanation and the source header as evidence. It has no DOM or network
dependency at all, which is why the same file backs both the web page and the Node test
suite.

`js/app.js` is the view layer, under one hard rule described below.

Deployed as static files on GitHub Pages. Tested with a 84-assertion Node suite that
runs with zero dependencies: `node tests/engine.test.cjs`.

## Two decisions I'd defend in a code review

**Nothing is uploaded, ever.** The page loads a dozen local files (markup, styles, three scripts
and its fonts) and then makes no further network requests. Disconnect from the internet and it keeps working — that's a
demonstrable claim, not a privacy-policy sentence. This matters because every comparable
tool asks you to paste your email into someone else's server, which means reporting a
phishing attempt requires handing a stranger the contents of your inbox. The cost is
stated openly in the UI: DKIM signatures can't be re-verified, since that needs a DNS
lookup for the sender's public key, so the tool reads the result your mail provider
already recorded.

**The email's HTML is never rendered.** A message under analysis is hostile input by
definition, so rendering its markup inside the tool examining it would be an own-goal.
The annotated view is a reconstruction: markup is flattened to text as a *string*, never
parsed into the DOM, and links are rebuilt as the app's own `<button>` elements. Nothing
derived from the message reaches `innerHTML` — every value arrives as a text node.

## Challenges I ran into

**Not crying wolf.** The first version flagged a third-party `Return-Path` as a serious
problem. That's wrong: every newsletter and receipt legitimately sends through a mail
provider, so the rule would have fired on half of all real mail. It now checks whether
anything *vouches* for the mismatch — a DMARC pass, or a DKIM signature aligned to the
From domain — and downgrades it to an explanation instead of a warning. Same story with
`amazonaws.com`, which naively reads as a lookalike of `amazon.com`; the brand list
needed a companion list of each brand's legitimate secondary domains.

Two of the six built-in specimens are legitimate mail on purpose. A detector you've only
ever seen say "bad" hasn't been shown to work.

**Where the tool honestly stops.** Business email compromise is the case that breaks
every header-based tool: when the attacker sends from a real mailbox they've stolen,
every check passes because everything is genuine except the person typing. Rather than
hide that, it's one of the specimens — authentication all green, verdict **Suspicious**,
caught on a `Reply-To` divergence and a stack of pressure tactics. The limitations are
a section on the page, not a footnote.

## What I learned

That the useful unit isn't a score, it's a **citation**. The first draft produced a risk
percentage, which is unfalsifiable and teaches nothing. Making every finding open to
reveal the exact header it was derived from changed the tool from something you trust
into something you can check — and, more usefully, something you learn the trick from.

## What's next

- Verify DKIM signatures properly via DNS-over-HTTPS, as an explicit opt-in that says
  clearly it's about to make a network request.
- A browser extension that reads the headers of the message already open, removing the
  copy-paste step that's the real adoption barrier.
- Extend the confusable table beyond Latin/Cyrillic/Greek to the full Unicode
  confusables set.

## AI disclosure

Built with Claude (Anthropic) as a coding assistant. The implementation, test suite and
copy were produced in collaboration with it; the product design, the choice of which
detection rules to implement, and the threat model are mine.

**The submitted tool contains no AI or machine learning.** Every verdict is a
deterministic rule over RFC 5322 headers — which is precisely what makes each finding
explainable down to the header it came from, and what lets it run offline.

---

## Video script — target 3:00, hard limit 5:00

Record at 1440×900. Open at `https://goofturtles.github.io/return-path/`. Speak over
screen capture; no face cam needed.

### 0:00–0:25 — The hook

> *(hero on screen)*
>
> For twenty years, the advice about phishing emails was: look for bad spelling. That
> advice is dead. This is a phishing email written by a language model — the grammar is
> perfect, the tone is right, and every tell you were trained to look for is gone.
>
> But the attacker only rewrote the letter. They didn't rewrite the envelope.

### 0:25–1:15 — Specimen 1: the credential phish

> *(click "Credential phish")*
>
> This is the raw source of that email, and here's what's underneath it.
>
> **Forged.** Not a score — a conclusion, and here's why.
>
> *(point at the two-senders panel)*
>
> Every email has two senders. The one your mail app shows you, and the one the servers
> actually talked to. Only the second one gets checked. Here the From says PayPal, the
> Return-Path says `mailer-7f2a.top`, and DMARC — the domain owner's own policy — says
> `fail`. PayPal has effectively stated this didn't come from them.
>
> *(open the display-name finding)*
>
> And look at this one. The sender's *name* is `service@paypal.com`. Not the address —
> the name. On a phone, that's all you'd ever see, because mobile mail clients show the
> name and hide the address. The real address is `alerts@paypa1.com`, with the digit
> one.
>
> *(scroll to the annotated message, click the first link)*
>
> The link says `paypal.com/signin`. Click it here and you see where it actually goes.
> That's not PayPal — `paypal.com` is just a subdomain label on someone else's domain.

### 1:15–2:00 — Specimen 2: the one that passes

> *(click "Business email compromise")*
>
> Now the case that matters most, because it's the one that breaks every tool like this.
>
> SPF: pass. DKIM: pass. DMARC: pass. Everything is green, and it's still an attack.
>
> A principal emails a teacher asking for gift cards. The account is real, so every
> cryptographic check passes. What doesn't pass is the envelope logic: hit reply and
> your message goes to `consultant-mail.co` — a domain unrelated to the sender *and* to
> every server that carried this. Plus urgency, plus a secrecy instruction, plus an
> unrecoverable payment rail.
>
> Verdict: **Suspicious**. The tool never says "safe", because a stolen mailbox sends
> perfectly authenticated mail.

### 2:00–2:30 — Specimen 3: homographs, and a real one

> *(click "Homograph attack")*
>
> This domain is registered as `xn--microsft-secure-esm.com`. Your browser renders it
> with a Cyrillic **о**. Two different domains, one appearance — and reading carefully
> cannot save you, because the characters genuinely are different. Return Path decodes
> the punycode and shows you both.
>
> *(click "A real one")*
>
> And a genuine Google security alert: **Authenticated**, zero findings. A detector you've
> only ever seen say "bad" hasn't been shown to work.

### 2:30–3:00 — How, and the honest limits

> Vanilla JavaScript — no framework, no backend, no dependencies. About thirty
> deterministic rules over the headers, each one citing the exact header it came from.
> No machine learning anywhere, which is what makes every finding explainable.
>
> *(open DevTools Network tab, reload, show it empty — or disconnect wi-fi and re-run)*
>
> And nothing is uploaded. The page loads three files and then makes zero network
> requests. I can turn off the internet and it still works — which is the only honest
> way to handle somebody's private mail, because every other tool like this asks you to
> paste your inbox onto a stranger's server.
>
> It can't re-verify a DKIM signature, because that needs DNS and I chose offline. It
> can't see a compromised account. Those limits are a section on the page, not a
> footnote.
>
> Read the envelope, not the letter.

### Shot list

| # | Shot | Note |
|---|---|---|
| 1 | Hero, static | 4s hold, let the headline land |
| 2 | Click `Credential phish` → verdict card | the scroll-in is the reveal |
| 3 | Two-senders panel, cursor tracing From → Return-Path | slow |
| 4 | Expand *display name is itself a fake email address* | |
| 5 | Annotated message, click link 1 | **the money shot** |
| 6 | Click `Business email compromise` → all-green auth strip + Suspicious | hold on the contradiction |
| 7 | Expand *Reply-To divergence* | |
| 8 | Click `Homograph attack`, expand the punycode finding | show `xn--` → Cyrillic |
| 9 | Click `A real one` → Authenticated, no findings | |
| 10 | DevTools Network panel empty after reload | the offline proof |
| 11 | Scroll the *What this can't do* section | end on honesty |

### Recording checklist

- [ ] Under 5:00 (aim 3:00)
- [ ] Says the problem, the solution, how it works, the stack, and the impact — all five are required
- [ ] Shows a working prototype, not slides
- [ ] Mentions AI assistance
- [ ] Audio levels checked before the full take

## Pre-submission checklist

- [ ] Devpost project page created with name, description, technologies
- [ ] Demo link added (live site **and** repo)
- [ ] Video uploaded and public, under 5 minutes, link added
- [ ] AI disclosure filled in (text above)
- [ ] Submitted **before 10:00 AM EDT, Sunday 20 September**
