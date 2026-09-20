# Return Path

**Read the envelope, not the letter.** Paste a suspicious email's raw source and see
exactly who really sent it — entirely in your browser, with no network requests.

Built for the TLN Cybersecurity Challenge, September 2026.

---

## The problem

For twenty years, anti-phishing advice was *look for bad spelling*. Language models
ended that. The prose in a phishing email is now frequently better than the prose in the
real one, and every signal people were trained to look for — broken grammar, odd
phrasing, clumsy formatting — has been erased.

What language models cannot touch is the machinery underneath. Every email carries a
record of the servers that actually handled it, the domain that cryptographically signed
it, and the address a reply would really go to. An attacker can write a perfect
paragraph. Forging that record is a different problem, and in most cases they don't
bother, because almost nobody looks.

## What it does

Paste raw message source (or drop a `.eml`) and Return Path reports:

| Check | What it catches |
|---|---|
| **Authentication** | SPF / DKIM / DMARC results as recorded by the receiving mail server |
| **Alignment** | The gap between the From address you're shown and the Return-Path the servers used — how mail passes SPF while still appearing to come from someone else |
| **Impersonation** | A real address hidden in the display name (invisible on mobile), a brand name on a domain that doesn't own it, a Reply-To pointing somewhere else |
| **Lookalike domains** | Punycode decoded to what you'd actually see, Cyrillic/Greek confusables, digit-for-letter and `rn`→`m` swaps, brand names buried in subdomains |
| **Links** | Anchor text vs. real destination, `@`-in-URL misdirection, bare IPs, shorteners, `javascript:`/`data:` URLs |
| **Attachments** | Double extensions (`invoice.pdf.js`), macro-capable formats, archives |
| **Route** | Every `Received` hop in order, with time deltas and backwards-running timestamps |
| **Pretext** | Urgency, threatened account loss, secrecy instructions, unrecoverable payment rails |

The verdict is one of **Forged**, **Suspicious**, **Unverified** or **Authenticated** —
deliberately never "safe" — with a plain-language *What to do*, and every finding
expands to show the exact header it was derived from.

## Running it

No build step, no dependencies, no server required.

```bash
python -m http.server 3526 -d return-path
```

Then open `http://localhost:3526/`. Opening `index.html` directly from disk also works.

Run the test suite:

```bash
node return-path/tests/engine.test.cjs
```

79 assertions covering address parsing, punycode round-trips, confusable folding,
auth-result extraction, hop ordering, all six specimens end to end, and malformed input.

## Two design decisions worth explaining

**Nothing is uploaded, ever.** The page loads a dozen local files (markup, styles, three scripts
and its fonts) and then makes no further network requests. You can disconnect from the internet and it keeps working.
This isn't a feature bullet — it's the only defensible way to handle somebody's private
mail. Every comparable tool asks you to paste your email into someone else's server,
which means reporting a phishing attempt requires handing a stranger the contents of
your inbox.

The cost is real and stated in the UI: DKIM signatures cannot be re-verified, because
that needs a DNS lookup for the sender's public key. Return Path reads the result the
receiving mail server already recorded rather than performing its own cryptography.

**The email's HTML is never rendered.** An email under analysis is hostile input by
definition, so rendering its markup inside the tool examining it would be an obvious
own-goal. The "annotated" view is a reconstruction: the markup is flattened to text as a
*string* (never parsed into the DOM), and links are rebuilt as our own `<button>`
elements. Nothing derived from the message ever reaches `innerHTML` — every value
arrives as a text node. See the header comment in `js/app.js`.

## What it can't do

- **It cannot see a compromised account.** When an attacker sends from a real mailbox
  they've stolen, every check passes, because everything is genuine except the person
  typing. The *Business email compromise* specimen demonstrates exactly this: SPF, DKIM
  and DMARC all pass and the verdict is still **Suspicious**.
- **Headers can be stripped.** Forwarding and some gateways remove or rewrite headers.
  Less evidence means a less confident answer, not a safer message.
- **The brand list is finite.** Lookalike detection compares against a fixed list of
  commonly impersonated domains, alongside a list of those brands' legitimate secondary
  domains (`amazonaws.com`, `googleapis.com`, …) so ordinary corporate mail isn't
  flagged. A lookalike of a domain outside that list won't be named by brand, though the
  link and alignment checks still apply.
- **"Authenticated" is a statement about a domain, not a person.** It means the message
  really came from where it claims. It says nothing about whether the request inside it
  is reasonable.

## Layout

```
return-path/
  index.html              one page
  css/app.css             one stylesheet
  css/fonts.css           self-hosted @font-face declarations
  fonts/                  seven woff2 files, so no third-party font requests
  js/engine.js            analysis — pure functions, runs in node and the browser
  js/samples.js           six synthetic specimens
  js/app.js               view layer — text nodes only, no innerHTML
  tests/engine.test.cjs   node test suite, zero dependencies
```

`engine.js` has no DOM or network dependency at all, which is why the same file backs
both the page and the tests.

## Specimens

Six, reachable by `#sample=<id>`: `credential-phish`, `bec`, `homograph`, `payload`,
`genuine`, `newsletter`. Every one was written for this tool — no real message, address
or recipient appears anywhere in the repository. Brand names appear only as the *targets*
of impersonation, which is the thing being detected.

Two of the six are legitimate mail, on purpose. A detector that has never been shown
saying "this is fine" hasn't been shown to work.

## AI disclosure

Built with Claude (Anthropic) as a coding assistant: implementation, tests and copy were
produced in collaboration with it, and the product design, the detection logic to
implement, and the threat model are the author's. The tool itself contains no AI or
machine learning — every verdict is a deterministic rule over RFC 5322 headers, which is
what makes each finding explainable down to the header it came from.

## Licence

MIT.
