#!/usr/bin/env python3
"""Build two self-contained HTML files from app.source.html + kb.js + app.js.

  blast-radius-local.html   full tool (all 3 modes). Offline/self-hosted ONLY.
  blast-radius-public.html  single-app mode only, for public hosting.

Also writes docs/index.html (the public build, for GitHub Pages) and SHA256SUMS,
then runs integrity checks and exits non-zero if any fail.

Usage:  python3 build.py [--out DIR]     (default: the repo directory)
"""
import hashlib, pathlib, re, shutil, sys

SRC = pathlib.Path(__file__).resolve().parent
OUT = SRC
if "--out" in sys.argv:
    OUT = pathlib.Path(sys.argv[sys.argv.index("--out") + 1]).resolve()
OUT.mkdir(parents=True, exist_ok=True)

html = (SRC / "app.source.html").read_text(encoding="utf-8")
kb   = (SRC / "kb.js").read_text(encoding="utf-8")
app  = (SRC / "app.js").read_text(encoding="utf-8")

START, END = "// <<<STRIP-PUBLIC-START>>>", "// <<<STRIP-PUBLIC-END>>>"

def strip_public(js):
    """Remove sentinel-marked tenant/partner blocks for the public build."""
    return re.sub(r"// <<<STRIP-PUBLIC-START>>>.*?// <<<STRIP-PUBLIC-END>>>\n", "", js, flags=re.DOTALL)

def inline(h, public=False):
    a = strip_public(app) if public else app.replace(START, "//").replace(END, "//")
    h = h.replace('<script src="kb.js"></script>', "<script>\n" + kb + "\n</script>")
    h = h.replace('<script src="app.js"></script>', "<script>\n" + a + "\n</script>")
    return h

def must_replace(h, old, new, label):
    if old not in h:
        sys.exit(f"build.py: could not find {label} in app.source.html")
    return h.replace(old, new, 1)

# ---------------------------------------------------------------------------
# Banners
# ---------------------------------------------------------------------------
LOCAL_BANNER = '''  <div class="build-banner local">
    <span class="bb-ic">\U0001F512</span>
    <div><b>Offline build. Runs entirely in your browser.</b> This tool makes no network calls. Anything you paste or
      load in Whole-tenant or Partner/MSP mode (Entra exports, GDAP maps) is analyzed locally and never leaves this
      machine. Best run from a local file or hosting you control, not a public URL.</div>
  </div>
'''

PUBLIC_BANNER = '''  <div class="build-banner public">
    <span class="bb-ic">\U0001F310</span>
    <div><b>Public build: the before-you-consent lookup.</b> Pick or paste the permissions an app is requesting and see
      its blast radius, before you grant anything. This is an analysis aid, not an audit: <b>\u201cno known path\u201d means
      nothing in the knowledge base matched, not that an app is safe.</b> The Whole-tenant and Partner/MSP analyzers live
      in the offline build, which runs on your own machine so client exports stay off public URLs.</div>
  </div>
'''

DO_NOT_HOST = (
    "<!--\n"
    "  ==========================================================================\n"
    "  Blast Radius: OFFLINE / FULL build.\n"
    "  DO NOT host this file on a public URL (GitHub Pages, public S3, etc.).\n"
    "  It contains the Whole-tenant and Partner/MSP analyzers, whose inputs are\n"
    "  real environment exports. The tool makes no network calls and never\n"
    "  uploads anything, but a public page is the wrong place to normalize\n"
    "  pasting client environment data. Run it from a local file, or from\n"
    "  hosting you control with access limits. The public before-you-consent\n"
    "  build is the one meant for public hosting.\n"
    "  ==========================================================================\n"
    "-->\n"
    "\n"
)

MODE_SWITCH = '  <div class="mode-switch mode-switch-3"'

# ---------------------------------------------------------------------------
# LOCAL build: full file + do-not-host comment + residency banner
# ---------------------------------------------------------------------------
local = html
local = must_replace(local, "<!DOCTYPE html>\n", "<!DOCTYPE html>\n" + DO_NOT_HOST, "<!DOCTYPE html>")
local = must_replace(local, '<body data-aud="tech">', '<body data-aud="tech" data-build="local">', "<body>")
local = must_replace(local, MODE_SWITCH, LOCAL_BANNER + MODE_SWITCH, "the mode switch")
local = inline(local)

# ---------------------------------------------------------------------------
# PUBLIC build: remove tenant-mode and partner-mode panels; lock their buttons
# ---------------------------------------------------------------------------
pub = html
pub = must_replace(pub, '<body data-aud="tech">', '<body data-aud="tech" data-build="public">', "<body>")
pub, n1 = re.subn(r"  <!-- ============ TENANT MODE ============ -->.*?(?=  <!-- ============ PARTNER / MSP MODE ============ -->)",
                  "", pub, flags=re.DOTALL)
pub, n2 = re.subn(r"  <!-- ============ PARTNER / MSP MODE ============ -->.*?(?=  <p class=\"footer-meta\")",
                  "", pub, flags=re.DOTALL)
if (n1, n2) != (1, 1):
    sys.exit("build.py: could not strip the tenant/partner panels from the public build")
pub = must_replace(pub,
'''    <button id="mode-tenant" aria-pressed="false">
      <span class="ms-t">Whole tenant</span>
      <span class="ms-d">Rank every app in a tenant and trace takeover chains.</span>
    </button>
    <button id="mode-partner" aria-pressed="false">
      <span class="ms-t">Partner / MSP</span>
      <span class="ms-d">Map GDAP reach: which customers a partner compromise unlocks.</span>
    </button>''',
'''    <button class="locked" type="button" title="Available in the offline build" aria-disabled="true">
      <span class="ms-lock">\u2193 offline</span>
      <span class="ms-t">Whole tenant</span>
      <span class="ms-d">Rank every app in a tenant and trace takeover chains. In the offline build so exports stay local.</span>
    </button>
    <button class="locked" type="button" title="Available in the offline build" aria-disabled="true">
      <span class="ms-lock">\u2193 offline</span>
      <span class="ms-t">Partner / MSP</span>
      <span class="ms-d">Map GDAP reach across customers. In the offline build so client data stays local.</span>
    </button>''', "the tenant/partner mode buttons")
pub = must_replace(pub, MODE_SWITCH, PUBLIC_BANNER + MODE_SWITCH, "the mode switch")
pub = inline(pub, public=True)

# ---------------------------------------------------------------------------
# Integrity checks: fail the build rather than ship a broken promise
# ---------------------------------------------------------------------------
problems = []
for name, txt in (("local", local), ("public", pub)):
    if 'http-equiv="Content-Security-Policy"' not in txt:
        problems.append(f"{name}: no Content-Security-Policy meta tag")
    if "connect-src 'none'" not in txt:
        problems.append(f"{name}: CSP does not block connections")
    for m in re.finditer(r'<(?:link|script)[^>]+(?:href|src)="(https?:[^"]+)"', txt):
        problems.append(f"{name}: loads an external resource: {m.group(1)}")
    if "STRIP-PUBLIC" in txt:
        problems.append(f"{name}: leftover STRIP-PUBLIC sentinel")
    if "\u2014" in txt:
        print(f"warning: {name} contains {txt.count(chr(0x2014))} em-dash(es)")
for marker in ('id="tenant-mode"', 'id="partner-mode"', "const TENANT_SCRIPT", "const SAMPLE_TENANT", "function analyzeTenant"):
    if marker in pub:
        problems.append(f"public: still contains {marker}")
if not all(x in local for x in ('id="tenant-mode"', 'id="partner-mode"', 'id="single-mode"')):
    problems.append("local: missing one of the three mode panels")
if problems:
    sys.exit("build.py: integrity check failed:\n  " + "\n  ".join(problems))

# ---------------------------------------------------------------------------
# Write outputs, the Pages copy, and hashes
# ---------------------------------------------------------------------------
# write bytes, not text: text mode turns \n into \r\n on Windows, which would make
# the hashes (and the CI drift check) depend on who ran the build
(OUT / "blast-radius-local.html").write_bytes(local.encode("utf-8"))
(OUT / "blast-radius-public.html").write_bytes(pub.encode("utf-8"))
(OUT / "docs").mkdir(exist_ok=True)
shutil.copyfile(OUT / "blast-radius-public.html", OUT / "docs" / "index.html")

sums = ""
for name in ("blast-radius-local.html", "blast-radius-public.html"):
    digest = hashlib.sha256((OUT / name).read_bytes()).hexdigest()
    sums += f"{digest}  {name}\n"
    print(f"{name}: {(OUT / name).stat().st_size / 1024:.1f} KB  sha256 {digest[:16]}...")
(OUT / "SHA256SUMS").write_bytes(sums.encode("utf-8"))
print("docs/index.html: public build copied for GitHub Pages")
print("integrity checks passed")
