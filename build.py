#!/usr/bin/env python3
"""Build two self-contained HTML files from app.source.html + kb.js + app.js:
   - blast-radius-local.html : full tool (all 3 modes) + data-residency banner
   - blast-radius-public.html : single-app mode only, for public hosting (GitHub Pages)
"""
import re, os, pathlib

SRC = pathlib.Path(__file__).parent
OUT = pathlib.Path("/mnt/user-data/outputs")
OUT.mkdir(parents=True, exist_ok=True)

html = (SRC / "app.source.html").read_text()
kb   = (SRC / "kb.js").read_text()
app  = (SRC / "app.js").read_text()

def strip_public(js):
    """Remove sentinel-marked tenant/partner blocks for the public build."""
    return re.sub(r'// <<<STRIP-PUBLIC-START>>>.*?// <<<STRIP-PUBLIC-END>>>\n',
                  '', js, flags=re.DOTALL)

def inline(h, public=False):
    a = strip_public(app) if public else app.replace('// <<<STRIP-PUBLIC-START>>>', '//').replace('// <<<STRIP-PUBLIC-END>>>', '//')
    h = h.replace('<script src="kb.js"></script>', '<script>\n' + kb + '\n</script>')
    h = h.replace('<script src="app.js"></script>', '<script>\n' + a + '\n</script>')
    return h

# ---------------------------------------------------------------------------
# Banners
# ---------------------------------------------------------------------------
LOCAL_BANNER = '''  <div class="build-banner local">
    <span class="bb-ic">\U0001F512</span>
    <div><b>Offline build — runs entirely in your browser.</b> This tool makes no network calls. Anything you paste or
      load in Whole-tenant or Partner/MSP mode (Entra exports, GDAP maps) is analyzed locally and never leaves this
      machine. Best run from a local file or hosting you control, not a public URL.</div>
  </div>
'''

PUBLIC_BANNER = '''  <div class="build-banner public">
    <span class="bb-ic">\U0001F310</span>
    <div><b>Public build — the before-you-consent lookup.</b> Pick or paste the permissions an app is requesting and see
      its blast radius, before you grant anything. This is an analysis aid, not an audit: <b>\u201cno known path\u201d means
      nothing in the knowledge base matched, not that an app is safe.</b> The Whole-tenant and Partner/MSP analyzers live
      in the offline build, which runs on your own machine so client exports stay off public URLs.</div>
  </div>
'''

# ---------------------------------------------------------------------------
# LOCAL build: full file + residency banner after the incident note
# ---------------------------------------------------------------------------
DO_NOT_HOST = (
    "<!--\n"
    "  ==========================================================================\n"
    "  Blast Radius — OFFLINE / FULL build.\n"
    "  DO NOT host this file on a public URL (GitHub Pages, public S3, etc.).\n"
    "  It contains the Whole-tenant and Partner/MSP analyzers, whose inputs are\n"
    "  real environment exports. The tool makes no network calls and never\n"
    "  uploads anything — but a public page is the wrong place to normalise\n"
    "  pasting client environment data. Run it from a local file, or from\n"
    "  hosting you control with access limits. The public before-you-consent\n"
    "  build is the one meant for public hosting.\n"
    "  ==========================================================================\n"
    "-->\n"
)
local = html
local = local.replace("<!DOCTYPE html>", "<!DOCTYPE html>\n" + DO_NOT_HOST, 1)
local = local.replace('<body data-aud="tech">', '<body data-aud="tech" data-build="local">')
# insert banner right before the mode switch
local = local.replace('  <div class="mode-switch mode-switch-3"', LOCAL_BANNER + '  <div class="mode-switch mode-switch-3"', 1)
local = inline(local)
(OUT / "blast-radius-local.html").write_text(local)

# ---------------------------------------------------------------------------
# PUBLIC build: remove tenant-mode and partner-mode panels; lock their buttons
# ---------------------------------------------------------------------------
pub = html
pub = pub.replace('<body data-aud="tech">', '<body data-aud="tech" data-build="public">')

# 1) remove the tenant-mode panel block  (<div id="tenant-mode" ...> ... </div> up to the partner comment)
pub = re.sub(
    r'  <!-- ============ TENANT MODE ============ -->.*?(?=  <!-- ============ PARTNER / MSP MODE ============ -->)',
    '', pub, flags=re.DOTALL)

# 2) remove the partner-mode panel block (up to the footer-meta paragraph)
pub = re.sub(
    r'  <!-- ============ PARTNER / MSP MODE ============ -->.*?(?=  <p class="footer-meta")',
    '', pub, flags=re.DOTALL)

# 3) also drop the closing comment tag left from single-mode wrapper staying intact — single-mode stays.

# 4) rewrite the mode switch: tenant & partner become locked/informational buttons
pub = pub.replace(
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
    </button>''')

# 5) public banner before the mode switch
pub = pub.replace('  <div class="mode-switch mode-switch-3"', PUBLIC_BANNER + '  <div class="mode-switch mode-switch-3"', 1)

pub = inline(pub, public=True)
(OUT / "blast-radius-public.html").write_text(pub)

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
for name in ("blast-radius-local.html", "blast-radius-public.html"):
    size = (OUT / name).stat().st_size / 1024
    print(f"{name}: {size:.1f} KB")

# quick integrity checks
pub_txt = (OUT / "blast-radius-public.html").read_text()
loc_txt = (OUT / "blast-radius-local.html").read_text()
print("public has tenant-mode panel:", 'id="tenant-mode"' in pub_txt)
print("public has partner-mode panel:", 'id="partner-mode"' in pub_txt)
print("public has single-mode:", 'id="single-mode"' in pub_txt)
print("public has locked buttons:", pub_txt.count('class="locked"'))
print("public banner present:", 'Public build' in pub_txt)
print("local banner present:", 'Offline build' in loc_txt)
print("local has all 3 panels:", all(x in loc_txt for x in ['id="tenant-mode"','id="partner-mode"','id="single-mode"']))
