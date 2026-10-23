// ============================================================================
// Blast Radius — application logic (browser-only, no network calls)
// Single-app mode + whole-tenant export analyzer with transitive takeover paths.
// ============================================================================
"use strict";

// ---- null-safe DOM helpers (so the public build can omit tenant/partner UI) ----
const $id = id => document.getElementById(id);
const on = (id, ev, fn) => { const el = $id(id); if (el) el.addEventListener(ev, fn); };
const has = id => !!$id(id);

// ---- shared utilities (kept here so they survive public-build stripping) ----
function escapeHtml(s){ return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function dedupBy(arr, keyFn){ const seen=new Set(); return arr.filter(x=>{const k=keyFn(x); if(seen.has(k))return false; seen.add(k); return true;}); }

// ---- lookup maps ----
const PERM_BY_ID   = Object.fromEntries(PERMISSIONS.map(p => [p.id.toLowerCase(), p]));
const PERM_BY_GUID = Object.fromEntries(PERMISSIONS.filter(p=>p.guid).map(p => [p.guid.toLowerCase(), p]));
const ROLE_BY_ID   = Object.fromEntries(ROLES.map(r => [r.id.toLowerCase(), r]));

// well-known Entra role template IDs -> our role display names (for raw exports)
const ROLE_TEMPLATE = {
  "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
  "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
  "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
  "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
  "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
  "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
  "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
  "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
  "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
  "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
  "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
  "fdd7a751-b60b-444a-984c-02652fe8fa1c": "Groups Administrator",
  "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
  "88d8e3e3-8f55-4a1e-953a-9b9898b8876b": "Directory Readers",
  "f2ef992c-3afb-46b9-b7cf-a126ee74c451": "Global Reader",
  "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8": "Partner Tier2 Support",
};

const REACH_LABELS = {
  mail:        { name: "Email", tech: "All mailboxes (read/write/send)", biz: "Every inbox in the company, including executives and finance." },
  files:       { name: "Files", tech: "OneDrive & SharePoint files", biz: "Shared files and documents across the business." },
  "files-scoped":{ name: "Files (scoped)", tech: "Only explicitly granted sites", biz: "Only the specific sites an admin named." },
  teams:       { name: "Teams", tech: "Teams chats & messages", biz: "Private Teams conversations." },
  directory:   { name: "Directory", tech: "Users, groups, apps, roles", biz: "The company's list of people, groups and apps." },
  users:       { name: "Users", tech: "User profiles", biz: "Staff account details." },
  groups:      { name: "Groups", tech: "Group membership", biz: "Who belongs to which group." },
  apps:        { name: "Apps", tech: "Application objects", biz: "Other connected apps." },
  roles:       { name: "Admin roles", tech: "Role assignments", biz: "Who gets to be an administrator." },
  "app-permissions": { name: "App permissions", tech: "Permission grants", biz: "What other apps are allowed to do." },
  "app-credentials": { name: "App credentials", tech: "Secrets & certificates on apps", biz: "The passwords other apps use to log in." },
  "auth-methods":{ name: "Sign-in methods", tech: "Everyone's MFA / auth methods", biz: "How people prove who they are when logging in." },
  policy:      { name: "Security policies", tech: "Conditional Access rules", biz: "The rules that decide who can sign in and how." },
  devices:     { name: "Managed devices", tech: "Intune device config / scripts", biz: "Company laptops and phones — can push software or scripts to them." },
  federation:  { name: "Federation/domains", tech: "Domains & trust config", biz: "The trust settings that verify every login." },
  self:        { name: "Self", tech: "Own profile only", biz: "Just the signed-in user's own basic profile." },
};
const HOT_REACH = new Set(["roles","app-permissions","app-credentials","auth-methods","policy","federation","devices"]);

// ---- state ----
let selected = new Set();
let inputMode = "pick";
let audience = "tech";
let ctrlSort = "effort";
let scope = "single";             // "single" | "tenant" | "partner"
let tenantData = null;            // parsed tenant analysis
let singleData = null;            // last single-app analysis
let appSort = "risk";
let reportBrand = { preparedFor: "", preparedBy: "", title: "" };

// ============================================================================
// SHARED ANALYSIS ENGINE
// ============================================================================
function analyzeApp(perms, roles, appType) {
  const all = [...perms, ...roles];
  let sev = "none";
  const directReasons = [], condReasons = [];
  all.forEach(item => {
    if (item.escalation === "direct") directReasons.push(item);
    else if (item.escalation === "conditional") condReasons.push(item);
  });
  if (directReasons.length) sev = "direct";
  else if (condReasons.length) sev = "conditional";

  const reads = new Set(), writes = new Set();
  perms.forEach(p => { (p.canRead||[]).forEach(r => reads.add(r)); (p.canWrite||[]).forEach(w => writes.add(w)); });
  roles.forEach(r => { if (r.tier === 1) ["directory","users","groups","apps","roles","mail","files"].forEach(x => { reads.add(x); writes.add(x); }); });

  const hasStealthyRead = perms.some(p => (p.tags||[]).includes("stealthy") || (p.tags||[]).includes("directory-read"));
  return { appType, perms, roles, all, sev, directReasons, condReasons, reads, writes, hasStealthyRead };
}

function resolvePerm(token) {
  if (!token) return null;
  const t = String(token).trim().toLowerCase();
  return PERM_BY_ID[t] || PERM_BY_GUID[t] || null;
}
function resolveRole(token) {
  if (!token) return null;
  const t = String(token).trim().toLowerCase();
  if (ROLE_BY_ID[t]) return ROLE_BY_ID[t];
  const mapped = ROLE_TEMPLATE[t];                 // template GUID -> name
  if (mapped) return ROLE_BY_ID[mapped.toLowerCase()] || null;
  return null;
}

// ============================================================================
// SINGLE-APP: input rendering
// ============================================================================
function renderPresets() {
  const host = document.getElementById("presets");
  host.innerHTML = "";
  VENDOR_PRESETS.forEach((pre, i) => {
    const b = document.createElement("button");
    b.className = "preset-chip";
    b.textContent = pre.name;
    b.title = pre.desc;
    b.addEventListener("click", () => applyPreset(i));
    host.appendChild(b);
  });
}
function applyPreset(i) {
  const pre = VENDOR_PRESETS[i];
  selected = new Set([...pre.permissions, ...pre.roles].map(s => s.toLowerCase()));
  document.querySelector(`input[name=apptype][value="${pre.appType}"]`).checked = true;
  renderPickList(); renderTray();
}
function allItems() {
  return [
    ...PERMISSIONS.map(p => ({ kind: "perm", id: p.id, label: p.label, api: p.api, tier: p.tier })),
    ...ROLES.map(r => ({ kind: "role", id: r.id, label: r.plain.slice(0, 60), api: "Entra role", tier: r.tier })),
  ];
}
function renderPickList() {
  const q = document.getElementById("search").value.trim().toLowerCase();
  const host = document.getElementById("picklist");
  host.innerHTML = "";
  const items = allItems().filter(it =>
    !q || it.id.toLowerCase().includes(q) || it.label.toLowerCase().includes(q) || it.api.toLowerCase().includes(q));
  if (!items.length) { host.innerHTML = `<div class="pick-item" style="color:var(--text-faint);cursor:default">No match. You can still paste a raw export.</div>`; return; }
  items.forEach(it => {
    const row = document.createElement("label");
    row.className = "pick-item";
    const checked = selected.has(it.id.toLowerCase()) ? "checked" : "";
    row.innerHTML = `<input type="checkbox" ${checked} data-id="${it.id.toLowerCase()}">
      <span><span class="pm">${it.id}</span><span class="pm-api"> · ${it.api}</span></span>
      <span class="pm-dot dot-${it.tier}" title="Tier ${it.tier}"></span>`;
    row.querySelector("input").addEventListener("change", e => {
      if (e.target.checked) selected.add(it.id.toLowerCase()); else selected.delete(it.id.toLowerCase());
      renderTray();
    });
    host.appendChild(row);
  });
}
function renderTray() {
  const host = document.getElementById("tray");
  host.innerHTML = "";
  [...selected].forEach(id => {
    const item = PERM_BY_ID[id] || ROLE_BY_ID[id];
    const label = item ? item.id : id;
    const chip = document.createElement("span");
    chip.className = "tray-chip";
    chip.innerHTML = `<span>${label}</span><button class="x" aria-label="Remove ${label}">×</button>`;
    chip.querySelector(".x").addEventListener("click", () => { selected.delete(id); renderTray(); renderPickList(); });
    host.appendChild(chip);
  });
  document.getElementById("count").textContent = selected.size;
  document.getElementById("analyze").disabled = selected.size === 0;
}

// ---- single-app paste parsing ----
function parsePaste() {
  const text = document.getElementById("paste").value;
  if (!text.trim()) return;
  const found = new Set();
  PERMISSIONS.forEach(p => {
    const re = new RegExp("(^|[^A-Za-z0-9._])" + escapeRe(p.id) + "([^A-Za-z0-9._]|$)", "i");
    if (re.test(text)) { found.add(p.id.toLowerCase()); return; }
    if (p.guid && text.toLowerCase().includes(p.guid.toLowerCase())) found.add(p.id.toLowerCase());
  });
  ROLES.forEach(r => {
    const re = new RegExp("(^|[^A-Za-z])" + escapeRe(r.id) + "([^A-Za-z]|$)", "i");
    if (re.test(text)) found.add(r.id.toLowerCase());
  });
  if (!found.size) { alert("No known permissions or role names were recognized. Add them from 'Pick from list', or use Whole-tenant mode for a full JSON export."); return; }
  found.forEach(f => selected.add(f));
  renderTray(); switchInput("pick"); renderPickList();
}
function escapeRe(s){ return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

// ============================================================================
// SINGLE-APP: analysis + results
// ============================================================================
function analyze() {
  const appType = document.querySelector("input[name=apptype]:checked").value;
  const perms = [...selected].map(id => PERM_BY_ID[id]).filter(Boolean);
  const roles = [...selected].map(id => ROLE_BY_ID[id]).filter(Boolean);
  const a = analyzeApp(perms, roles, appType);
  singleData = a;
  renderResults(a);
  document.getElementById("results").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderResults(a) {
  const R = document.getElementById("results");
  R.innerHTML = "";
  R.appendChild(exportBar("single"));
  R.appendChild(verdictBlock(a));
  R.appendChild(readoutBlock(a));
  R.appendChild(controlsBlock(a));
  if (a.appType === "multi-tenant") R.appendChild(vendorQuestionsBlock());
  R.appendChild(disclaimerBlock());
}

function verdictBlock(a) {
  const el = document.createElement("div");
  el.className = "verdict sev-" + a.sev;
  const cfg = {
    direct:      { badge: "YES — DIRECT", title: "This app can take over the tenant.",
                   sub: "One or more permissions lead to Global Administrator (or equivalent) in a step or two, on their own." },
    conditional: { badge: "YES — CONDITIONAL", title: "This app can likely take over the tenant.",
                   sub: "Escalation is possible, but it depends on what else exists in the tenant (other apps, role-assignable groups)." },
    none:        { badge: "NO KNOWN PATH", title: "No known takeover path from these permissions.",
                   sub: "Nothing here maps to a known Global Admin escalation. That is not the same as “safe” — reach can still be large." },
  }[a.sev];
  let why = "";
  const reasons = a.sev === "direct" ? a.directReasons : a.sev === "conditional" ? a.condReasons : [];
  if (reasons.length) {
    why = `<div class="verdict-why">`;
    reasons.slice(0, 6).forEach((r, i) => {
      const cond = r.conditionalOn ? ` <span style="color:var(--text-faint)">(depends on: ${r.conditionalOn})</span>` : "";
      why += `<div class="step"><span class="n">${i+1}</span><span><code>${r.id}</code> — ${r.escalationNote || r.plain}${audience==="tech"?cond:""}</span></div>`;
    });
    why += `</div>`;
  } else if (a.sev === "none") {
    why = `<div class="verdict-why"><div class="step" style="color:var(--text-dim)">
      Re-check whenever you add permissions. The known-path list grows as researchers publish new techniques,
      and a combination of “safe” permissions can still be abused.</div></div>`;
  }
  el.innerHTML = `<div class="verdict-head">
      <span class="verdict-badge">${cfg.badge}</span>
      <div><p class="v-title">${cfg.title}</p><p class="v-sub">${cfg.sub}</p></div>
    </div>${why}`;
  return el;
}

function readoutBlock(a) {
  const el = document.createElement("div");
  el.className = "readout";
  const cats = new Set([...a.reads, ...a.writes]); cats.delete("self");
  const scopeWord = a.appType === "multi-tenant"
    ? `<span class="owner">every tenant this vendor app is installed in</span>`
    : `<span class="owner">this tenant</span>`;
  let worst = "";
  if (a.reads.has("mail")) worst = "read and act on email";
  else if (a.reads.has("files")) worst = "reach shared files";
  else if (a.reads.has("directory")) worst = "map the whole directory";
  const bizLine = a.sev !== "none"
    ? `If this app's credential is stolen, an attacker can act with its full access across ${scopeWord} — and from there escalate to complete control of the tenant, which means resetting staff, reading anything, and locking you out.`
    : `If this app's credential is stolen, an attacker can use its access across ${scopeWord}${worst ? ` to ${worst}` : ""}. No known path to full admin takeover from these permissions, but the data reach below still matters.`;
  const techLine = `App type: <span class="owner">${a.appType}</span>. Worst-case holder of a stolen credential gets app-only access (no user, no MFA prompt) to everything below${a.appType==="multi-tenant" ? ", in every consented tenant" : ""}.`;

  let reachCards = "";
  [...cats].forEach(cat => {
    const lab = REACH_LABELS[cat]; if (!lab) return;
    const canW = a.writes.has(cat), hot = HOT_REACH.has(cat);
    const desc = audience === "tech" ? `${lab.tech}${canW ? " · read+write" : " · read"}` : lab.biz;
    reachCards += `<div class="reach ${hot?"hot":""}"><div class="rn"><span class="ic"></span>${lab.name}</div><div class="rd">${desc}</div></div>`;
  });
  if (!reachCards) reachCards = `<div class="reach"><div class="rn"><span class="ic"></span>Minimal</div><div class="rd">${audience==="tech"?"Own profile / sign-in only":"Just basic sign-in — very low reach."}</div></div>`;

  const vis = [
    { ic: "✓", cls: "yes", label: "Can you see the app sign in from a strange IP?",
      val: audience==="tech" ? "Yes, in service principal sign-in logs — but that tab needs Entra P1 and isn't the default user sign-in view." : "Only if you have the right license turned on (Entra P1)." },
    { ic: a.hasStealthyRead ? "✗" : "~", cls: a.hasStealthyRead ? "no" : "part", label: "Can you see what it read?",
      val: a.hasStealthyRead
        ? (audience==="tech" ? "No. Directory reads via Microsoft Graph leave no audit record at all." : "No — directory look-ups are invisible after the fact.")
        : (audience==="tech" ? "Partly. Some data reads aren't logged; mailbox/file access may appear in unified audit if enabled." : "Partly, at best.") },
    { ic: "~", cls: "part", label: "How far back can you look?",
      val: audience==="tech" ? "Default Entra log retention is short (7–30 days). Longer needs P1 + Log Analytics/SIEM export." : "Usually only a few weeks unless you pay to keep logs longer." },
  ];
  const visRows = vis.map(v => `<div class="vis-row"><span class="vic ${v.cls}">${v.ic}</span><span><b style="color:var(--text)">${v.label}</b> ${v.val}</span></div>`).join("");

  el.innerHTML = `<h3>Blast radius</h3>
    <p class="sum biz-only">${bizLine}</p>
    <p class="sum tech-only">${techLine}</p>
    <div class="reach-grid">${reachCards}</div>
    <div class="visibility"><div class="vt">Would you even notice? Detection reach with typical licensing</div>${visRows}</div>`;
  return el;
}

function controlsBlock(a) {
  const el = document.createElement("div");
  el.className = "controls-sec";
  const isVendor = a.appType === "multi-tenant";
  let list = CONTROLS.filter(c => isVendor ? c.appliesVendor : c.appliesSingle);
  let notApplicable = CONTROLS.filter(c => isVendor ? !c.appliesVendor : !c.appliesSingle);
  const sorters = {
    effort: (x,y) => x.effort - y.effort || licRank(x.license) - licRank(y.license),
    license: (x,y) => licRank(x.license) - licRank(y.license) || x.effort - y.effort,
    stops: (x,y) => stopRank(x.stops) - stopRank(y.stops) || x.effort - y.effort,
  };
  list.sort(sorters[ctrlSort]);
  let rows = list.map(c => ctrlRow(c, false)).join("");
  let naRows = notApplicable.length
    ? `<div style="margin-top:16px;font-size:12.5px;color:var(--text-faint);font-weight:600">Won't help for a ${isVendor?"vendor":"single-tenant"} app like this:</div>` +
      notApplicable.sort(sorters.effort).map(c => ctrlRow(c, true)).join("") : "";
  el.innerHTML = `<h3>Compensating controls</h3>
    <p class="csub">Ranked for a <b style="color:var(--text)">${isVendor ? "vendor (multi-tenant)" : "single-tenant"}</b> app. Tap any control for the how and the catch.</p>
    <div class="ctrl-filters"><span class="fl">Sort by:</span>
      <button class="sortbtn" data-sort="effort" aria-pressed="${ctrlSort==='effort'}">Least effort</button>
      <button class="sortbtn" data-sort="license" aria-pressed="${ctrlSort==='license'}">Lowest license</button>
      <button class="sortbtn" data-sort="stops" aria-pressed="${ctrlSort==='stops'}">Strongest (prevents first)</button>
    </div>${rows}${naRows}`;
  el.querySelectorAll(".sortbtn").forEach(b => b.addEventListener("click", () => {
    ctrlSort = b.dataset.sort; renderResults(a);
    document.querySelector(".controls-sec").scrollIntoView({ behavior:"smooth", block:"start" });
  }));
  wireCollapsers(el, ".ctrl-head", ".ctrl");
  return el;
}
function ctrlRow(c, na) {
  const licClass = c.license === "Free" ? "Free" : c.license.includes("P1") ? "P1" : c.license.includes("P2") ? "P2" : "WID";
  const licLabel = c.license === "Workload ID Premium" ? "Workload ID Prem" : c.license;
  const effortLabel = ["", "toggle", "quick", "moderate", "project"][c.effort];
  return `<div class="ctrl"><div class="ctrl-head" role="button" aria-expanded="false">
      <span class="chev">▸</span><span class="ctrl-name">${c.name}</span>
      <span class="ctrl-meta">
        <span class="tag tag-effort">${effortLabel}</span>
        <span class="tag tag-lic-${licClass}">${licLabel}</span>
        <span class="tag tag-stops-${c.stops}">${c.stops}</span>
      </span></div>
    <div class="ctrl-detail">${c.detail}${na ? `<div class="na-note">Does not apply to this app type.</div>` : ""}</div></div>`;
}
function licRank(l){ return l==="Free"?0 : l.includes("P1")?1 : l.includes("P2")?2 : 3; }
function stopRank(s){ return s==="Prevents"?0 : s==="Limits"?1 : 2; }

function vendorQuestionsBlock() {
  const el = document.createElement("div");
  el.className = "vq";
  el.innerHTML = `<h3>Before you consent: ask the vendor</h3>
    <p class="vqs">You're about to trust this vendor's credential hygiene across your tenants. A stolen secret on their side is something you cannot rotate. Get these answers in writing first.</p>
    <ul>${VENDOR_QUESTIONS.map(q => `<li>${q}</li>`).join("")}</ul>`;
  return el;
}
function disclaimerBlock() {
  const el = document.createElement("div");
  el.className = "disclaimer";
  el.innerHTML = `<b>Read this.</b> This is a reasoning aid, not an audit. The escalation logic is built from public research
    (SpecterOps/BloodHound, Horizon3, Maester, Emilien Socchi's azure-tiering) and Microsoft's permission docs, and it only
    knows the paths in its knowledge base (v${KB_VERSION}). “No known path” means nothing in that list matched — never that an
    app is safe. Real blast radius also depends on objects this tool can't always see (role-assignable groups, app ownership,
    Azure RBAC, GDAP). Verify against your tenant and current Microsoft documentation before making decisions. A backup or
    management app legitimately needs broad access — the goal is informed acceptance with controls in place, not panic.`;
  return el;
}

// <<<STRIP-PUBLIC-START>>> tenant + partner engine and rendering (full build only)
// ============================================================================
// TENANT MODE: normalize an export into a uniform shape
// ============================================================================
function normalizeTenant(raw) {
  let obj;
  try { obj = typeof raw === "string" ? JSON.parse(raw) : raw; }
  catch (e) { throw new Error("That isn't valid JSON. Check you copied the whole export."); }

  const tenantId = obj.tenantId || obj.tenant || null;
  let list = obj.servicePrincipals || obj.value || (Array.isArray(obj) ? obj : null);
  if (!list) throw new Error("Couldn't find a service-principal list. Expected a 'servicePrincipals' array (from the script) or a raw Graph list.");
  if (!Array.isArray(list)) throw new Error("The service-principal collection isn't an array.");

  const sps = list.map(sp => {
    // permissions: clean 'appRoles' (strings) OR raw 'appRoleAssignments' (appRoleId GUIDs)
    let permTokens = [];
    if (Array.isArray(sp.appRoles) && typeof sp.appRoles[0] === "string") permTokens = sp.appRoles.slice();
    else if (Array.isArray(sp.appRoleAssignments)) permTokens = sp.appRoleAssignments.map(a => a.appRoleId || a.value || a).filter(Boolean);
    if (Array.isArray(sp.applicationPermissions)) permTokens = permTokens.concat(sp.applicationPermissions);

    // delegated: clean 'delegatedScopes' OR raw oauth2PermissionGrants {scope}
    let delegTokens = [];
    if (Array.isArray(sp.delegatedScopes)) delegTokens = sp.delegatedScopes.slice();
    else if (Array.isArray(sp.oauth2PermissionGrants)) sp.oauth2PermissionGrants.forEach(g => { if (g.scope) delegTokens.push(...String(g.scope).split(/\s+/)); });

    // directory roles (ACTIVE): clean 'directoryRoles' names OR raw role assignment objects
    let roleTokens = [];
    if (Array.isArray(sp.directoryRoles)) roleTokens = sp.directoryRoles.slice();
    else if (Array.isArray(sp.roles)) roleTokens = sp.roles.slice();
    else if (Array.isArray(sp.roleAssignments)) roleTokens = sp.roleAssignments.map(r => r.roleDefinitionId || r.displayName || r).filter(Boolean);
    // PIM-ELIGIBLE roles (not active until activated — a gated, logged step)
    let eligibleRoleTokens = [];
    if (Array.isArray(sp.eligibleRoles)) eligibleRoleTokens = sp.eligibleRoles.slice();
    else if (Array.isArray(sp.roleEligibilitySchedules)) eligibleRoleTokens = sp.roleEligibilitySchedules.map(r => r.roleDefinitionId || r.displayName || r).filter(Boolean);

    // credentials — carry a `source` ("application" | "servicePrincipal") when present
    const normCred = (c, src) => (typeof c === "object" ? { ...c, source: c.source || c.src || src } : c);
    const keyCreds = (sp.keyCredentials || []).map(c => normCred(c, undefined));
    const pwCreds  = (sp.passwordCredentials || []).map(c => normCred(c, undefined));
    const ownedAppIds = sp.ownedApps || sp.ownedApplications || [];
    // owners of THIS sp/app — may be id strings or {id,type,displayName}
    const owners = (sp.owners || []).map(o => {
      if (o && typeof o === "object") return { id: o.id || o.objectId || null, type: (o.type || o.principalType || (/servicePrincipal|application/i.test(o["@odata.type"]||"") ? "servicePrincipal" : "user")), name: o.displayName || o.name || null };
      return { id: o, type: null, name: null };
    }).filter(o => o.id);
    // group edges: which groups this SP is a member of / owns (by group id)
    const memberOf = (sp.memberOf || sp.groupMemberships || []).map(g => (g && g.id) ? g.id : g).filter(Boolean);
    const ownsGroups = (sp.ownedGroups || []).map(g => (g && g.id) ? g.id : g).filter(Boolean);

    // app type: explicit, else infer from appOwnerOrganizationId vs this tenant
    let appType = sp.appType;
    const ownerOrg = sp.appOwnerOrganizationId || sp.publisherTenantId;
    const external = ownerOrg && tenantId ? (ownerOrg.toLowerCase() !== String(tenantId).toLowerCase()) : null;
    if (!appType) {
      if (external === true) appType = "multi-tenant";
      else if (external === false) appType = "single-tenant";
      else if (sp.signInAudience && /multipleorgs|azureadandpersonal/i.test(sp.signInAudience)) appType = "multi-tenant";
      else appType = "single-tenant";
    }

    return {
      id: sp.id || sp.objectId || null,
      appId: sp.appId || sp.applicationId || null,
      name: sp.displayName || sp.appDisplayName || "(unnamed app)",
      enabled: sp.accountEnabled !== false,
      appType,
      external: external === true,
      ownerOrg: ownerOrg || null,
      permTokens, delegTokens, roleTokens, eligibleRoleTokens, owners, ownedAppIds,
      memberOf, ownsGroups,
      keyCreds, pwCreds,
    };
  });

  // tenant-level groups (optional). Each: id, displayName, isAssignableToRole,
  // roles (directory roles the group holds), members[], owners[].
  const groups = (obj.groups || []).map(g => ({
    id: g.id || g.objectId || null,
    name: g.displayName || "(unnamed group)",
    roleAssignable: !!(g.isAssignableToRole),
    roleTokens: (g.directoryRoles || g.roles || g.assignedRoles || []).slice(),
    members: (g.members || []).map(m => (m && m.id) ? m.id : m).filter(Boolean),
    owners: (g.owners || []).map(o => (o && o.id) ? o.id : o).filter(Boolean),
  }));

  return { tenantId, generatedAt: obj.generatedAt || null, sps, groups };
}

// ============================================================================
// TENANT MODE: analyze all apps + transitive takeover propagation
// ============================================================================
function analyzeTenant(raw, opts) {
  const { tenantId, generatedAt, sps, groups } = normalizeTenant(raw);
  const now = Date.now();
  const haveGroupData = Array.isArray(groups) && groups.length > 0;
  const sinceTs = (opts && opts.since) ? Date.parse(opts.since) : null;

  // ---- evaluate each group's privilege level ----
  // Reality: ONLY role-assignable groups can hold Entra directory roles. A group
  // that carries a direct-escalation role is "role-privileged". Such a group's
  // membership can be changed ONLY by RoleManagement.ReadWrite.Directory (already
  // a direct GA escalator) or by an existing owner/member — never by plain
  // Group.ReadWrite.All (Microsoft protects role-assignable groups).
  const groupById = {};
  (groups || []).forEach(g => {
    g.roleObjs = (g.roleTokens || []).map(resolveRole).filter(Boolean);
    // directory roles only take effect on role-assignable groups
    g.rolePrivileged = g.roleAssignable && g.roleObjs.some(r => r.escalation === "direct");
    g.condRolePrivileged = g.roleAssignable && g.roleObjs.some(r => r.escalation === "conditional");
    if (g.id) groupById[g.id] = g;
  });

  sps.forEach(sp => {
    sp.perms = [...new Set(sp.permTokens.concat(sp.delegTokens))].map(resolvePerm).filter(Boolean);
    sp.roleObjs = sp.roleTokens.map(resolveRole).filter(Boolean);
    sp.roleObjsEligible = dedupBy((sp.eligibleRoleTokens||[]).map(resolveRole).filter(Boolean), r => r.id);
    sp.perms = dedupBy(sp.perms, p => p.id);
    sp.roleObjs = dedupBy(sp.roleObjs, r => r.id);
    sp.unknownCount = (sp.permTokens.length + sp.delegTokens.length) - sp.perms.length;
    sp.analysis = analyzeApp(sp.perms, sp.roleObjs, sp.appType);

    const permIds = new Set(sp.perms.map(p => p.id));
    const roleIds = new Set(sp.roleObjs.map(r => r.id));

    // PIM-eligible direct role = can reach GA, but only via a gated, logged activation.
    // Modeled as its own state so the control (PIM) is rewarded, not erased.
    sp.pimEligibleGA = sp.roleObjsEligible.some(r => r.escalation === "direct");

    // ---- group-write capability (BloodHound post-processing rules) ----
    // Plain group-write perms reach ONLY non-role-assignable groups.
    sp.canWriteOpenGroups =
      permIds.has("Group.ReadWrite.All") || permIds.has("GroupMember.ReadWrite.All") ||
      permIds.has("Directory.ReadWrite.All") ||
      roleIds.has("Groups Administrator") || roleIds.has("User Administrator");
    // RoleManagement.ReadWrite.Directory reaches ALL groups incl. role-assignable
    // (but it's already a direct GA escalator, so it doesn't need the group path).

    // ---- existing membership / ownership of a role-privileged group ----
    // Membership => already inherits the role. Ownership => can add itself as a
    // member (owners may manage role-assignable group membership).
    // Resolve from BOTH sides: edges on the SP (memberOf/ownsGroups) and edges
    // on the group (members/owners), matching this SP by object id OR appId —
    // real exports put membership on the group object.
    const idMatch = (edgeId) => edgeId === sp.id || (sp.appId && edgeId === sp.appId);
    const spMemberGroups = (sp.memberOf || []).map(id => groupById[id]).filter(Boolean)
      .concat((groups || []).filter(g => (g.members || []).some(idMatch)));
    const spOwnsGroups = (sp.ownsGroups || []).map(id => groupById[id]).filter(Boolean)
      .concat((groups || []).filter(g => (g.owners || []).some(idMatch)));
    sp.memberPrivGroup = spMemberGroups.find(g => g && g.rolePrivileged) || null;
    sp.ownsPrivGroup   = spOwnsGroups.find(g => g && g.rolePrivileged) || null;

    // base: reaches Global Admin on its own (tenant-independent + already-held group roles)?
    sp.baseGA = sp.analysis.sev === "direct"
      || permIds.has("AppRoleAssignment.ReadWrite.All")
      || !!sp.memberPrivGroup                  // already a member of a GA-carrying group
      || !!sp.ownsPrivGroup;                   // owns a GA-carrying group -> can add itself
    sp.reachesGA = sp.baseGA;
    sp.gaProof = null;
    sp.groupProof = null;
    if (sp.memberPrivGroup) sp.groupProof = { group: sp.memberPrivGroup, how: "is already a member of" };
    else if (sp.ownsPrivGroup) sp.groupProof = { group: sp.ownsPrivGroup, how: "owns (can add itself to)" };

    // app-credential backdoor capability
    sp.canModAll = permIds.has("Application.ReadWrite.All")
      || roleIds.has("Application Administrator") || roleIds.has("Cloud Application Administrator");
    sp.canModOwned = permIds.has("Application.ReadWrite.OwnedBy");

    sp.credFlags = credentialFlags(sp, now, sinceTs);
  });

  const byAppId = {};
  sps.forEach(s => { if (s.appId) byAppId[s.appId] = s; });

  // ---- ownership paths INTO each app ----
  // Owners of an app can add a credential to it and inherit its access. For a
  // privileged (GA-reaching) app this is a real escalation path — but a HUMAN
  // owner is a different risk class (depends on that account's security) from a
  // service-principal owner (a stealable-credential path, like app-backdoor).
  const spByAnyId = {};
  sps.forEach(s => { if (s.id) spByAnyId[s.id] = s; if (s.appId) spByAnyId[s.appId] = s; });

  // Role-privileged groups exist only as role-assignable groups. Plain group-write
  // CANNOT reach them (Microsoft protection), so there's no "open group -> GA" path
  // to confirm from directory-role data. A non-role-assignable group can still grant
  // privilege via app-role or access-package grants, but a service-principal export
  // doesn't carry those — so that residual stays a noted caveat, never a false confirm.
  const rolePrivGroups = (groups || []).filter(g => g.rolePrivileged);

  // Precompute, per SP, the set of apps it OWNS (as an owner principal). An owner
  // can add a credential to the owned app regardless of its own permissions.
  sps.forEach(sp => {
    sp.ownsAppObjs = sps.filter(o => o !== sp && (o.owners||[]).some(ow => ow.id === sp.id || (sp.appId && ow.id === sp.appId)));
  });

  // fixed-point propagation: app-credential backdoor (via Application.ReadWrite.*
  // OR via being a service-principal OWNER of the target app)
  let changed = true, guard = 0;
  while (changed && guard++ < 16) {
    changed = false;
    sps.forEach(sp => {
      if (sp.reachesGA) return;
      let appTargets = [];
      if (sp.canModAll) appTargets = sps.filter(o => o !== sp);
      else if (sp.canModOwned) appTargets = (sp.ownedAppIds || []).map(a => byAppId[a]).filter(Boolean);
      // ownership edge: apps this SP owns, it can backdoor
      appTargets = appTargets.concat(sp.ownsAppObjs || []);
      const appProof = appTargets.find(o => o.reachesGA);
      if (appProof) {
        sp.reachesGA = true; sp.gaProof = appProof;
        if ((sp.ownsAppObjs||[]).includes(appProof) && !sp.canModAll && !sp.canModOwned) sp.gaViaOwnership = true;
        changed = true;
      }
    });
  }

  // Human-owner findings: for each GA-reaching app, surface its HUMAN owners as a
  // distinct (account-security-dependent) path. Service-principal owners are
  // already folded into the propagation above.
  sps.forEach(sp => {
    sp.ownerFindings = [];
    if (sp.reachesGA) {
      (sp.owners||[]).forEach(ow => {
        const ownerSp = ow.id ? spByAnyId[ow.id] : null;
        if (ownerSp) return; // service-principal owner: handled as a backdoor edge
        if (ow.type === "servicePrincipal") return;
        sp.ownerFindings.push({ sev: "med",
          text: `Owned by ${ow.name ? "“"+ow.name+"”" : "a user"}${ow.type?` (${ow.type})`:""}`,
          why: "A human owner can add a credential to this GA-reaching app and inherit it. This path depends on that account's security (MFA, phishing-resistance), a different risk class from a stealable app credential." });
      });
    }
  });

  // final verdict per app
  sps.forEach(sp => {
    if (sp.reachesGA) {
      sp.finalSev = "direct";
      const selfDirect = sp.analysis.sev === "direct" || sp.perms.some(p=>p.id==="AppRoleAssignment.ReadWrite.All");
      // "confirmedViaChain" means proven by the app-credential backdoor path specifically
      sp.confirmedViaChain = !selfDirect && !!sp.gaProof;
      // group-confirmed is tracked separately via sp.groupProof
    } else if (sp.pimEligibleGA) {
      // Can reach GA, but only through a gated, logged PIM activation. Distinct
      // state: verdict is "direct" (it IS a path) but flagged as PIM-gated and
      // scored below a standing assignment, so the control is rewarded.
      sp.finalSev = "direct";
      sp.viaPim = true;
    } else {
      sp.finalSev = sp.analysis.sev;
      // Honest cleared-note: if the ONLY thing making this conditional is a
      // plain group-write permission, group data lets us clear the role-based
      // path — those privileged groups are role-assignable and protected.
      if (sp.finalSev === "conditional" && haveGroupData) {
        const onlyGroupCond = sp.analysis.condReasons.length > 0 &&
          sp.analysis.condReasons.every(r => (r.tags||[]).includes("group-write"));
        if (onlyGroupCond && sp.canWriteOpenGroups) {
          const n = rolePrivGroups.length;
          sp.groupCleared = n
            ? `Group data reviewed: the ${n} privileged group${n>1?"s":""} in this tenant ${n>1?"are":"is"} role-assignable, which plain group-write cannot modify. No confirmed directory-role path. (A non-role-assignable group could still grant access via app-role or access-package assignments — not captured in this export.)`
            : `Group data reviewed: no group in this tenant carries a privileged directory role. (A non-role-assignable group could still grant access via app-role or access-package assignments — not captured in this export.)`;
        }
      }
    }
    sp.riskScore = scoreApp(sp);
  });

  // rollup
  const roll = {
    total: sps.length,
    enabled: sps.filter(s => s.enabled).length,
    disabled: sps.filter(s => !s.enabled).length,
    vendor: sps.filter(s => s.appType === "multi-tenant").length,
    own: sps.filter(s => s.appType === "single-tenant").length,
    ga: sps.filter(s => s.finalSev === "direct").length,
    gaChained: sps.filter(s => s.confirmedViaChain || (s.groupProof && s.groupProof.how.startsWith("owns"))).length,
    conditional: sps.filter(s => s.finalSev === "conditional").length,
    withRoles: sps.filter(s => s.roleObjs.length).length,
    suspCreds: sps.filter(s => s.credFlags.length).length,
    gaViaGroup: sps.filter(s => s.reachesGA && s.groupProof).length,
    cleared: sps.filter(s => s.groupCleared).length,
    pimGa: sps.filter(s => s.viaPim).length,
    crossTenantCreds: sps.filter(s => (s.credFlags||[]).some(f => /externally-owned|Microsoft first-party/.test(f.text))).length,
    changedSince: sps.reduce((n, s) => n + (s.credFlags||[]).filter(f => /after the review date/.test(f.text)).length, 0),
    haveGroupData,
    groupCount: (groups || []).length,
    privGroups: (groups || []).filter(g => g.rolePrivileged).length,
  };

  return { tenantId, generatedAt, sps, roll, byAppId, groups: groups || [], haveGroupData };
}

// Returns an array of { text, sev, why } flags. sev: "high" | "med".
// Each flag states WHY it fired so a reviewer can judge or overrule it.
function credentialFlags(sp, now, sinceTs) {
  const flags = [];
  // each credential may carry a `source`: "application" (on the app registration)
  // or "servicePrincipal" (on the SP). Cleanup differs, so we surface it.
  const tag = (c, kind) => ({ ...c, kind, src: c.source || c.src || c.Source || null });
  const all = [
    ...(sp.keyCreds||[]).map(c => tag(c, "certificate")),
    ...(sp.pwCreds||[]).map(c => tag(c, "secret")),
  ];

  // --- Cross-tenant credential: the SkyKick persistence pattern in one rule ---
  // A credential sitting on an externally-owned (vendor) service principal in YOUR
  // tenant is abnormal: the vendor's credential normally lives in the vendor's
  // tenant. Microsoft first-party is expected; an explicit allowlist can overrule.
  if (all.length && sp.external && sp.ownerOrg) {
    const org = String(sp.ownerOrg).toLowerCase();
    const isMs = org === MICROSOFT_FIRST_PARTY_TENANT;
    const alEntry = (typeof CROSS_TENANT_CRED_ALLOWLIST !== "undefined" ? CROSS_TENANT_CRED_ALLOWLIST : [])
      .find(e => (e.ownerOrg && e.ownerOrg.toLowerCase() === org) || (e.appId && sp.appId && e.appId.toLowerCase() === String(sp.appId).toLowerCase()));
    if (!isMs && !alEntry) {
      flags.push({ sev: "high",
        text: `Tenant-side credential on a vendor (externally-owned) app`,
        why: `This service principal is owned by another tenant (${escapeHtml(String(sp.ownerOrg))}), yet carries ${all.length} credential(s) in yours. Vendor credentials normally live in the vendor's tenant — a credential here matches the known persistence pattern (attacker-planted secret). Review and remove if you did not create it.` });
    } else if (alEntry) {
      flags.push({ sev: "med",
        text: `Cross-tenant credential — allowlisted`,
        why: `A tenant-side credential on this external app would normally flag, but it is on the allowlist: "${escapeHtml(alEntry.reason||"no reason given")}". Re-confirm this is still intended.` });
    }
  }

  if (all.length > 3) flags.push({ sev: "med", text: `${all.length} credentials on this app`, why: "Multiple credentials widen the attack surface and make rotation/cleanup harder." });

  all.forEach(c => {
    const sVal = c.startDateTime || c.StartDateTime;
    const eVal = c.endDateTime || c.EndDateTime;
    const start = sVal ? Date.parse(sVal) : null;
    const end = eVal ? Date.parse(eVal) : null;
    const src = c.src || c.source || c.Source;
    const srcLabel = src === "application" ? " on the app registration" : src === "servicePrincipal" ? " on the service principal" : "";
    if (start && end) {
      const years = (end - start) / (365.25 * 864e5);
      const cName = c.displayName || c.DisplayName;
      if (years > 2) flags.push({ sev: "med",
        text: `Long-lived ${c.kind} (${years.toFixed(1)} yr)${cName ? ' “'+escapeHtml(cName)+'”' : ""}`,
        why: `A multi-year credential${srcLabel} is ideal for persistence; short lifetimes limit a stolen secret's window.` });
    }
    if (start && now && start > now - 14 * 864e5) flags.push({ sev: "med",
      text: `${c.kind} added in the last 14 days${srcLabel}`,
      why: "Recently-added credentials deserve a look — confirm you (not an attacker) created it." });
    // "changes since" filter: credentials created after the chosen date
    if (sinceTs && start && start >= sinceTs) flags.push({ sev: "high",
      text: `${c.kind} created after the review date${srcLabel}`,
      why: `This credential's start date is on/after the date you set — it is a candidate for "what changed since" review.` });
  });

  if (sp.ownerOrg && String(sp.ownerOrg).toLowerCase() === MICROSOFT_FIRST_PARTY_TENANT && all.length)
    flags.push({ sev: "high", text: "Credential on a Microsoft first-party app", why: "Customers essentially never add their own credential to a Microsoft-owned service principal. This is highly unusual and worth investigating." });

  // de-dup by text
  const seen = new Set();
  return flags.filter(f => { if (seen.has(f.text)) return false; seen.add(f.text); return true; });
}

function scoreApp(sp) {
  let s = 0;
  if (sp.finalSev === "direct") s += sp.viaPim ? 70 : 100;   // PIM-gated GA ranks below standing GA
  else if (sp.finalSev === "conditional") s += 50;
  if (sp.confirmedViaChain) s += 10;
  if (sp.gaViaOwnership) s += 8;
  if (sp.groupProof) s += 12;
  if (sp.groupCleared) s -= 25;   // demonstrably not a takeover path -> lower priority
  if (sp.roleObjs.some(r => r.escalation === "direct")) s += 20;
  if (sp.appType === "multi-tenant") s += 8;          // vendor apps: credential you can't rotate
  const highFlags = (sp.credFlags||[]).filter(f => f.sev === "high").length;
  s += highFlags * 25 + ((sp.credFlags||[]).length - highFlags) * 8;
  if (sp.ownerFindings && sp.ownerFindings.length) s += 6;
  if (sp.analysis.writes.size) s += sp.analysis.writes.size;
  if (!sp.enabled) s -= 30;                            // disabled apps are lower priority
  return s;
}

// ============================================================================
// TENANT MODE: rendering
// ============================================================================
function renderTenant(data) {
  tenantData = data;
  const R = document.getElementById("tenant-results");
  R.innerHTML = "";
  R.appendChild(exportBar("tenant"));
  R.appendChild(rollupBlock(data));
  R.appendChild(appListBlock(data));
  R.appendChild(disclaimerBlock());
  R.scrollIntoView({ behavior: "smooth", block: "start" });
}

function rollupBlock(d) {
  const el = document.createElement("div");
  el.className = "rollup";
  const r = d.roll;
  const stat = (num, lbl, cls="") => `<div class="stat ${cls}"><div class="num">${num}</div><div class="lbl">${lbl}</div></div>`;
  const meta = d.generatedAt ? `exported ${new Date(d.generatedAt).toLocaleString()}` : "";
  const groupStats = r.haveGroupData
    ? `${stat(r.gaViaGroup, "reach GA via a group", r.gaViaGroup ? "alarm" : "")}
       ${stat(r.privGroups, "privileged groups", r.privGroups ? "warn" : "")}
       ${stat(r.cleared, "conditionals cleared by group data", r.cleared ? "" : "")}`
    : "";
  const groupNote = r.haveGroupData
    ? `<p class="rsub" style="margin-top:14px;color:var(--contained)">Group data included (${r.groupCount} groups): membership and role-assignable-group paths were resolved, so group-based conditionals are now confirmed or cleared.</p>`
    : `<p class="rsub" style="margin-top:14px;color:var(--text-faint)">No group data in this export — group-based escalation stays “conditional (unverified).” Re-run the export script with the group block to resolve those. Role-assignable groups are protected from plain group-write, so many will clear.</p>`;
  const sinceNote = d.since
    ? `<p class="rsub" style="margin-top:10px;color:var(--caution)">“What changed since ${escapeHtml(d.since)}”: ${r.changedSince} credential(s) dated on/after that are flagged on their apps. This only sees items that carry a creation date — a change with no timestamp in the export will not appear here.</p>`
    : "";
  const blindspot = `<div class="blindspot"><span class="bs-ic">◐</span><div><b>What this can't see.</b> It reasons only from what's in the export: it doesn't log in, confirm activity, or capture app-role/access-package grants on non-role-assignable groups or Azure RBAC. “No known path” means nothing in the knowledge base matched for the data provided — not that an app is safe.</div></div>`;
  el.innerHTML = `<h3>Tenant rollup</h3>
    <p class="rsub">${r.total} apps analyzed${d.tenantId ? ` in tenant ${d.tenantId}` : ""}. ${meta}</p>
    <div class="stat-grid">
      ${stat(r.ga, "can reach Global Admin", r.ga ? "alarm" : "")}
      ${stat(r.gaChained, "only via a backdoor/group chain", r.gaChained ? "alarm" : "")}
      ${stat(r.pimGa, "GA via PIM activation (gated)", r.pimGa ? "warn" : "")}
      ${stat(r.crossTenantCreds, "cross-tenant credentials", r.crossTenantCreds ? "alarm" : "")}
      ${stat(r.conditional, "conditional (unverified)", r.conditional ? "warn" : "")}
      ${stat(r.withRoles, "hold a directory role", r.withRoles ? "warn" : "")}
      ${stat(r.suspCreds, "credential concerns", r.suspCreds ? "warn" : "")}
      ${groupStats}
      ${stat(r.vendor, "vendor (multi-tenant)")}
      ${stat(r.own, "your own apps")}
      ${stat(r.disabled, "disabled")}
    </div>${groupNote}${sinceNote}${blindspot}`;
  return el;
}

function appListBlock(d) {
  const el = document.createElement("div");
  el.className = "controls-sec";
  el.innerHTML = `<h3>Apps, ranked by risk</h3>
    <p class="csub">Tap any app to see its blast radius and, where one exists, the exact chain it would walk to Global Admin.</p>
    <div class="app-controls">
      <input class="app-search" id="app-search" placeholder="Filter by name or app ID…" autocomplete="off">
      <span class="fl">Sort:</span>
      <button class="sortbtn" data-asort="risk" aria-pressed="${appSort==='risk'}">Risk</button>
      <button class="sortbtn" data-asort="name" aria-pressed="${appSort==='name'}">Name</button>
      <button class="sortbtn" data-asort="type" aria-pressed="${appSort==='type'}">Vendor first</button>
    </div>
    <div class="app-list" id="app-list"></div>`;
  el.querySelectorAll("[data-asort]").forEach(b => b.addEventListener("click", () => {
    appSort = b.dataset.asort;
    el.querySelectorAll("[data-asort]").forEach(x => x.setAttribute("aria-pressed", x.dataset.asort===appSort));
    paintAppRows(d);
  }));
  el.querySelector("#app-search").addEventListener("input", () => paintAppRows(d));
  // paint after insert
  setTimeout(() => paintAppRows(d), 0);
  return el;
}

function paintAppRows(d) {
  const host = document.getElementById("app-list");
  if (!host) return;
  const q = (document.getElementById("app-search").value || "").trim().toLowerCase();
  let rows = d.sps.filter(sp => !q || sp.name.toLowerCase().includes(q) || (sp.appId||"").toLowerCase().includes(q));
  const sorters = {
    risk: (a,b) => b.riskScore - a.riskScore || a.name.localeCompare(b.name),
    name: (a,b) => a.name.localeCompare(b.name),
    type: (a,b) => (a.appType==="multi-tenant"?0:1) - (b.appType==="multi-tenant"?0:1) || b.riskScore - a.riskScore,
  };
  rows.sort(sorters[appSort]);
  host.innerHTML = rows.map(appRow).join("") || `<div class="empty-state" style="padding:24px">No apps match “${q}”.</div>`;
  wireCollapsers(host, ".app-row-head", ".app-row");
}

function appRow(sp) {
  const sev = sp.finalSev;
  const verdict = sev === "direct" ? (sp.viaPim ? "GA · PIM-GATED" : "GLOBAL ADMIN") : sev === "conditional" ? "CONDITIONAL" : "NO KNOWN PATH";
  const badges = [];
  badges.push(sp.appType === "multi-tenant" ? `<span class="abadge vendor">vendor</span>` : `<span class="abadge own">own app</span>`);
  if (!sp.enabled) badges.push(`<span class="abadge disabled">disabled</span>`);
  if (sp.roleObjs.length) badges.push(`<span class="abadge role">${sp.roleObjs.length} role${sp.roleObjs.length>1?"s":""}</span>`);
  if (sp.viaPim) badges.push(`<span class="abadge pim">PIM-gated</span>`);
  if (sp.gaViaOwnership) badges.push(`<span class="abadge group">via ownership</span>`);
  if (sp.groupProof) badges.push(`<span class="abadge group">via group</span>`);
  if (sp.groupCleared) badges.push(`<span class="abadge cleared">group-cleared</span>`);
  if ((sp.credFlags||[]).some(f => /externally-owned|Microsoft first-party/.test(f.text))) badges.push(`<span class="abadge cred">cross-tenant cred</span>`);
  else if (sp.credFlags.length) badges.push(`<span class="abadge cred">cred flag</span>`);
  if (sp.ownerFindings && sp.ownerFindings.length) badges.push(`<span class="abadge owner">human owner</span>`);

  return `<div class="app-row sev-${sev}">
    <div class="app-row-head" role="button" aria-expanded="false" tabindex="0">
      <span class="app-dot ${sev}"></span>
      <span class="app-id-wrap">
        <div class="app-name">${escapeHtml(sp.name)}</div>
        <div class="app-sub">${sp.appId || "no app id"}</div>
      </span>
      <span class="app-badges">${badges.join("")}</span>
      <span class="app-verdict ${sev}">${verdict}</span>
      <span class="chev">▸</span>
    </div>
    <div class="app-detail">${appDetail(sp)}</div>
  </div>`;
}

function appDetail(sp) {
  let html = "";

  // 1. escalation reasoning / proof chain
  if (sp.finalSev === "direct") {
    html += `<div class="sec-t">Why it can reach Global Admin</div>`;
    if (sp.groupProof) {
      const g = sp.groupProof.group;
      const rnames = (g.roleObjs||[]).map(r=>r.id).join(", ") || "a privileged role";
      html += `<div style="font-size:12.5px;color:var(--text-dim);margin-bottom:10px">Confirmed via group membership — this app ${sp.groupProof.how} a ${g.roleAssignable?"role-assignable ":""}group that holds <code style="font-family:var(--mono);color:var(--text)">${escapeHtml(rnames)}</code>:</div>`;
      html += groupChain(sp);
    } else if (sp.confirmedViaChain && sp.gaProof) {
      html += `<div style="font-size:12.5px;color:var(--text-dim);margin-bottom:10px">Confirmed from this tenant's own data — this app can plant a credential on a more privileged app and inherit it:</div>`;
      html += proofChain(sp);
    } else {
      const reasons = sp.analysis.directReasons.length ? sp.analysis.directReasons
        : sp.perms.filter(p => p.id === "AppRoleAssignment.ReadWrite.All");
      html += `<div style="font-size:12.5px;color:var(--text-dim)">`;
      reasons.slice(0,4).forEach(r => { html += `• <code style="font-family:var(--mono);color:var(--text)">${r.id}</code> — ${r.escalationNote || r.plain}<br>`; });
      if (sp.roleObjs.some(r=>r.escalation==="direct")) sp.roleObjs.filter(r=>r.escalation==="direct").forEach(r => html += `• role <code style="font-family:var(--mono);color:var(--text)">${r.id}</code> — ${r.escalationNote}<br>`);
      html += `</div>`;
    }
  } else if (sp.finalSev === "conditional") {
    html += `<div class="sec-t">Conditional — needs tenant data this export doesn't confirm</div>`;
    html += `<div style="font-size:12.5px;color:var(--text-dim)">`;
    sp.analysis.condReasons.slice(0,4).forEach(r => {
      html += `• <code style="font-family:var(--mono);color:var(--text)">${r.id}</code> — ${r.escalationNote || r.plain}${r.conditionalOn?` <span style="color:var(--text-faint)">(depends on: ${r.conditionalOn})</span>`:""}<br>`;
    });
    html += `</div>`;
    if (sp.groupCleared) html += `<div style="font-size:12px;color:var(--contained);margin-top:8px">✓ ${escapeHtml(sp.groupCleared)}</div>`;
  } else {
    html += `<div class="sec-t">No known takeover path</div>
      <div style="font-size:12.5px;color:var(--text-dim)">Nothing here maps to a known Global Admin escalation. Data reach can still matter — see below.</div>`;
  }

  // 2. reach
  const cats = new Set([...sp.analysis.reads, ...sp.analysis.writes]); cats.delete("self");
  if (cats.size) {
    html += `<div class="sec-t">Data &amp; control it can reach</div><div class="mini-reach">`;
    [...cats].forEach(c => { const lab = REACH_LABELS[c]; if (lab) html += `<span class="mini-chip ${HOT_REACH.has(c)?"hot":""}">${lab.name}</span>`; });
    html += `</div>`;
  }

  // 3. roles (active + PIM-eligible) and owners
  if (sp.roleObjs.length || (sp.roleObjsEligible && sp.roleObjsEligible.length)) {
    html += `<div class="sec-t">Directory roles</div><div class="mini-reach">`;
    sp.roleObjs.forEach(r => html += `<span class="mini-chip ${r.escalation==="direct"?"hot":""}">${escapeHtml(r.id)}</span>`);
    (sp.roleObjsEligible||[]).forEach(r => html += `<span class="mini-chip ${r.escalation==="direct"?"hot":""}" title="Eligible via PIM — requires activation">${escapeHtml(r.id)} · PIM-eligible</span>`);
    html += `</div>`;
    if (sp.viaPim) html += `<div style="font-size:12px;color:var(--caution);margin-top:7px">Reaches Global Admin only by activating a PIM-eligible role — a gated, logged step (often MFA + approval), not standing access. Still a path, but weaker than a standing assignment.</div>`;
  }

  // 3b. ownership paths
  if (sp.ownerFindings && sp.ownerFindings.length) {
    html += `<div class="sec-t">Ownership paths into this app</div>`;
    sp.ownerFindings.forEach(f => html += `<div class="cred-line"><span class="cf" style="color:${f.sev==="high"?"var(--takeover)":"var(--caution)"}">${f.sev==="high"?"!":"~"}</span><span>${escapeHtml(f.text)} <span style="color:var(--text-faint)">— ${escapeHtml(f.why)}</span></span></div>`);
  }

  // 4. credential flags (structured: severity + why)
  if (sp.credFlags.length) {
    html += `<div class="sec-t">Credential hygiene</div>`;
    sp.credFlags.forEach(f => html += `<div class="cred-line"><span class="cf" style="color:${f.sev==="high"?"var(--takeover)":"var(--caution)"}">${f.sev==="high"?"!":"~"}</span><span><b style="color:var(--text)">${escapeHtml(f.text)}</b> <span style="color:var(--text-faint)">— ${escapeHtml(f.why)}</span></span></div>`);
  }

  // 5. permission dump + unknowns
  if (sp.perms.length) {
    html += `<div class="sec-t">Permissions recognized (${sp.perms.length})</div>
      <div class="perm-dump">${sp.perms.map(p => p.id).join(" · ")}</div>`;
  }
  if (sp.unknownCount > 0) {
    html += `<div style="font-size:11.5px;color:var(--text-faint);margin-top:8px">${sp.unknownCount} permission(s) weren't in the knowledge base and were skipped. A full audit should review those too.</div>`;
  }
  return html;
}

function proofChain(sp) {
  // sp --(backdoor)--> proof app --> (its own proof or GA)
  const nodes = [];
  nodes.push({ name: sp.name, why: sp.canModAll ? "can add a credential to any app" : "can add a credential to an app it owns", ga:false });
  let cur = sp.gaProof, guard = 0;
  while (cur && guard++ < 12) {
    const why = cur.baseGA
      ? (cur.analysis.directReasons[0]?.id || "AppRoleAssignment.ReadWrite.All")
      : (cur.canModAll ? "can add a credential to any app" : "backdoors another app");
    nodes.push({ name: cur.name, why, ga: cur.baseGA });
    if (cur.baseGA) break;
    cur = cur.gaProof;
  }
  let html = `<div class="chain">`;
  nodes.forEach((n, i) => {
    html += `<div class="chain-node ${n.ga?"ga":""}"><div class="cn-name">${escapeHtml(n.name)}</div><div class="cn-why">${escapeHtml(n.why)}</div></div>`;
    if (i < nodes.length - 1) html += `<div class="chain-arrow">▶</div>`;
  });
  html += `<div class="chain-arrow">▶</div><div class="chain-node ga"><div class="cn-name">Global Admin</div><div class="cn-why">full tenant takeover</div></div>`;
  html += `</div>`;
  return html;
}

function groupChain(sp) {
  const g = sp.groupProof.group;
  const roleName = (g.roleObjs||[]).find(r=>r.escalation==="direct")?.id || (g.roleObjs||[])[0]?.id || "privileged role";
  let html = `<div class="chain">`;
  html += `<div class="chain-node"><div class="cn-name">${escapeHtml(sp.name)}</div><div class="cn-why">${escapeHtml(sp.groupProof.how)}</div></div>`;
  html += `<div class="chain-arrow">▶</div>`;
  html += `<div class="chain-node"><div class="cn-name">${escapeHtml(g.name)}</div><div class="cn-why">${g.roleAssignable?"role-assignable · ":""}holds ${escapeHtml(roleName)}</div></div>`;
  html += `<div class="chain-arrow">▶</div>`;
  html += `<div class="chain-node ga"><div class="cn-name">Global Admin</div><div class="cn-why">full tenant takeover</div></div>`;
  html += `</div>`;
  return html;
}


// ============================================================================
// PARTNER / MSP MODE: GDAP cross-tenant reach
// ----------------------------------------------------------------------------
// Graph:  partner principal --member of--> partner security group
//         --GDAP access assignment--> Entra roles --scoped into--> customer tenant
// A relationship/assignment granting a direct-escalation role (Global Admin etc.)
// means a partner compromise can fully take over that customer.
// ============================================================================
let partnerData = null;
let custSort = "exposure";

function normalizePartner(raw) {
  let obj;
  try { obj = typeof raw === "string" ? JSON.parse(raw) : raw; }
  catch (e) { throw new Error("That isn't valid JSON. Check you copied the whole export."); }

  const partnerTenantId = obj.partnerTenantId || obj.tenantId || null;

  // GDAP relationships (partner <-> customer), each may carry roles directly
  const rels = (obj.gdapRelationships || obj.delegatedAdminRelationships || obj.relationships || []).map(r => ({
    id: r.id || r.relationshipId || null,
    customerTenantId: r.customerTenantId || (r.customer && (r.customer.tenantId || r.customer.id)) || r.customerId || null,
    customerName: r.customerName || (r.customer && r.customer.displayName) || r.displayName || "(unnamed customer)",
    status: (r.status || r.state || "active").toLowerCase(),
    endDateTime: r.endDateTime || (r.accessDetails && r.accessDetails.endDateTime) || r.expiry || null,
    isLegacyDap: !!(r.isLegacyDap || /dap/i.test(r.relationshipType || "") && !/gdap/i.test(r.relationshipType || "")),
    roleTokens: extractRoleTokens(r),
  }));

  // access assignments: map a security group to roles within a relationship
  const assigns = (obj.accessAssignments || obj.delegatedAdminAccessAssignments || obj.assignments || []).map(a => ({
    relationshipId: a.relationshipId || (a.relationship && a.relationship.id) || a.id || null,
    customerTenantId: a.customerTenantId || null,
    securityGroupId: a.securityGroupId || (a.accessContainer && (a.accessContainer.accessContainerId || a.accessContainer.id)) || a.groupId || null,
    roleTokens: extractRoleTokens(a),
  }));

  const groups = (obj.securityGroups || obj.groups || []).map(g => ({
    id: g.id || g.objectId || null,
    name: g.displayName || "(unnamed group)",
    members: (g.members || []).map(m => (m && m.id) ? m.id : m).filter(Boolean),
  }));

  const principals = (obj.principals || obj.members || []).map(p => ({
    id: p.id || p.objectId || null,
    name: p.displayName || p.name || "(unnamed)",
    type: (p.type || p.principalType || (/servicePrincipal/i.test(p["@odata.type"]||"") ? "servicePrincipal" : "user")),
    mfa: (p.mfa === undefined || p.mfa === null) ? null : !!p.mfa,
  }));

  return { partnerTenantId, generatedAt: obj.generatedAt || null, rels, assigns, groups, principals };
}
function extractRoleTokens(x) {
  // roles can be: ["Global Administrator"], or accessDetails.unifiedRoles [{roleDefinitionId}]
  if (Array.isArray(x.roles) && x.roles.length) return x.roles.slice();
  const ad = x.accessDetails || x;
  if (ad && Array.isArray(ad.unifiedRoles)) return ad.unifiedRoles.map(u => u.roleDefinitionId || u.displayName || u).filter(Boolean);
  if (Array.isArray(x.unifiedRoles)) return x.unifiedRoles.map(u => u.roleDefinitionId || u.displayName || u).filter(Boolean);
  return [];
}

function analyzePartner(raw) {
  const { partnerTenantId, generatedAt, rels, assigns, groups, principals } = normalizePartner(raw);
  const now = Date.now();

  const groupById = {};
  groups.forEach(g => { if (g.id) groupById[g.id] = g; });
  const relById = {};
  rels.forEach(r => { if (r.id) relById[r.id] = r; });

  // worst escalation among a set of role tokens
  const worstOf = (roleTokens) => {
    const roleObjs = roleTokens.map(resolveRole).filter(Boolean);
    let sev = "none";
    if (roleObjs.some(r => r.escalation === "direct")) sev = "direct";
    else if (roleObjs.some(r => r.escalation === "conditional")) sev = "conditional";
    return { sev, roleObjs, roleNames: [...new Set(roleTokens.map(t => { const r = resolveRole(t); return r ? r.id : t; }))] };
  };

  // Build per-customer exposure, and per-group reach.
  // For each assignment: group -> roles -> customer (via its relationship).
  const customers = {};   // customerTenantId -> { name, sev, roles:Set, viaGroups:Set, status, endDateTime, isLegacyDap, rels:Set }
  const groupReach = {};  // groupId -> { name, customers:Map(customerId->{sev,roleNames}), worst }

  const ensureCustomer = (id, name) => {
    if (!customers[id]) customers[id] = { id, name: name || id, sev: "none", roles: new Set(), viaGroups: new Set(), status: "active", endDateTime: null, isLegacyDap: false, relIds: new Set() };
    return customers[id];
  };
  const sevRank = s => s === "direct" ? 2 : s === "conditional" ? 1 : 0;
  const bumpSev = (obj, sev) => { if (sevRank(sev) > sevRank(obj.sev)) obj.sev = sev; };

  // Relationships with roles but no assignment still define what the relationship grants
  // (roles aren't live until mapped to a group, but we surface them as latent exposure).
  rels.forEach(r => {
    if (!r.customerTenantId) return;
    const c = ensureCustomer(r.customerTenantId, r.customerName);
    c.status = r.status; c.endDateTime = r.endDateTime; c.isLegacyDap = c.isLegacyDap || r.isLegacyDap;
    if (r.id) c.relIds.add(r.id);
    if (r.isLegacyDap) { bumpSev(c, "direct"); c.roles.add("Global Administrator (legacy DAP)"); }
  });

  // Access assignments are the live path: group members get these roles in the customer.
  assigns.forEach(a => {
    const rel = a.relationshipId ? relById[a.relationshipId] : null;
    const customerTenantId = a.customerTenantId || (rel && rel.customerTenantId);
    if (!customerTenantId) return;
    const custName = rel ? rel.customerName : customerTenantId;
    const c = ensureCustomer(customerTenantId, custName);
    if (rel) { c.status = rel.status; c.endDateTime = rel.endDateTime; }

    // roles granted by this assignment (fall back to relationship roles)
    const tokens = (a.roleTokens && a.roleTokens.length) ? a.roleTokens : (rel ? rel.roleTokens : []);
    const w = worstOf(tokens);
    bumpSev(c, w.sev);
    w.roleNames.forEach(n => c.roles.add(n));

    const g = a.securityGroupId ? groupById[a.securityGroupId] : null;
    if (g) {
      c.viaGroups.add(g.name);
      if (!groupReach[g.id]) groupReach[g.id] = { id: g.id, name: g.name, members: g.members, customers: new Map(), worst: "none" };
      const gr = groupReach[g.id];
      const prev = gr.customers.get(customerTenantId);
      if (!prev || sevRank(w.sev) > sevRank(prev.sev)) gr.customers.set(customerTenantId, { name: custName, sev: w.sev, roleNames: w.roleNames });
      if (sevRank(w.sev) > sevRank(gr.worst)) gr.worst = w.sev;
    }
  });

  // finalize customers list
  const custList = Object.values(customers).map(c => {
    // expiry classification
    let relstat = c.isLegacyDap ? "dap" : (c.status === "active" ? "active" : c.status);
    if (c.endDateTime) {
      const end = Date.parse(c.endDateTime);
      if (!isNaN(end)) {
        if (end < now) relstat = "expired";
        else if (end < now + 30 * 864e5) relstat = "expiring";
      }
    }
    return { ...c, roles: [...c.roles], viaGroups: [...c.viaGroups], relstat };
  });

  // master keys: groups ranked by (# customers they reach at direct level), then total customers
  const keyList = Object.values(groupReach).map(gr => {
    const custs = [...gr.customers.values()];
    const directCount = custs.filter(x => x.sev === "direct").length;
    const condCount = custs.filter(x => x.sev === "conditional").length;
    // map members -> principals
    const memberNames = (gr.members || []).map(id => {
      const p = principals.find(pp => pp.id === id);
      return p ? `${p.name}${p.type==="servicePrincipal"?" (app)":""}${p.mfa===false?" ⚠no MFA":""}` : id;
    });
    return { id: gr.id, name: gr.name, total: custs.length, directCount, condCount, worst: gr.worst, memberNames, memberCount: (gr.members||[]).length };
  }).sort((a,b) => b.directCount - a.directCount || b.total - a.total);

  const roll = {
    customers: custList.length,
    fullTakeover: custList.filter(c => c.sev === "direct").length,
    partial: custList.filter(c => c.sev === "conditional").length,
    legacyDap: custList.filter(c => c.isLegacyDap).length,
    expired: custList.filter(c => c.relstat === "expired").length,
    expiring: custList.filter(c => c.relstat === "expiring").length,
    masterKeys: keyList.filter(k => k.directCount > 0).length,
    groups: keyList.length,
    gaRelationships: rels.filter(r => worstOf(r.roleTokens).sev === "direct" || r.isLegacyDap).length,
    noMfaMembers: principals.filter(p => p.mfa === false).length,
  };

  return { partnerTenantId, generatedAt, custList, keyList, roll, principals };
}

function renderPartner(data) {
  partnerData = data;
  const R = document.getElementById("partner-results");
  R.innerHTML = "";
  R.appendChild(exportBar("partner"));
  R.appendChild(partnerRollupBlock(data));
  if (data.keyList.length) R.appendChild(masterKeysBlock(data));
  R.appendChild(customersBlock(data));
  R.appendChild(partnerControlsBlock());
  R.appendChild(partnerDisclaimerBlock());
  R.scrollIntoView({ behavior: "smooth", block: "start" });
}

function partnerRollupBlock(d) {
  const el = document.createElement("div");
  el.className = "rollup";
  const r = d.roll;
  const stat = (num, lbl, cls="") => `<div class="stat ${cls}"><div class="num">${num}</div><div class="lbl">${lbl}</div></div>`;
  const meta = d.generatedAt ? `exported ${new Date(d.generatedAt).toLocaleString()}` : "";
  el.innerHTML = `<h3>Partner cross-tenant reach</h3>
    <p class="rsub">${r.customers} customer tenant${r.customers===1?"":"s"} reachable from this partner${d.partnerTenantId ? ` (${d.partnerTenantId})` : ""}. ${meta}</p>
    <div class="stat-grid">
      ${stat(r.fullTakeover, "customers fully takeable (GA-equiv reachable)", r.fullTakeover ? "alarm" : "")}
      ${stat(r.legacyDap, "legacy DAP (standing GA)", r.legacyDap ? "alarm" : "")}
      ${stat(r.masterKeys, "master-key groups", r.masterKeys ? "alarm" : "")}
      ${stat(r.partial, "partial (scoped roles)", r.partial ? "warn" : "")}
      ${stat(r.gaRelationships, "relationships granting GA", r.gaRelationships ? "warn" : "")}
      ${stat(r.expired, "expired relationships", r.expired ? "warn" : "")}
      ${stat(r.expiring, "expiring < 30 days", r.expiring ? "warn" : "")}
      ${stat(r.noMfaMembers, "admins without MFA", r.noMfaMembers ? "alarm" : "")}
    </div>
    <p class="rsub" style="margin-top:14px;color:var(--text-dim)">If a single partner-tenant identity in a master-key group is phished, or a management app's credential in one is stolen, the attacker inherits that group's roles in <b style="color:var(--text)">every customer it reaches</b> — the MSP amplification behind the SkyKick-class incidents.</p>`;
  return el;
}

function masterKeysBlock(d) {
  const el = document.createElement("div");
  el.className = "controls-sec";
  el.innerHTML = `<h3>Master keys — lock these down first</h3>
    <p class="csub">Partner security groups ranked by how many customers they unlock and at what level. One group mapped to Global Admin across many customers is the highest-value target in your whole estate.</p>
    ${d.keyList.map(masterKeyCard).join("")}`;
  return el;
}
function masterKeyCard(k) {
  const hot = k.directCount > 0;
  const membersLine = k.memberNames.length
    ? `<div class="mk-members">members: ${k.memberNames.map(escapeHtml).join(" · ")}</div>`
    : `<div class="mk-members">no members listed in export</div>`;
  const sub = hot
    ? `${k.directCount} customer${k.directCount>1?"s":""} fully takeable${k.condCount?`, ${k.condCount} partial`:""}`
    : k.condCount ? `${k.condCount} customer${k.condCount>1?"s":""} with scoped roles` : `${k.total} customer${k.total>1?"s":""} reached`;
  return `<div class="masterkey ${hot?"hot":""}">
    <div class="mk-head">
      <span class="mk-name">${escapeHtml(k.name)}</span>
      <span class="mk-type">${k.memberCount} member${k.memberCount===1?"":"s"}</span>
      <span class="mk-metric ${hot?"hot":""}"><div class="big">${k.total}</div><div class="sm">customers</div></span>
    </div>
    <div class="mk-detail">${sub}.</div>
    ${membersLine}
  </div>`;
}

function customersBlock(d) {
  const el = document.createElement("div");
  el.className = "controls-sec";
  el.innerHTML = `<h3>Customers, ranked by exposure</h3>
    <p class="csub">Each customer tenant and the worst role a partner compromise could wield inside it. Tap for the roles and the groups that carry them.</p>
    <div class="app-controls">
      <input class="app-search" id="cust-search" placeholder="Filter by customer name or tenant id…" autocomplete="off">
      <span class="fl">Sort:</span>
      <button class="sortbtn" data-csort="exposure" aria-pressed="${custSort==='exposure'}">Exposure</button>
      <button class="sortbtn" data-csort="name" aria-pressed="${custSort==='name'}">Name</button>
      <button class="sortbtn" data-csort="expiry" aria-pressed="${custSort==='expiry'}">Expiry risk</button>
    </div>
    <div class="app-list" id="cust-list"></div>`;
  el.querySelectorAll("[data-csort]").forEach(b => b.addEventListener("click", () => {
    custSort = b.dataset.csort;
    el.querySelectorAll("[data-csort]").forEach(x => x.setAttribute("aria-pressed", x.dataset.csort===custSort));
    paintCustRows(d);
  }));
  el.querySelector("#cust-search").addEventListener("input", () => paintCustRows(d));
  setTimeout(() => paintCustRows(d), 0);
  return el;
}
function paintCustRows(d) {
  const host = document.getElementById("cust-list");
  if (!host) return;
  const q = (document.getElementById("cust-search").value || "").trim().toLowerCase();
  const sevRank = s => s === "direct" ? 2 : s === "conditional" ? 1 : 0;
  const expRank = c => c.relstat === "dap" ? 4 : c.relstat === "expired" ? 3 : c.relstat === "expiring" ? 2 : 1;
  let rows = d.custList.filter(c => !q || c.name.toLowerCase().includes(q) || (c.id||"").toLowerCase().includes(q));
  const sorters = {
    exposure: (a,b) => sevRank(b.sev) - sevRank(a.sev) || b.roles.length - a.roles.length || a.name.localeCompare(b.name),
    name: (a,b) => a.name.localeCompare(b.name),
    expiry: (a,b) => expRank(b) - expRank(a) || sevRank(b.sev) - sevRank(a.sev),
  };
  rows.sort(sorters[custSort]);
  host.innerHTML = rows.map(custRow).join("") || `<div class="empty-state" style="padding:24px">No customers match “${q}”.</div>`;
  wireCollapsers(host, ".cust-head", ".cust-row");
}
function custRow(c) {
  const verdict = c.sev === "direct" ? "FULL TAKEOVER" : c.sev === "conditional" ? "SCOPED ADMIN" : "LOW";
  const relLabel = { active:"active", expiring:"expiring", expired:"expired", dap:"legacy DAP" }[c.relstat] || c.relstat;
  return `<div class="cust-row sev-${c.sev}">
    <div class="cust-head" role="button" aria-expanded="false" tabindex="0">
      <span class="app-dot ${c.sev}"></span>
      <span style="flex:1;min-width:0">
        <div class="cust-name">${escapeHtml(c.name)}</div>
        <div class="cust-sub">${c.id || "no tenant id"}</div>
      </span>
      <span class="cust-badges"><span class="relstat ${c.relstat}">${relLabel}</span></span>
      <span class="cust-verdict ${c.sev}">${verdict}</span>
      <span class="chev">▸</span>
    </div>
    <div class="cust-detail">
      <div class="sec-t">Roles a partner compromise could wield here</div>
      <div class="mini-reach">${c.roles.length ? c.roles.map(r => `<span class="mini-chip ${/global admin|privileged|legacy dap/i.test(r)?"hot":""}">${escapeHtml(r)}</span>`).join("") : '<span class="mini-chip">none mapped</span>'}</div>
      ${c.viaGroups.length ? `<div class="sec-t">Reached via these partner groups</div><div class="mini-reach">${c.viaGroups.map(g=>`<span class="mini-chip">${escapeHtml(g)}</span>`).join("")}</div>` : ""}
      ${c.endDateTime ? `<div style="font-size:11.5px;color:var(--text-faint);margin-top:10px">Relationship ends ${new Date(c.endDateTime).toLocaleDateString()}${c.relstat==="expired"?" — already expired":c.relstat==="expiring"?" — expiring soon":""}.</div>` : ""}
      ${c.isLegacyDap ? `<div style="font-size:12px;color:var(--takeover);margin-top:8px">Legacy DAP: standing Global Admin on this customer. Migrate to GDAP and remove it.</div>` : ""}
    </div>
  </div>`;
}

function partnerControlsBlock() {
  const el = document.createElement("div");
  el.className = "controls-sec";
  const sorters = { effort:(x,y)=>x.effort-y.effort||licRank(x.license)-licRank(y.license), stops:(x,y)=>stopRank(x.stops)-stopRank(y.stops)||x.effort-y.effort };
  const list = PARTNER_CONTROLS.slice().sort(sorters[ctrlSort === "stops" ? "stops" : "effort"]);
  el.innerHTML = `<h3>Partner hardening controls</h3>
    <p class="csub">The partner tenant is the single point of failure for every customer above. Hardening it is worth more than hardening any one customer.</p>
    <div class="ctrl-filters"><span class="fl">Sort by:</span>
      <button class="sortbtn" data-sort="effort" aria-pressed="${ctrlSort!=='stops'}">Least effort</button>
      <button class="sortbtn" data-sort="stops" aria-pressed="${ctrlSort==='stops'}">Strongest (prevents first)</button>
    </div>
    ${list.map(c => {
      const licClass = c.license === "Free" ? "Free" : c.license.includes("P1") ? "P1" : c.license.includes("P2") ? "P2" : "WID";
      const effortLabel = ["", "toggle", "quick", "moderate", "project"][c.effort];
      return `<div class="ctrl"><div class="ctrl-head" role="button" aria-expanded="false">
        <span class="chev">▸</span><span class="ctrl-name">${c.name}</span>
        <span class="ctrl-meta"><span class="tag tag-effort">${effortLabel}</span><span class="tag tag-lic-${licClass}">${c.license}</span><span class="tag tag-stops-${c.stops}">${c.stops}</span></span>
      </div><div class="ctrl-detail">${c.detail}</div></div>`;
    }).join("")}`;
  el.querySelectorAll(".sortbtn").forEach(b => b.addEventListener("click", () => {
    ctrlSort = b.dataset.sort === "stops" ? "stops" : "effort"; renderPartner(partnerData);
    document.querySelectorAll(".controls-sec")[document.querySelectorAll(".controls-sec").length-2]?.scrollIntoView({behavior:"smooth",block:"start"});
  }));
  wireCollapsers(el, ".ctrl-head", ".ctrl");
  return el;
}
function partnerDisclaimerBlock() {
  const el = document.createElement("div");
  el.className = "disclaimer";
  el.innerHTML = `<b>Read this.</b> This maps the <i>structural</i> reach of GDAP and legacy DAP: which customer tenants a partner-side
    identity can administer, and at what role level. It reasons from the relationships, access assignments and group memberships in
    your export; it does not log in to customer tenants or confirm what was actually done. Roles become live only once mapped to a
    group via an access assignment — latent relationship roles are shown but flagged. Escalation classification reuses the same
    knowledge base (v${KB_VERSION}) as the rest of the tool. Verify against Partner Center and current Microsoft guidance before acting.
    GDAP exists to shrink this blast radius; the goal is least-privilege, time-bound, MFA-protected partner access, not zero partner access.`;
  return el;
}

// <<<STRIP-PUBLIC-END>>>

// ============================================================================
// EXPORTABLE REPORT — browser-only, self-contained, print/PDF-ready
// ============================================================================
function exportBar(mode) {
  const el = document.createElement("div");
  el.className = "export-bar";
  const defTitle = { single: "App Permission Risk Assessment", tenant: "Tenant App Risk Assessment", partner: "Partner Cross-Tenant (GDAP) Assessment" }[mode];
  el.innerHTML = `
    <div class="xb-row">
      <span class="xb-label">Client report</span>
      <input class="xb-input" id="xb-for" placeholder="Prepared for (client)" value="${escapeHtml(reportBrand.preparedFor)}">
      <input class="xb-input" id="xb-by" placeholder="Prepared by (your org)" value="${escapeHtml(reportBrand.preparedBy)}">
      <button class="xb-btn primary" id="xb-dl">Download report</button>
      <button class="xb-btn" id="xb-print">Print / Save PDF</button>
    </div>
    <div class="xb-note" id="xb-note"></div>`;
  const capture = () => {
    reportBrand.preparedFor = el.querySelector("#xb-for").value.trim();
    reportBrand.preparedBy = el.querySelector("#xb-by").value.trim();
    reportBrand.title = defTitle;
  };
  el.querySelector("#xb-dl").addEventListener("click", () => { capture(); downloadReport(mode); });
  el.querySelector("#xb-print").addEventListener("click", () => { capture(); printReport(mode); });
  return el;
}

function downloadReport(mode) {
  const html = buildReportHTML(mode);
  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const stamp = new Date().toISOString().slice(0, 10);
  a.href = url;
  a.download = `blast-radius-${mode}-report-${stamp}.html`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  const note = document.getElementById("xb-note");
  if (note) note.textContent = "Downloaded. Open the file and choose Print → Save as PDF for a PDF copy.";
}

function printReport(mode) {
  const html = buildReportHTML(mode);
  // isolate print in a hidden iframe so the app's dark UI isn't printed
  const frame = document.createElement("iframe");
  frame.style.cssText = "position:fixed;right:0;bottom:0;width:0;height:0;border:0;";
  document.body.appendChild(frame);
  const note = document.getElementById("xb-note");
  try {
    const doc = frame.contentWindow.document;
    doc.open(); doc.write(html); doc.close();
    setTimeout(() => {
      try { frame.contentWindow.focus(); frame.contentWindow.print(); }
      catch (e) { if (note) note.textContent = "Printing was blocked here — use Download report instead, then print the file."; }
      setTimeout(() => frame.remove(), 1000);
    }, 300);
  } catch (e) {
    frame.remove();
    if (note) note.textContent = "Printing was blocked here — use Download report instead, then print the file.";
  }
}

// ---- report HTML builder (light theme, system fonts, print CSS) ----
function reportHead(title) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  :root { --ink:#1a2230; --dim:#55657a; --faint:#8695a6; --line:#e2e8f0; --panel:#f7f9fb;
    --red:#b42318; --redbg:#fef3f2; --amber:#b54708; --amberbg:#fffaeb; --green:#067647; --greenbg:#ecfdf3; }
  * { box-sizing: border-box; }
  body { margin:0; color:var(--ink); background:#fff; font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  .page { max-width: 820px; margin: 0 auto; padding: 40px 48px 64px; }
  .toolbar { position: sticky; top:0; background:#fff; border-bottom:1px solid var(--line); padding:12px 48px;
    display:flex; gap:10px; align-items:center; }
  .toolbar button { font:inherit; font-size:13px; font-weight:600; cursor:pointer; border:1px solid var(--line);
    background:var(--panel); color:var(--ink); border-radius:7px; padding:8px 14px; }
  .toolbar button.primary { background:#2563eb; color:#fff; border-color:#2563eb; }
  .toolbar .tnote { font-size:12px; color:var(--faint); margin-left:auto; }
  header.rpt { border-bottom:3px solid var(--ink); padding-bottom:18px; margin-bottom:26px; }
  header.rpt .mark { display:inline-flex; align-items:center; gap:9px; font-weight:800; font-size:15px; letter-spacing:-0.01em; }
  header.rpt .dot { width:16px;height:16px;border-radius:5px;background:radial-gradient(circle at 50% 42%, var(--amber) 0 30%, transparent 32%), #2b3a4c; }
  header.rpt h1 { font-size:26px; letter-spacing:-0.02em; margin:16px 0 6px; }
  header.rpt .meta { font-size:13px; color:var(--dim); }
  header.rpt .meta b { color:var(--ink); font-weight:600; }
  h2.sec { font-size:17px; letter-spacing:-0.01em; margin:30px 0 12px; padding-bottom:6px; border-bottom:1px solid var(--line); }
  h3.sub { font-size:14px; margin:18px 0 8px; color:var(--ink); }
  p { margin:0 0 11px; }
  .lede { font-size:15.5px; color:var(--ink); }
  .muted { color:var(--dim); }
  .verdict { display:flex; gap:14px; align-items:center; padding:16px 18px; border-radius:10px; border:1px solid var(--line); margin:4px 0 14px; }
  .verdict .badge { font-weight:700; font-size:12px; letter-spacing:.02em; padding:6px 12px; border-radius:20px; white-space:nowrap; }
  .verdict.direct { background:var(--redbg); border-color:#fecdc9; } .verdict.direct .badge { background:var(--red); color:#fff; }
  .verdict.conditional { background:var(--amberbg); border-color:#fde68a; } .verdict.conditional .badge { background:var(--amber); color:#fff; }
  .verdict.none { background:var(--greenbg); border-color:#a6f4c5; } .verdict.none .badge { background:var(--green); color:#fff; }
  .verdict .vt { font-weight:700; font-size:15px; } .verdict .vs { font-size:13px; color:var(--dim); margin-top:2px; }
  .stats { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin:6px 0 4px; }
  .stat { border:1px solid var(--line); border-radius:8px; padding:12px 14px; }
  .stat .n { font-size:24px; font-weight:700; letter-spacing:-0.02em; }
  .stat .l { font-size:11.5px; color:var(--dim); margin-top:3px; line-height:1.3; }
  .stat.red .n { color:var(--red); } .stat.red { background:var(--redbg); border-color:#fecdc9; }
  .stat.amber .n { color:var(--amber); } .stat.amber { background:var(--amberbg); border-color:#fde68a; }
  table { width:100%; border-collapse:collapse; font-size:13px; margin:8px 0 6px; }
  th { text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.03em; color:var(--faint); font-weight:700; padding:7px 10px; border-bottom:2px solid var(--line); }
  td { padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  tr { break-inside: avoid; }
  .pill { display:inline-block; font-size:10.5px; font-weight:700; padding:2px 8px; border-radius:20px; }
  .pill.direct { background:var(--red); color:#fff; } .pill.conditional { background:var(--amber); color:#fff; } .pill.none { background:var(--green); color:#fff; }
  .tag { display:inline-block; font-size:10.5px; padding:2px 7px; border:1px solid var(--line); border-radius:5px; color:var(--dim); margin:1px 2px 1px 0; }
  .tag.hot { border-color:#fecdc9; background:var(--redbg); color:var(--red); }
  ul.clean { margin:6px 0 10px; padding-left:18px; } ul.clean li { margin:4px 0; }
  .finding { break-inside:avoid; padding:11px 14px; border:1px solid var(--line); border-left:3px solid var(--amber); border-radius:7px; background:var(--panel); margin:8px 0; font-size:13.5px; }
  .finding.red { border-left-color:var(--red); }
  .finding b { color:var(--ink); }
  .foot { margin-top:34px; padding-top:16px; border-top:1px solid var(--line); font-size:11.5px; color:var(--faint); line-height:1.6; }
  .chainline { font-size:13px; margin:5px 0; }
  .chainline .step { font-weight:700; } .chainline .arr { color:var(--faint); margin:0 7px; }
  @media print {
    .toolbar { display:none; }
    .page { max-width:none; padding:0 0 20px; }
    @page { margin: 16mm 14mm; }
    h2.sec { break-after: avoid; }
    .verdict, .finding, .stat, .masterkey { break-inside: avoid; }
  }
  @media (max-width:640px){ .stats { grid-template-columns:repeat(2,1fr); } .page{padding:24px 20px;} .toolbar{padding:12px 20px;} }
</style></head><body>
<div class="toolbar">
  <button class="primary" onclick="window.print()">Print / Save as PDF</button>
  <span class="tnote">Opens your browser's print dialog — choose “Save as PDF” as the destination.</span>
</div>
<div class="page">`;
}

function reportHeader(title, scopeLine) {
  const now = new Date();
  const forLine = reportBrand.preparedFor ? `<b>Prepared for:</b> ${escapeHtml(reportBrand.preparedFor)}` : "";
  const byLine = reportBrand.preparedBy ? `<b>Prepared by:</b> ${escapeHtml(reportBrand.preparedBy)}` : "";
  const sep = forLine && byLine ? " &nbsp;·&nbsp; " : "";
  return `<header class="rpt">
    <div class="mark"><span class="dot"></span> Blast Radius</div>
    <h1>${escapeHtml(title)}</h1>
    <div class="meta">${scopeLine}<br>${forLine}${sep}${byLine}${(forLine||byLine)?"<br>":""}<b>Generated:</b> ${now.toLocaleString()} &nbsp;·&nbsp; knowledge base v${KB_VERSION}</div>
  </header>`;
}

function reportFoot() {
  return `<div class="foot"><b>Methodology &amp; limitations.</b> This assessment reasons about Microsoft Entra application
    permissions, directory roles, group memberships and delegated-admin (GDAP) relationships using a knowledge base
    (v${KB_VERSION}) built from public research (SpecterOps/BloodHound, Horizon3, Maester, Emilien Socchi's azure-tiering)
    and Microsoft documentation. It analyzes configuration and structural reach, not activity — it does not confirm what an
    attacker did or could do in practice, and “no known path” means nothing in the knowledge base matched, not that a target
    is safe. Escalation and blast-radius findings depend on the accuracy and completeness of the exported data. Verify against
    the live tenant and current Microsoft guidance before acting. Prepared with Blast Radius, an analysis aid — not a
    substitute for a full security audit.</div></div></body></html>`;
}

function verdictCfgReport(sev) {
  return {
    direct: { badge:"CAN REACH GLOBAL ADMIN", t:"Full tenant takeover is possible.", s:"One or more permissions or roles lead to Global Administrator (or equivalent)." },
    conditional: { badge:"LIKELY — CONDITIONAL", t:"Takeover is likely, depending on tenant configuration.", s:"Escalation depends on other objects (apps, role-assignable groups)." },
    none: { badge:"NO KNOWN PATH", t:"No known takeover path from what was analyzed.", s:"Not the same as safe — data reach can still be significant." },
  }[sev];
}

function buildReportHTML(mode) {
  const title = reportBrand.title || "Risk Assessment";
  if (mode === "single") return reportSingle(title);
  if (mode === "tenant") return reportTenant(title);
  if (mode === "partner") return reportPartner(title);
  return reportHead(title) + "<p>Nothing to report.</p>" + reportFoot();
}

function reportSingle(title) {
  const a = singleData;
  if (!a) return reportHead(title) + "<p>Run an analysis first.</p>" + reportFoot();
  const cfg = verdictCfgReport(a.sev);
  const typeLabel = a.appType === "multi-tenant" ? "Vendor (multi-tenant)" : "Single-tenant (your own)";
  let html = reportHead(title);
  html += reportHeader(title, `<b>Scope:</b> a single ${typeLabel} application · ${a.perms.length} permission(s), ${a.roles.length} directory role(s) analyzed`);

  // exec summary
  const reach = [...new Set([...a.reads, ...a.writes])].filter(c => c !== "self").map(c => (REACH_LABELS[c]||{}).name).filter(Boolean);
  html += `<h2 class="sec">Executive summary</h2>`;
  const scopeWord = a.appType === "multi-tenant" ? "every tenant this vendor app is installed in" : "this tenant";
  html += `<p class="lede">If this application's credential were stolen, an attacker could act with its full access across ${scopeWord}` +
    (reach.length ? `, reaching: ${reach.join(", ").toLowerCase()}.` : ".") +
    (a.sev !== "none" ? ` From there, they could escalate to complete control of the tenant.` : ` There is no known path from these permissions to full admin takeover, but the data reach above still matters.`) + `</p>`;

  // verdict
  html += `<div class="verdict ${a.sev}"><span class="badge">${cfg.badge}</span><div><div class="vt">${cfg.t}</div><div class="vs">${cfg.s}</div></div></div>`;
  const reasons = a.sev === "direct" ? a.directReasons : a.sev === "conditional" ? a.condReasons : [];
  if (reasons.length) {
    html += `<h3 class="sub">Why</h3><ul class="clean">`;
    reasons.slice(0,8).forEach(r => html += `<li><b>${escapeHtml(r.id)}</b> — ${escapeHtml(r.escalationNote || r.plain)}${r.conditionalOn?` <span class="muted">(depends on: ${escapeHtml(r.conditionalOn)})</span>`:""}</li>`);
    html += `</ul>`;
  }

  // blast radius
  if (reach.length) {
    html += `<h2 class="sec">Blast radius</h2><p>${reach.map(r=>`<span class="tag">${escapeHtml(r)}</span>`).join("")}</p>`;
  }

  // detection
  html += `<h2 class="sec">Detection reality</h2><ul class="clean">
    <li>App sign-ins from unexpected IPs are visible only in service-principal sign-in logs, which require Entra P1 and are a separate view from user sign-ins.</li>
    <li>${a.hasStealthyRead ? "Directory reads via Microsoft Graph leave no audit record — you cannot tell after the fact what this app read." : "Some reads are not logged; mailbox and file access may appear in the unified audit log if it is enabled."}</li>
    <li>Default Entra log retention is short (7–30 days); longer retention needs P1 plus a Log Analytics/SIEM export.</li></ul>`;

  // controls
  const isVendor = a.appType === "multi-tenant";
  const controls = CONTROLS.filter(c => isVendor ? c.appliesVendor : c.appliesSingle).sort((x,y)=>x.effort-y.effort||licRank(x.license)-licRank(y.license));
  html += `<h2 class="sec">Recommended compensating controls</h2>`;
  html += controlsTable(controls);

  if (isVendor) {
    html += `<h2 class="sec">Before you consent: questions for the vendor</h2><ul class="clean">` +
      VENDOR_QUESTIONS.map(q => `<li>${escapeHtml(q)}</li>`).join("") + `</ul>`;
  }
  html += reportFoot();
  return html;
}

function controlsTable(controls) {
  const eff = ["", "toggle", "quick", "moderate", "project"];
  let h = `<table><thead><tr><th>Control</th><th>Effort</th><th>License</th><th>Effect</th></tr></thead><tbody>`;
  controls.forEach(c => { h += `<tr><td><b>${escapeHtml(c.name)}</b><br><span class="muted">${escapeHtml(c.detail)}</span></td><td>${eff[c.effort]}</td><td>${escapeHtml(c.license)}</td><td>${escapeHtml(c.stops)}</td></tr>`; });
  return h + `</tbody></table>`;
}

function reportTenant(title) {
  const d = tenantData;
  if (!d) return reportHead(title) + "<p>Run a tenant analysis first.</p>" + reportFoot();
  const r = d.roll;
  let html = reportHead(title);
  html += reportHeader(title, `<b>Scope:</b> ${r.total} applications in ${d.tenantId ? "tenant " + escapeHtml(d.tenantId) : "the tenant"}${d.haveGroupData ? ` · ${r.groupCount} groups included` : ""}`);

  html += `<h2 class="sec">Executive summary</h2>`;
  html += `<p class="lede">Of ${r.total} applications analyzed, <b>${r.ga}</b> can reach Global Administrator` +
    (r.gaChained ? ` (${r.gaChained} only by chaining through another app or a group)` : "") +
    `. ${r.conditional} more are conditional, ${r.withRoles} hold a directory role, and ${r.suspCreds} carry credential-hygiene concerns. ` +
    `${r.vendor} are vendor (multi-tenant) apps whose credential you cannot rotate.</p>`;

  html += `<div class="stats">
    ${rstat(r.ga,"reach Global Admin",r.ga?"red":"")}
    ${rstat(r.gaChained,"via a backdoor/group chain",r.gaChained?"red":"")}
    ${rstat(r.conditional,"conditional",r.conditional?"amber":"")}
    ${rstat(r.withRoles,"hold a directory role",r.withRoles?"amber":"")}
    ${rstat(r.suspCreds,"credential concerns",r.suspCreds?"amber":"")}
    ${rstat(r.vendor,"vendor apps","")}
    ${rstat(r.own,"your own apps","")}
    ${rstat(r.disabled,"disabled","")}</div>`;

  // key findings: GA-reaching apps
  const ga = d.sps.filter(s => s.finalSev === "direct").sort((a,b)=>b.riskScore-a.riskScore);
  if (ga.length) {
    html += `<h2 class="sec">Priority findings — apps that can reach Global Admin</h2>`;
    ga.slice(0,12).forEach(sp => {
      let why = "";
      if (sp.groupProof) { const g = sp.groupProof.group; why = `${sp.groupProof.how} the ${g.roleAssignable?"role-assignable ":""}group “${escapeHtml(g.name)}”, which holds a privileged role`; }
      else if (sp.confirmedViaChain && sp.gaProof) why = `can plant a credential on the more privileged app “${escapeHtml(sp.gaProof.name)}” and inherit it`;
      else { const rr = (sp.analysis.directReasons[0]||sp.perms.find(p=>p.id==="AppRoleAssignment.ReadWrite.All")); why = rr ? `holds ${escapeHtml(rr.id)}` : (sp.roleObjs.find(x=>x.escalation==="direct") ? `holds the ${escapeHtml(sp.roleObjs.find(x=>x.escalation==="direct").id)} role` : "holds a direct-escalation permission"); }
      html += `<div class="finding red"><b>${escapeHtml(sp.name)}</b> <span class="muted">(${sp.appType==="multi-tenant"?"vendor":"own"}${sp.enabled?"":", disabled"})</span> — ${why}.</div>`;
    });
  }

  // full inventory
  html += `<h2 class="sec">Application inventory</h2>`;
  html += `<table><thead><tr><th>Application</th><th>Type</th><th>Verdict</th><th>Roles</th><th>Flags</th></tr></thead><tbody>`;
  d.sps.slice().sort((a,b)=>b.riskScore-a.riskScore).forEach(sp => {
    const v = sp.finalSev; const vl = v==="direct"?"Global Admin":v==="conditional"?"Conditional":"No known path";
    const flags = []; if (!sp.enabled) flags.push("disabled"); if (sp.credFlags.length) flags.push("cred concern"); if (sp.groupProof) flags.push("via group"); if (sp.groupCleared) flags.push("group-cleared");
    html += `<tr><td><b>${escapeHtml(sp.name)}</b><br><span class="muted" style="font-size:11px">${escapeHtml(sp.appId||"")}</span></td>` +
      `<td>${sp.appType==="multi-tenant"?"vendor":"own"}</td>` +
      `<td><span class="pill ${v}">${vl}</span></td>` +
      `<td>${sp.roleObjs.map(x=>escapeHtml(x.id)).join(", ")||"—"}</td>` +
      `<td>${flags.join(", ")||"—"}</td></tr>`;
  });
  html += `</tbody></table>`;

  // recommended actions
  html += `<h2 class="sec">Recommended actions</h2>`;
  html += controlsTable(CONTROLS.filter(c=>c.appliesVendor||c.appliesSingle).sort((x,y)=>x.effort-y.effort||licRank(x.license)-licRank(y.license)).slice(0,10));
  html += reportFoot();
  return html;
}
function rstat(n,l,cls){ return `<div class="stat ${cls}"><div class="n">${n}</div><div class="l">${l}</div></div>`; }

function reportPartner(title) {
  const d = partnerData;
  if (!d) return reportHead(title) + "<p>Run a partner analysis first.</p>" + reportFoot();
  const r = d.roll;
  let html = reportHead(title);
  html += reportHeader(title, `<b>Scope:</b> ${r.customers} customer tenant(s) reachable via delegated admin from the partner tenant${d.partnerTenantId?" "+escapeHtml(d.partnerTenantId):""}`);

  html += `<h2 class="sec">Executive summary</h2>`;
  html += `<p class="lede">This partner can administer <b>${r.customers}</b> customer tenants through GDAP/DAP. ` +
    `A single compromise on the partner side could fully take over <b>${r.fullTakeover}</b> of them` +
    (r.legacyDap ? `, including ${r.legacyDap} still on legacy DAP (standing Global Admin)` : "") + `. ` +
    `${r.masterKeys} partner security group(s) act as master keys. ${r.noMfaMembers} admin(s) in delegated groups lack MFA.</p>`;

  html += `<div class="stats">
    ${rstat(r.fullTakeover,"customers fully takeable",r.fullTakeover?"red":"")}
    ${rstat(r.legacyDap,"legacy DAP (standing GA)",r.legacyDap?"red":"")}
    ${rstat(r.masterKeys,"master-key groups",r.masterKeys?"red":"")}
    ${rstat(r.noMfaMembers,"admins without MFA",r.noMfaMembers?"red":"")}
    ${rstat(r.partial,"scoped-role customers",r.partial?"amber":"")}
    ${rstat(r.gaRelationships,"relationships granting GA",r.gaRelationships?"amber":"")}
    ${rstat(r.expired,"expired relationships",r.expired?"amber":"")}
    ${rstat(r.expiring,"expiring < 30 days",r.expiring?"amber":"")}</div>`;

  // master keys
  if (d.keyList.length) {
    html += `<h2 class="sec">Master keys — highest-value targets</h2>`;
    html += `<table><thead><tr><th>Partner group</th><th>Customers reached</th><th>Fully takeable</th><th>Members</th></tr></thead><tbody>`;
    d.keyList.forEach(k => { html += `<tr><td><b>${escapeHtml(k.name)}</b></td><td>${k.total}</td><td>${k.directCount?`<span class="pill direct">${k.directCount}</span>`:"0"}</td><td class="muted">${k.memberNames.map(escapeHtml).join(", ")||"—"}</td></tr>`; });
    html += `</tbody></table>`;
  }

  // customers fully takeable
  const full = d.custList.filter(c=>c.sev==="direct");
  if (full.length) {
    html += `<h2 class="sec">Customers fully takeable from the partner</h2>`;
    html += `<table><thead><tr><th>Customer</th><th>Roles reachable</th><th>Via groups</th><th>Status</th></tr></thead><tbody>`;
    full.forEach(c => { html += `<tr><td><b>${escapeHtml(c.name)}</b></td><td>${c.roles.map(x=>`<span class="tag ${/global|privileged|dap/i.test(x)?"hot":""}">${escapeHtml(x)}</span>`).join("")}</td><td>${c.viaGroups.map(escapeHtml).join(", ")||"—"}</td><td>${escapeHtml(c.relstat)}</td></tr>`; });
    html += `</tbody></table>`;
  }

  // full customer table
  html += `<h2 class="sec">All customers</h2>`;
  html += `<table><thead><tr><th>Customer</th><th>Exposure</th><th>Worst roles</th><th>Relationship</th></tr></thead><tbody>`;
  const sevRank = s => s==="direct"?2:s==="conditional"?1:0;
  d.custList.slice().sort((a,b)=>sevRank(b.sev)-sevRank(a.sev)).forEach(c => {
    const vl = c.sev==="direct"?"Full takeover":c.sev==="conditional"?"Scoped admin":"Low";
    html += `<tr><td><b>${escapeHtml(c.name)}</b></td><td><span class="pill ${c.sev}">${vl}</span></td><td>${c.roles.map(escapeHtml).join(", ")||"—"}</td><td>${escapeHtml(c.relstat)}</td></tr>`;
  });
  html += `</tbody></table>`;

  // controls
  html += `<h2 class="sec">Partner hardening — priorities</h2>`;
  const eff = ["","toggle","quick","moderate","project"];
  html += `<table><thead><tr><th>Control</th><th>Effort</th><th>License</th><th>Effect</th></tr></thead><tbody>`;
  PARTNER_CONTROLS.slice().sort((x,y)=>x.effort-y.effort).forEach(c => html += `<tr><td><b>${escapeHtml(c.name)}</b><br><span class="muted">${escapeHtml(c.detail)}</span></td><td>${eff[c.effort]}</td><td>${escapeHtml(c.license)}</td><td>${escapeHtml(c.stops)}</td></tr>`);
  html += `</tbody></table>`;
  html += reportFoot();
  return html;
}

// ============================================================================
// SHARED: collapsible wiring
// ============================================================================
function wireCollapsers(root, headSel, itemSel) {
  root.querySelectorAll(headSel).forEach(h => {
    const toggle = () => h.closest(itemSel).classList.toggle("open");
    h.addEventListener("click", toggle);
    h.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
    if (!h.hasAttribute("tabindex")) h.tabIndex = 0;
  });
}

// ============================================================================
// WIRING
// ============================================================================
function switchInput(mode) {
  inputMode = mode;
  document.getElementById("tab-pick").setAttribute("aria-pressed", mode==="pick");
  document.getElementById("tab-paste").setAttribute("aria-pressed", mode==="paste");
  document.getElementById("mode-pick").style.display = mode==="pick" ? "" : "none";
  document.getElementById("mode-paste").style.display = mode==="paste" ? "" : "none";
}
function switchScope(s) {
  // in the public build, tenant/partner panels don't exist — ignore those scopes
  if ((s === "tenant" && !has("tenant-mode")) || (s === "partner" && !has("partner-mode"))) return;
  scope = s;
  const press = (id, v) => { const el = $id(id); if (el) el.setAttribute("aria-pressed", v); };
  const hide = (id, v) => { const el = $id(id); if (el) el.hidden = v; };
  press("mode-single", s==="single"); press("mode-tenant", s==="tenant"); press("mode-partner", s==="partner");
  hide("single-mode", s !== "single"); hide("tenant-mode", s !== "tenant"); hide("partner-mode", s !== "partner");
}
function switchAudience(aud) {
  audience = aud;
  document.body.dataset.aud = aud;
  document.getElementById("aud-tech").setAttribute("aria-pressed", aud==="tech");
  document.getElementById("aud-biz").setAttribute("aria-pressed", aud==="biz");
  if (scope === "single" && selected.size && !document.querySelector("#results .empty-state")) analyze();
  if (scope === "tenant" && tenantData) renderTenant(tenantData);
  if (scope === "partner" && partnerData) renderPartner(partnerData);
}

const SCRIPT_TEXT = `# Read-only. Lists what an app's service principal can do in YOUR tenant.
# Needs Microsoft.Graph module. Consents to read-only scopes only.
Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All","RoleManagement.Read.Directory"

$appId = Read-Host "Enter the application (client) ID to inspect"
$sp = Get-MgServicePrincipal -Filter "appId eq '$appId'"
if (-not $sp) { Write-Host "No service principal found for that appId in this tenant."; return }

Write-Host "\`n=== APP ROLES (application permissions) ==="
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id | ForEach-Object {
  $res = Get-MgServicePrincipal -ServicePrincipalId $_.ResourceId
  ($res.AppRoles | Where-Object Id -eq $_.AppRoleId).Value
}

Write-Host "\`n=== DIRECTORY ROLES held by this service principal ==="
Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($sp.Id)'" |
  ForEach-Object { (Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId).DisplayName }

Write-Host "\`n=== CREDENTIALS on this app (check for unexpected / long-dated) ==="
$sp.KeyCredentials    | Select-Object DisplayName, StartDateTime, EndDateTime
$sp.PasswordCredentials | Select-Object DisplayName, StartDateTime, EndDateTime

Write-Host "\`nPaste the app role + role names above into Blast Radius."`;

// <<<STRIP-PUBLIC-START>>> tenant + partner scripts, samples, dispatchers (full build only)
const TENANT_SCRIPT = `# ============================================================
#  Blast Radius — read-only TENANT export
#  READ-ONLY: every call below is a *Get*. No writes, ever.
#  Scopes are read-only and the script is short on purpose — read it
#  before you run it. It never reads credential VALUES, only metadata.
#
#  !! The file this produces maps every privilege path in the tenant. !!
#  Treat it like a password vault: don't email it or attach it to a
#  ticket, and delete it as soon as you've finished the analysis.
# ============================================================
Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All","RoleManagement.Read.Directory"

$ctx = Get-MgContext
$tenantId = $ctx.TenantId

# Resolve ACTIVE directory role assignments once: principalId -> [role names]
$roleDefs = @{}
Get-MgRoleManagementDirectoryRoleDefinition -All | ForEach-Object { $roleDefs[$_.Id] = $_.DisplayName }
$rolesByPrincipal = @{}
Get-MgRoleManagementDirectoryRoleAssignment -All | ForEach-Object {
  $n = $roleDefs[$_.RoleDefinitionId]
  if (-not $rolesByPrincipal.ContainsKey($_.PrincipalId)) { $rolesByPrincipal[$_.PrincipalId] = @() }
  if ($n) { $rolesByPrincipal[$_.PrincipalId] += $n }
}
# Resolve PIM-ELIGIBLE role assignments (gated, not standing)
$eligibleByPrincipal = @{}
Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction SilentlyContinue | ForEach-Object {
  $n = $roleDefs[$_.RoleDefinitionId]
  if (-not $eligibleByPrincipal.ContainsKey($_.PrincipalId)) { $eligibleByPrincipal[$_.PrincipalId] = @() }
  if ($n) { $eligibleByPrincipal[$_.PrincipalId] += $n }
}

$sps = foreach ($sp in Get-MgServicePrincipal -All) {
  $appRoleValues = foreach ($a in (Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All)) {
    $res = Get-MgServicePrincipal -ServicePrincipalId $a.ResourceId -ErrorAction SilentlyContinue
    ($res.AppRoles | Where-Object Id -eq $a.AppRoleId).Value
  }
  $owned = foreach ($o in (Get-MgServicePrincipalOwnedObject -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue)) {
    $o.AdditionalProperties.appId
  }
  # OWNERS of this service principal (users or other SPs) — an owner can add a
  # credential and inherit access, so this is an escalation path into the app.
  $owners = foreach ($o in (Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue)) {
    $t = if ($o.AdditionalProperties.'@odata.type' -match 'servicePrincipal|application') { 'servicePrincipal' } else { 'user' }
    [pscustomobject]@{ id = $o.Id; type = $t; displayName = $o.AdditionalProperties.displayName }
  }
  # credential METADATA only (never values); tag the source for cleanup guidance
  $spKey = @($sp.KeyCredentials      | Select-Object DisplayName, StartDateTime, EndDateTime | ForEach-Object { $_ | Add-Member source 'servicePrincipal' -PassThru })
  $spPwd = @($sp.PasswordCredentials | Select-Object DisplayName, StartDateTime, EndDateTime | ForEach-Object { $_ | Add-Member source 'servicePrincipal' -PassThru })
  # also the app REGISTRATION's credentials (different cleanup), if we own it
  $appReg = Get-MgApplication -Filter "appId eq '$($sp.AppId)'" -ErrorAction SilentlyContinue
  if ($appReg) {
    $spKey += @($appReg.KeyCredentials      | Select-Object DisplayName, StartDateTime, EndDateTime | ForEach-Object { $_ | Add-Member source 'application' -PassThru })
    $spPwd += @($appReg.PasswordCredentials | Select-Object DisplayName, StartDateTime, EndDateTime | ForEach-Object { $_ | Add-Member source 'application' -PassThru })
  }
  [pscustomobject]@{
    id                     = $sp.Id
    appId                  = $sp.AppId
    displayName            = $sp.DisplayName
    accountEnabled         = $sp.AccountEnabled
    appOwnerOrganizationId = $sp.AppOwnerOrganizationId
    signInAudience         = $sp.SignInAudience
    appRoles               = @($appRoleValues | Where-Object { $_ })
    directoryRoles         = @($rolesByPrincipal[$sp.Id])
    eligibleRoles          = @($eligibleByPrincipal[$sp.Id])
    ownedApps              = @($owned | Where-Object { $_ })
    owners                 = @($owners)
    keyCredentials         = @($spKey)
    passwordCredentials    = @($spPwd)
  }
}

# --- Groups: role-assignable flag, directory roles held, members, owners ---
$groups = foreach ($g in Get-MgGroup -All -Property "id,displayName,isAssignableToRole") {
  $members = Get-MgGroupMember -GroupId $g.Id -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Id }
  $owners  = Get-MgGroupOwner  -GroupId $g.Id -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Id }
  [pscustomobject]@{
    id                 = $g.Id
    displayName        = $g.DisplayName
    isAssignableToRole = [bool]$g.IsAssignableToRole
    directoryRoles     = @($rolesByPrincipal[$g.Id])
    members            = @($members)
    owners             = @($owners)
  }
}

$export = [pscustomobject]@{
  tenantId          = $tenantId
  generatedAt       = (Get-Date).ToString("o")
  servicePrincipals = @($sps)
  groups            = @($groups)
}
$stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
$file  = "blast-radius-tenant-$stamp.json"
$export | ConvertTo-Json -Depth 6 | Out-File $file -Encoding utf8
Write-Host ""
Write-Host "Wrote $file"
Write-Host "SENSITIVE: this file maps every privilege path in the tenant. Paste it"
Write-Host "into Blast Radius (Whole tenant), then DELETE it:  Remove-Item $file"`;

// small synthetic tenant that exercises the chain logic
const SAMPLE_TENANT = {
  tenantId: "contoso-1111-2222-3333-444455556666",
  generatedAt: new Date().toISOString(),
  servicePrincipals: [
    { id: "sp-backup", appId: "506e08f9-6e9a-4da4-942b-a099a03644ae", displayName: "ConnectWise Cloud Backup", accountEnabled: true,
      appOwnerOrganizationId: "vendor-aaaa-bbbb-cccc-dddddddddddd",
      appRoles: ["Mail.ReadWrite","Files.ReadWrite.All","Sites.ReadWrite.All","Directory.Read.All","full_access_as_app"],
      directoryRoles: [], ownedApps: [],
      passwordCredentials: [{ displayName: "vendor-secret", startDateTime: new Date().toISOString(), endDateTime: "2028-10-01T00:00:00Z" }] },
    { id: "sp-teams", appId: "24205314-2b89-4e07-a2a4-579e898a5640", displayName: "ConnectWise Cloud Management - MS Teams", accountEnabled: true,
      appOwnerOrganizationId: "vendor-aaaa-bbbb-cccc-dddddddddddd",
      appRoles: ["Application.ReadWrite.All","Directory.Read.All","Chat.ReadWrite.All"],
      directoryRoles: [], ownedApps: [] },
    { id: "sp-privileged", appId: "aaaaaaaa-0000-1111-2222-333333333333", displayName: "Legacy Automation Runner", accountEnabled: true,
      appOwnerOrganizationId: "contoso-1111-2222-3333-444455556666",
      appRoles: ["RoleManagement.ReadWrite.Directory"], directoryRoles: [], ownedApps: [] },
    { id: "sp-signature", appId: "bbbbbbbb-0000-1111-2222-333333333333", displayName: "MailBrand Signatures", accountEnabled: true,
      appOwnerOrganizationId: "vendor2-eeee-ffff-0000-111111111111",
      appRoles: ["Mail.ReadWrite","Mail.Send","MailboxSettings.ReadWrite"], directoryRoles: [], ownedApps: [] },
    { id: "sp-report", appId: "cccccccc-0000-1111-2222-333333333333", displayName: "InsightReports (read-only)", accountEnabled: true,
      appOwnerOrganizationId: "vendor3-2222-3333-4444-555555555555",
      appRoles: ["Directory.Read.All","User.Read.All","AuditLog.Read.All"], directoryRoles: [], ownedApps: [] },
    { id: "sp-exch", appId: "dddddddd-0000-1111-2222-333333333333", displayName: "Archive Connector", accountEnabled: false,
      appOwnerOrganizationId: "contoso-1111-2222-3333-444455556666",
      appRoles: ["full_access_as_app"], directoryRoles: ["Exchange Administrator"], ownedApps: [] },
    { id: "sp-scoped", appId: "eeeeeeee-0000-1111-2222-333333333333", displayName: "DocSync (scoped)", accountEnabled: true,
      appOwnerOrganizationId: "contoso-1111-2222-3333-444455556666",
      appRoles: ["Sites.Selected","User.Read"], directoryRoles: [], ownedApps: [] },
    // --- group-path examples ---
    { id: "sp-ingroup", appId: "ffffffff-0000-1111-2222-333333333333", displayName: "Provisioning Worker", accountEnabled: true,
      appOwnerOrganizationId: "contoso-1111-2222-3333-444455556666",
      appRoles: ["User.Read.All"], directoryRoles: [], ownedApps: [],
      memberOf: ["grp-admins"] },                         // member of a GA-carrying role-assignable group -> direct via group
    { id: "sp-groupwrite", appId: "11110000-0000-1111-2222-333333333333", displayName: "HR Sync (group writer)", accountEnabled: true,
      appOwnerOrganizationId: "vendor4-7777-8888-9999-000000000000",
      appRoles: ["Group.ReadWrite.All","User.Read.All"], directoryRoles: [], ownedApps: [] },
                                                           // Group.ReadWrite.All: privileged groups here are role-assignable -> CLEARED (protected)
    { id: "sp-ownerapp", appId: "22220000-0000-1111-2222-333333333333", displayName: "Group Lifecycle Owner", accountEnabled: true,
      appOwnerOrganizationId: "contoso-1111-2222-3333-444455556666",
      appRoles: ["User.Read.All"], directoryRoles: [], ownedApps: [],
      ownedGroups: ["grp-ra-priv"] },                      // owns a role-assignable priv group -> can add itself -> direct via group
  ],
  groups: [
    // Only role-assignable groups can hold directory roles.
    { id: "grp-admins", displayName: "Tier-0 Admins", isAssignableToRole: true,
      directoryRoles: ["Global Administrator"], members: ["sp-ingroup"], owners: [] },
    { id: "grp-ra-priv", displayName: "PrivRole Operators", isAssignableToRole: true,
      directoryRoles: ["Privileged Role Administrator"], members: [], owners: ["sp-ownerapp"] },
    { id: "grp-normal", displayName: "All Staff (not role-assignable)", isAssignableToRole: false,
      directoryRoles: [], members: [], owners: [] },
  ],
};

function doTenantAnalyze(rawText) {
  const note = document.getElementById("tenant-parse-note");
  try {
    const sinceEl = $id("tenant-since");
    const since = sinceEl && sinceEl.value ? sinceEl.value : null;
    const data = analyzeTenant(rawText, since ? { since } : undefined);
    data.since = since;
    note.className = "parse-note ok";
    note.textContent = `Parsed ${data.roll.total} apps. ${data.roll.ga} can reach Global Admin.` + (since ? ` Showing changes since ${since}.` : "");
    renderTenant(data);
  } catch (e) {
    note.className = "parse-note err";
    note.textContent = e.message || "Couldn't parse that export.";
    document.getElementById("tenant-results").innerHTML = "";
  }
}

// Clear pasted/loaded data from memory and the UI, so a sensitive export isn't
// left sitting in a tab. (Browser-local; there was never a server copy.)
function clearData(which) {
  if (which === "tenant") {
    const p = $id("tenant-paste"); if (p) p.value = "";
    const r = $id("tenant-results"); if (r) r.innerHTML = "";
    const n = $id("tenant-parse-note"); if (n) { n.className = "parse-note"; n.textContent = "Cleared."; }
    const b = $id("tanalyze"); if (b) b.disabled = true;
    const l = $id("file-label"); if (l) l.textContent = "Choose or drop a .json file";
    const si = $id("tenant-since"); if (si) si.value = "";
    tenantData = null;
  } else if (which === "partner") {
    const p = $id("partner-paste"); if (p) p.value = "";
    const r = $id("partner-results"); if (r) r.innerHTML = "";
    const n = $id("partner-parse-note"); if (n) { n.className = "parse-note"; n.textContent = "Cleared."; }
    const b = $id("panalyze"); if (b) b.disabled = true;
    const l = $id("pfile-label"); if (l) l.textContent = "Choose or drop a .json file";
    partnerData = null;
  }
}

// ---- Partner / GDAP export script (read-only) ----
const PARTNER_SCRIPT = `# ============================================================
#  Blast Radius — read-only PARTNER (GDAP) export
#  Run in the PARTNER tenant. Maps delegated reach into customers.
#  READ-ONLY: every call below is a *Get*. No writes. Read it first.
#
#  !! The file this produces maps every customer tenant a partner !!
#  !! compromise can reach — the single most sensitive file an MSP !!
#  !! can make. Treat it like a password vault: keep it off tickets !!
#  !! and email, and delete it the moment the analysis is done.     !!
# ============================================================
Connect-MgGraph -Scopes "DelegatedAdminRelationship.Read.All","Directory.Read.All","Group.Read.All"

# Resolve role GUIDs -> display names
$roleDefs = @{}
Get-MgRoleManagementDirectoryRoleDefinition -All | ForEach-Object { $roleDefs[$_.Id] = $_.DisplayName }
function Resolve-Roles($unified) { @($unified | ForEach-Object { $roleDefs[$_.RoleDefinitionId] ?? $_.RoleDefinitionId }) }

$rels = @(); $assigns = @(); $groupIds = @{}
foreach ($r in Get-MgTenantRelationshipDelegatedAdminRelationship -All) {
  $rels += [pscustomobject]@{
    id               = $r.Id
    customerTenantId = $r.Customer.TenantId
    customerName     = $r.Customer.DisplayName
    status           = $r.Status
    endDateTime      = $r.EndDateTime
    roles            = @(Resolve-Roles $r.AccessDetails.UnifiedRoles)
  }
  foreach ($a in Get-MgTenantRelationshipDelegatedAdminRelationshipAccessAssignment -DelegatedAdminRelationshipId $r.Id -All) {
    $gid = $a.AccessContainer.AccessContainerId
    $groupIds[$gid] = $true
    $assigns += [pscustomobject]@{
      relationshipId   = $r.Id
      customerTenantId = $r.Customer.TenantId
      securityGroupId  = $gid
      roles            = @(Resolve-Roles $a.AccessDetails.UnifiedRoles)
    }
  }
}

# Partner security groups referenced by assignments, with members
$groups = foreach ($gid in $groupIds.Keys) {
  $g = Get-MgGroup -GroupId $gid -ErrorAction SilentlyContinue
  if ($g) {
    $members = Get-MgGroupMember -GroupId $gid -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Id }
    [pscustomobject]@{ id = $gid; displayName = $g.DisplayName; members = @($members) }
  }
}

$export = [pscustomobject]@{
  partnerTenantId   = (Get-MgContext).TenantId
  generatedAt       = (Get-Date).ToString("o")
  gdapRelationships = @($rels)
  accessAssignments = @($assigns)
  securityGroups    = @($groups)
}
$stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
$file  = "blast-radius-partner-$stamp.json"
$export | ConvertTo-Json -Depth 8 | Out-File $file -Encoding utf8
Write-Host ""
Write-Host "Wrote $file"
Write-Host "SENSITIVE: this maps every customer a partner compromise can reach."
Write-Host "Paste it into Blast Radius (Partner / MSP), then DELETE it:  Remove-Item $file"`;

// Synthetic MSP with ~6 customers exercising full-takeover, scoped, DAP, expiry.
const SAMPLE_PARTNER = (() => {
  const soon = new Date(Date.now() + 12 * 864e5).toISOString();
  const past = new Date(Date.now() - 20 * 864e5).toISOString();
  const far  = new Date(Date.now() + 400 * 864e5).toISOString();
  return {
    partnerTenantId: "msp-9999-aaaa-bbbb-cccccccccccc",
    generatedAt: new Date().toISOString(),
    gdapRelationships: [
      { id: "rel-1", customerTenantId: "cust-acme", customerName: "Acme Manufacturing", status: "active", endDateTime: far, roles: ["Global Administrator"] },
      { id: "rel-2", customerTenantId: "cust-borealis", customerName: "Borealis Legal", status: "active", endDateTime: soon, roles: ["Exchange Administrator","User Administrator"] },
      { id: "rel-3", customerTenantId: "cust-cobalt", customerName: "Cobalt Clinic", status: "active", endDateTime: far, roles: ["Helpdesk Administrator","Global Reader"] },
      { id: "rel-4", customerTenantId: "cust-delta", customerName: "Delta Freight", status: "active", endDateTime: far, roles: ["Intune Administrator"] },
      { id: "rel-5", customerTenantId: "cust-echo", customerName: "Echo Media", status: "active", endDateTime: past, roles: ["Exchange Administrator"] },
      { id: "rel-6", customerTenantId: "cust-foxtrot", customerName: "Foxtrot Retail", status: "active", relationshipType: "DAP", isLegacyDap: true, roles: ["Global Administrator"] },
    ],
    accessAssignments: [
      { relationshipId: "rel-1", securityGroupId: "grp-l3", roles: ["Global Administrator"] },
      { relationshipId: "rel-2", securityGroupId: "grp-l1", roles: ["Exchange Administrator","User Administrator"] },
      { relationshipId: "rel-3", securityGroupId: "grp-l1", roles: ["Helpdesk Administrator"] },
      { relationshipId: "rel-4", securityGroupId: "grp-rmm", roles: ["Intune Administrator"] },
      { relationshipId: "rel-5", securityGroupId: "grp-l1", roles: ["Exchange Administrator"] },
      // Acme is ALSO reachable by the RMM app group at GA -> that app is a master key
      { relationshipId: "rel-1", securityGroupId: "grp-rmm", roles: ["Global Administrator"] },
    ],
    securityGroups: [
      { id: "grp-l3", displayName: "L3 Engineering", members: ["u-alice","u-bob"] },
      { id: "grp-l1", displayName: "L1 Helpdesk", members: ["u-carol","u-dave","u-erin"] },
      { id: "grp-rmm", displayName: "RMM Automation", members: ["sp-rmm"] },
    ],
    principals: [
      { id: "u-alice", displayName: "Alice (senior eng)", type: "user", mfa: true },
      { id: "u-bob", displayName: "Bob (eng)", type: "user", mfa: true },
      { id: "u-carol", displayName: "Carol (helpdesk)", type: "user", mfa: true },
      { id: "u-dave", displayName: "Dave (helpdesk)", type: "user", mfa: false },
      { id: "u-erin", displayName: "Erin (helpdesk)", type: "user", mfa: true },
      { id: "sp-rmm", displayName: "ConnectWise RMM", type: "servicePrincipal", mfa: null },
    ],
  };
})();

function doPartnerAnalyze(rawText) {
  const note = document.getElementById("partner-parse-note");
  try {
    const data = analyzePartner(rawText);
    note.className = "parse-note ok";
    note.textContent = `Mapped ${data.roll.customers} customers. ${data.roll.fullTakeover} fully takeable from this partner.`;
    renderPartner(data);
  } catch (e) {
    note.className = "parse-note err";
    note.textContent = e.message || "Couldn't parse that export.";
    document.getElementById("partner-results").innerHTML = "";
  }
}

// <<<STRIP-PUBLIC-END>>>

function init() {
  renderPresets(); renderPickList(); renderTray();
  const st = $id("script-text"); if (st) st.textContent = SCRIPT_TEXT;

  // scope (tenant/partner buttons only exist in the full build)
  on("mode-single", "click", () => switchScope("single"));
  on("mode-tenant", "click", () => switchScope("tenant"));
  on("mode-partner", "click", () => switchScope("partner"));

  // audience
  on("aud-tech", "click", () => switchAudience("tech"));
  on("aud-biz", "click", () => switchAudience("biz"));

  // single-app input (always present)
  on("tab-pick", "click", () => switchInput("pick"));
  on("tab-paste", "click", () => switchInput("paste"));
  on("search", "input", renderPickList);
  on("analyze", "click", () => { if (inputMode === "paste") parsePaste(); if (selected.size) analyze(); });
  on("script-toggle", "click", () => $id("script-box").classList.toggle("open"));
  on("copy-script", "click", e => copyText(SCRIPT_TEXT, e.target));
  on("paste", "input", () => { $id("analyze").disabled = !$id("paste").value.trim() && selected.size===0; });

  // tenant input (full build only)
  if (has("tenant-paste")) {
    const tst = $id("tscript-text"); if (tst) tst.textContent = TENANT_SCRIPT;
    const tpaste = $id("tenant-paste"), tbtn = $id("tanalyze");
    on("tenant-paste", "input", () => tbtn.disabled = !tpaste.value.trim());
    on("tanalyze", "click", () => doTenantAnalyze(tpaste.value));
    on("tenant-since", "change", () => { if (tpaste.value.trim()) doTenantAnalyze(tpaste.value); });
    on("tscript-toggle", "click", () => $id("tscript-box").classList.toggle("open"));
    on("tcopy-script", "click", e => copyText(TENANT_SCRIPT, e.target));
    on("load-sample", "click", () => { tpaste.value = JSON.stringify(SAMPLE_TENANT, null, 2); tbtn.disabled = false; doTenantAnalyze(tpaste.value); });
    on("tclear", "click", () => clearData("tenant"));
    wireFileDrop("tenant-file", "file-drop", "tenant-paste", "tanalyze", "file-label", doTenantAnalyze, "tenant-parse-note");
  }

  // partner input (full build only)
  if (has("partner-paste")) {
    const pst = $id("pscript-text"); if (pst) pst.textContent = PARTNER_SCRIPT;
    const ppaste = $id("partner-paste"), pbtn = $id("panalyze");
    on("partner-paste", "input", () => pbtn.disabled = !ppaste.value.trim());
    on("panalyze", "click", () => doPartnerAnalyze(ppaste.value));
    on("pscript-toggle", "click", () => $id("pscript-box").classList.toggle("open"));
    on("pcopy-script", "click", e => copyText(PARTNER_SCRIPT, e.target));
    on("pload-sample", "click", () => { ppaste.value = JSON.stringify(SAMPLE_PARTNER, null, 2); pbtn.disabled = false; doPartnerAnalyze(ppaste.value); });
    on("pclear", "click", () => clearData("partner"));
    wireFileDrop("partner-file", "pfile-drop", "partner-paste", "panalyze", "pfile-label", doPartnerAnalyze, "partner-parse-note");
  }

  const fm = $id("footer-meta");
  if (fm) fm.textContent =
    `Blast Radius v${typeof TOOL_VERSION!=="undefined"?TOOL_VERSION:"?"} · knowledge base v${KB_VERSION} · ${PERMISSIONS.length} permissions · ${ROLES.length} roles · ${CONTROLS.length + PARTNER_CONTROLS.length} controls · no network calls — verify in dev tools`;
}

function wireFileDrop(inputId, dropId, pasteId, btnId, labelId, analyzeFn, noteId) {
  const fileInput = $id(inputId), drop = $id(dropId);
  if (!fileInput || !drop) return;
  const read = file => {
    const fr = new FileReader();
    fr.onload = () => {
      $id(pasteId).value = fr.result;
      $id(btnId).disabled = false;
      const lab = $id(labelId); if (lab) lab.textContent = file.name;
      analyzeFn(fr.result);
    };
    fr.onerror = () => { const n = $id(noteId); if (n) { n.className = "parse-note err"; n.textContent = "Couldn't read that file."; } };
    fr.readAsText(file);
  };
  fileInput.addEventListener("change", e => { const f = e.target.files[0]; if (f) read(f); });
  ["dragenter","dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("drag"); }));
  ["dragleave","drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("drag"); }));
  drop.addEventListener("drop", e => { const f = e.dataTransfer.files[0]; if (f) read(f); });
}
function copyText(text, btn) {
  navigator.clipboard?.writeText(text).then(() => { const o = btn.textContent; btn.textContent = "Copied"; setTimeout(() => btn.textContent = o, 1500); });
}

document.addEventListener("DOMContentLoaded", init);
