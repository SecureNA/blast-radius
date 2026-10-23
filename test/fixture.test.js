// Fixture-based regression: loads the real fixtures through the actual engine
// (as the browser would), checks verdicts, flags, PascalCase tolerance, and the
// new v0.9 detections. Run: node test/fixture.test.js
const vm = require("vm"); const fs = require("fs"); const path = require("path");
const ROOT = path.join(__dirname, "..");

function makeEl(id){return{id:id||"el",_html:"",dataset:{},style:{},classList:{_s:new Set(),add(c){this._s.add(c)},remove(c){this._s.delete(c)},toggle(c){this._s.has(c)?this._s.delete(c):this._s.add(c)},contains(c){return this._s.has(c)}},hidden:false,tabIndex:0,value:"",textContent:"",files:[],children:[],setAttribute(){},getAttribute(){return null},hasAttribute(){return false},addEventListener(){},appendChild(c){this.children.push(c);return c;},querySelector(){return makeEl()},querySelectorAll(){return[]},closest(){return makeEl()},scrollIntoView(){},focus(){},click(){},remove(){},get innerHTML(){return this._html},set innerHTML(v){this._html=v;}};}
const els={};
const sb={document:{getElementById:id=>els[id]||(els[id]=makeEl(id)),querySelector:()=>null,querySelectorAll:()=>[],addEventListener:(ev,fn)=>{if(ev==="DOMContentLoaded")sb.__init=fn;},createElement:t=>makeEl(t),body:{dataset:{},appendChild(c){return c;},removeChild(){}}},navigator:{clipboard:{writeText:()=>Promise.resolve()}},FileReader:class{readAsText(){this.onload&&this.onload();}},alert:()=>{},setTimeout:fn=>fn(),console,Blob:class{constructor(a){this.parts=a}},URL:{createObjectURL:()=>"blob:x",revokeObjectURL(){}}};
vm.createContext(sb);
vm.runInContext(fs.readFileSync(path.join(ROOT,"kb.js"),"utf8")+"\n"+fs.readFileSync(path.join(ROOT,"app.js"),"utf8"), sb);

const tenant = JSON.parse(fs.readFileSync(path.join(ROOT,"fixtures/tenant-fixture.json"),"utf8"));
const partner = JSON.parse(fs.readFileSync(path.join(ROOT,"fixtures/partner-fixture.json"),"utf8"));

let ok=0, fail=0; const A=(c,m)=>{ (c?ok++:fail++); console.log((c?"PASS":"FAIL")+" "+m); };
const get = (r,id) => r.sps.find(s=>s.id===id);

// ---------- TENANT fixture ----------
sb.__tenant = tenant;
const rt = vm.runInContext("analyzeTenant(__tenant)", sb);

A(rt.roll.total === 7, "tenant fixture parses 7 apps ("+rt.roll.total+")");
A(get(rt,"sp-0003").finalSev === "direct", "Legacy Runner (RoleManagement.ReadWrite.Directory) => direct");
A(get(rt,"sp-0002").finalSev === "direct" && get(rt,"sp-0002").confirmedViaChain,
  "Teams Manager (Application.ReadWrite.All) => confirmed via backdoor chain to the privileged app");
A(get(rt,"sp-0001").finalSev === "none", "Backup app (data scopes only) => no known path");
A(get(rt,"sp-0001").credFlags.some(f=>/externally-owned/i.test(f.text) && f.sev==="high"),
  "Backup app (vendor-owned SP with tenant-side secret) => cross-tenant credential HIGH flag");

// PascalCase credential fields (StartDateTime/EndDateTime) parse for long-lived detection
A(get(rt,"sp-0001").credFlags.some(f=>/long-lived/i.test(f.text)),
  "PascalCase credential dates parsed (long-lived secret detected)");

// PIM-eligible distinct state
A(get(rt,"sp-0004").finalSev === "direct" && get(rt,"sp-0004").viaPim === true,
  "JIT Operations (eligible GA only) => direct but PIM-gated");
A(get(rt,"sp-0004").riskScore < get(rt,"sp-0003").riskScore,
  "PIM-gated GA scored below standing-direct ("+get(rt,"sp-0004").riskScore+" < "+get(rt,"sp-0003").riskScore+")");

// ownership: App Lifecycle Bot owns the role-assignable Tier-0 group => reaches GA via group ownership
A(get(rt,"sp-0006").finalSev === "direct" && get(rt,"sp-0006").groupProof,
  "App Lifecycle Bot owns a GA role-assignable group => direct via group ownership");

// human owner of the privileged Legacy Runner surfaced distinctly
A((get(rt,"sp-0003").ownerFindings||[]).some(f=>/Dana Admin/.test(f.text)),
  "human owner (Dana Admin) of privileged app surfaced as distinct finding");

// HR Group Sync: group-write, privileged group is role-assignable => cleared (protected)
A(get(rt,"sp-0007").finalSev === "conditional" && get(rt,"sp-0007").groupCleared,
  "HR Group Sync (Group.ReadWrite.All) => conditional, cleared (privileged group is protected role-assignable)");

// rollup new stats
A(rt.roll.crossTenantCreds >= 1, "rollup counts cross-tenant credential apps ("+rt.roll.crossTenantCreds+")");
A(rt.roll.pimGa === 1, "rollup counts 1 PIM-gated GA app ("+rt.roll.pimGa+")");

// changes-since filter honours the boundary
const rtSince = vm.runInContext("analyzeTenant(__tenant, {since:'2026-10-01'})", sb);
A(get(rtSince,"sp-0001").credFlags.some(f=>/after the review date/i.test(f.text)),
  "changes-since flags the backup secret created 2026-10-05");
const rtSince2 = vm.runInContext("analyzeTenant(__tenant, {since:'2026-10-10'})", sb);
A(!get(rtSince2,"sp-0001").credFlags.some(f=>/after the review date/i.test(f.text)),
  "changes-since does not flag the secret when date is after its start");

// ---------- PARTNER fixture (raw Graph shape: accessDetails.unifiedRoles GUIDs) ----------
sb.__partner = partner;
const rp = vm.runInContext("analyzePartner(__partner)", sb);
const cust = id => rp.custList.find(c=>c.id===id);
A(rp.roll.customers === 3, "partner fixture parses 3 customers ("+rp.roll.customers+")");
A(cust("cust-acme-0001").sev === "direct", "Acme (GA via GUID role) => full takeover, raw shape resolved");
A(cust("cust-borealis-0002").sev === "conditional", "Borealis (Exchange Admin) => scoped");
A(cust("cust-borealis-0002").relstat === "expiring", "Borealis relationship expiring (<30d) flagged");
const rmm = rp.keyList.find(k=>k.name.includes("RMM"));
A(rmm && rmm.directCount >= 1, "RMM Automation group is a master key (GA into Acme)");
A(rp.roll.noMfaMembers === 1, "1 admin without MFA (Dave) counted");

console.log(`\n${ok} passed, ${fail} failed`);
process.exit(fail?1:0);
