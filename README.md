# Blast Radius: a proof-of-concept Entra app permission analyzer

Blast Radius tells you what happens when an Entra (Azure AD) application's credential is stolen. It answers three questions: what the attacker can reach, whether they can escalate to Global Admin, and which compensating controls actually help. I built it in response to the October 2026 ConnectWise Cloud Backup (formerly SkyKick) vendor-credential incident, and to the next one like it.

The tool runs entirely in your browser. It collects no data and makes no network calls.

> This is an analysis aid, not an audit. **"No known path" means nothing in the
> knowledge base matched, not that an app is safe.** Verify against the live tenant
> and current Microsoft documentation before acting.

## Two builds

The public build does less on purpose. Asking people to paste tenant exports into a random web page and promising "trust me bro, I'm not gathering data" is not responsible, and the industry needs to stop reinforcing that habit. The public build at https://pslorenz.github.io/blast-radius/ is a before-you-consent checker: pick or paste the permissions an app is requesting and see its blast radius before you grant anything.

The offline build adds whole-tenant analysis and GDAP partner mapping. It is meant for data you should never paste into someone else's URL, so don't host it publicly either. Run it from a local file or from hosting you control.

## Running the offline build

Download `blast-radius-local.html` from the releases page and open it in any modern browser, either by double-clicking it or through `file://`. The read-only PowerShell export scripts that produce tenant and GDAP data are embedded in the tool itself. The tenant export uses the Microsoft Graph PowerShell SDK and needs `Application.Read.All`, `Directory.Read.All`, and `RoleManagement.Read.Directory`.

## Verifying what you run

Check the file before you paste client data into it. Each release ships a `SHA256SUMS` file. Compare it against your download with `Get-FileHash .\blast-radius-local.html -Algorithm SHA256` on Windows or `sha256sum -c SHA256SUMS` on Linux and macOS.

You don't have to take the no-network claim on faith either. Both builds carry a Content Security Policy that blocks every outbound connection, and the exported reports carry one too. Open DevTools, watch the Network tab while you analyze a tenant, and confirm nothing leaves.

## What's inside

The core is a knowledge base of Entra application permissions and directory roles, classified into escalation tiers that mirror public research and Microsoft documentation. Every app gets a three-state Global Admin verdict: direct, conditional, or no known path.

The offline build resolves takeover chains transitively. It follows one app planting a credential on another, ownership of an app registration or service principal, group membership and role-assignable group paths, and GDAP reach across customer tenants. Paths that run through a PIM-eligible role, on the app itself or on a role-assignable group, get their own PIM-gated verdict: still a path, ranked below standing access.

Credential findings come with the reason each one fired. The strongest is a credential sitting on a vendor-owned or Microsoft-owned service principal in your tenant, which is the persistence pattern from the ConnectWise incident. A "changed since" date highlights every credential created on or after it. An allowlist in the source can quiet the cross-tenant rule for credentials you have reviewed; keep it short.

Both builds rank compensating controls by effort, license requirement, and effect, and both export print-ready client reports. The offline build's tenant export treats its own output like a password vault, and the Clear data button wipes a loaded export from the page when you're done.

## What it doesn't see

Blast Radius reasons about configuration, not activity. It cannot tell you what an attacker actually did, and unless Microsoft Graph activity logs were enabled before the incident, directory reads leave nothing for anyone else to find either. The "changed since" filter only sees credentials, because role assignments, group memberships, and consent grants carry no creation date in the export; use the directory audit log for those. The export does not read Conditional Access policy state, Azure RBAC on subscriptions, or app-role and access-package assignments that flow through non-role-assignable groups. Treat every verdict as a floor on the blast radius, never a ceiling.

The knowledge base carries a date. The tool shows its age in the header and stamps it on every exported report, and it warns once the knowledge base is more than 90 days old. A verdict is only as current as the research behind it.

## Sources and further research

Escalation classifications come from Emilien Socchi's Azure administrative tiering and the Maester `Test-MtHighRiskAppPermissions` list. Attack-path logic draws on SpecterOps/BloodHound and Horizon3.ai research. Permission descriptions come from the Microsoft Graph permissions reference (via graphpermissions.merill.net), and behavioral details from Microsoft Learn. Huntress's reporting on the ConnectWise/SkyKick vendor-credential incident prompted the project.

This project is independent and is not affiliated with or endorsed by Microsoft or any of the parties above. It is provided as-is. Validate every finding independently before making security decisions.
