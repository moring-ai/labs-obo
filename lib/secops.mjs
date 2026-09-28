/**
 * labsOBO | steps 10-11 of the flow: what Agent A1 does with Defender.
 *
 * A1 picks a hunt from a fixed library of KQL (no model writes queries), runs it with
 * T_A1_DEFENDER against the Advanced Hunting endpoint from the runtime tool registry (lib/tools.mjs),
 * and turns the rows that come back into a finding with plain counting rules. Nothing is canned: an empty result is reported as
 * empty, and a table this tenant is not licensed for comes back as Defender's own error.
 *
 * Tables this tenant has (measured 2026-09-24): EntraIdSignInEvents, EntraIdSpnSignInEvents,
 * AlertInfo, AlertEvidence. Device* and Email* need Defender for Endpoint / Office licences.
 */
import { doHttp } from "./entra.mjs";

const SEV = ["Info", "Low", "Medium", "High"];
const worst = (a, b) => (SEV.indexOf(a) >= SEV.indexOf(b) ? a : b);
const tally = (rows, key) => rows.reduce((m, r) => ((m[r[key] ?? "(none)"] = (m[r[key] ?? "(none)"] ?? 0) + 1), m), {});
const topOf = (m, n = 3) => Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => `${k} (${v})`).join(", ");
const list = (v) => (Array.isArray(v) ? v.join(", ") : String(v ?? ""));
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;

const HUNTS = {
  agent: {
    title: "Agent A1 token activity", table: "EntraIdSpnSignInEvents + EntraIdSignInEvents", window: "24h",
    kql: ({ window, ids }) => `union
  (EntraIdSpnSignInEvents
   | where Timestamp > ago(${window})
   | where ApplicationId in ("${ids.bp}", "${ids.agent}")
   | extend Kind = "agent credential (T1)", OnBehalfOf = ""),
  (EntraIdSignInEvents
   | where Timestamp > ago(${window})
   | where ApplicationId in ("${ids.bp}", "${ids.agent}")
   | extend Kind = "on behalf of a user", OnBehalfOf = AccountUpn)
| project Timestamp, Kind, Application, OnBehalfOf, Resource = ResourceDisplayName, ErrorCode, IPAddress
| order by Timestamp desc
| take 100`,
    read(rows, { window }) {
      const failed = rows.filter((r) => Number(r.ErrorCode) !== 0);
      const evidence = [`${plural(rows.length, "token request")}: ${topOf(tally(rows, "Kind"))}`, `Resources: ${topOf(tally(rows, "Resource"))}`];
      if (failed.length) {
        const times = failed.map((r) => r.Timestamp).sort();
        evidence.push(`Failures by Entra error: ${Object.entries(tally(failed, "ErrorCode")).map(([c, n]) => `AADSTS${c} x${n}`).join(", ")}`,
                      `First failure ${times[0]}, last ${times.at(-1)}`);
      }
      return { severity: failed.length ? "Medium" : "Info",
        title: failed.length ? `${plural(failed.length, "failed token request")} by labsOBO-agent1 in the last ${window}`
                             : `labsOBO-agent1 made ${plural(rows.length, "token request")} in the last ${window}, none failed`,
        evidence, mitre: [] };
    },
  },
  failedSignins: {
    title: "Failed sign-ins by account", table: "EntraIdSignInEvents", window: "7d",
    kql: ({ window }) => `EntraIdSignInEvents
| where Timestamp > ago(${window})
| where ErrorCode != 0
| summarize Failures = count(), SourceIPs = dcount(IPAddress), ErrorCodes = make_set(ErrorCode, 5), Apps = make_set(Application, 5), LastSeen = max(Timestamp) by AccountUpn
| order by Failures desc
| take 50`,
    read(rows, { window }) {
      const spray = rows.filter((r) => Number(r.Failures) >= 20 && Number(r.SourceIPs) >= 5);
      const total = rows.reduce((s, r) => s + Number(r.Failures), 0);
      const severity = spray.length ? "High" : Number(rows[0].Failures) >= 5 ? "Medium" : "Low";
      return { severity,
        title: spray.length ? `Possible password spray: ${plural(spray.length, "account")} with 20+ failures from 5+ IPs`
                            : `${plural(total, "failed sign-in")} across ${plural(rows.length, "account")} in the last ${window}`,
        evidence: rows.slice(0, 5).map((r) => `${r.AccountUpn}: ${plural(Number(r.Failures), "failure")} from ${plural(Number(r.SourceIPs), "IP")}; errors ${list(r.ErrorCodes)}; apps ${list(r.Apps)}`),
        mitre: spray.length ? ["T1110.003 Password Spraying"] : [] };
    },
  },
  userSignins: {
    title: "Sign-ins for one user", table: "EntraIdSignInEvents", window: "7d",
    kql: ({ window, who }) => `EntraIdSignInEvents
| where Timestamp > ago(${window})
| where ${who.upn ? `AccountUpn =~ "${who.upn}"` : `AccountObjectId == "${who.oid}"`}
| project Timestamp, Application, Resource = ResourceDisplayName, ErrorCode, IPAddress, Country, City, ClientAppUsed, RiskLevelDuringSignIn
| order by Timestamp desc
| take 100`,
    read(rows, { window, who }) {
      const failed = rows.filter((r) => Number(r.ErrorCode) !== 0);
      const risky = rows.filter((r) => Number(r.RiskLevelDuringSignIn) > 0);
      const severity = risky.length || failed.length >= 5 ? "Medium" : failed.length ? "Low" : "Info";
      return { severity,
        title: `${who.label}: ${plural(rows.length, "sign-in")} in the last ${window}, ${failed.length} failed`,
        evidence: [`Apps: ${topOf(tally(rows, "Application"))}`, `Locations: ${topOf(tally(rows, "Country"))}; ${plural(new Set(rows.map((r) => r.IPAddress)).size, "IP")}`,
                   ...(failed.length ? [`Failures by Entra error: ${Object.entries(tally(failed, "ErrorCode")).map(([c, n]) => `AADSTS${c} x${n}`).join(", ")}`] : []),
                   ...(risky.length ? [`${plural(risky.length, "sign-in")} flagged risky by Entra ID Protection`] : [])],
        mitre: [] };
    },
  },
  alerts: {
    title: "Defender alerts", table: "AlertInfo + AlertEvidence", window: "7d",
    kql: ({ window }) => `AlertInfo
| where Timestamp > ago(${window})
| join kind=leftouter (AlertEvidence
    | where Timestamp > ago(${window})
    | summarize Entities = make_set(coalesce(DeviceName, AccountUpn, RemoteUrl, FileName), 10) by AlertId) on AlertId
| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, Entities
| order by Timestamp desc
| take 50`,
    read(rows, { window }) {
      const map = { High: "High", Medium: "Medium", Low: "Low", Informational: "Info" };
      const severity = rows.map((r) => map[r.Severity] ?? "Info").reduce(worst, "Info");
      return { severity, title: `${plural(rows.length, "Defender alert")} in the last ${window}`,
        evidence: rows.slice(0, 5).map((r) => `${r.Severity}: ${r.Title} (${r.ServiceSource}); entities ${list(r.Entities) || "none"}`), mitre: [] };
    },
  },
  powershell: {
    title: "Encoded PowerShell", table: "DeviceProcessEvents", window: "24h",
    kql: ({ window }) => `DeviceProcessEvents
| where Timestamp > ago(${window})
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "FromBase64String")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
| take 100`,
    read(rows, { window }) {
      const office = rows.filter((r) => /^(winword|excel|powerpnt|outlook)\.exe$/i.test(r.InitiatingProcessFileName ?? ""));
      return { severity: office.length ? "High" : "Medium", title: `${rows.length} encoded PowerShell launch${rows.length === 1 ? "" : "es"} in the last ${window}`,
        evidence: [`Devices: ${topOf(tally(rows, "DeviceName"))}`, `Started by: ${topOf(tally(rows, "InitiatingProcessFileName"))}`], mitre: ["T1059.001 PowerShell"] };
    },
  },
  phishing: {
    title: "Clicked phishing links", table: "EmailEvents + UrlClickEvents", window: "7d",
    kql: ({ window }) => `EmailEvents
| where Timestamp > ago(${window})
| where ThreatTypes has "Phish"
| join kind=inner (UrlClickEvents | where ActionType == "ClickAllowed") on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, Url
| take 100`,
    read(rows, { window }) {
      return { severity: "Medium", title: `${plural(rows.length, "allowed click")} on phishing links in the last ${window}`,
        evidence: [`Recipients: ${topOf(tally(rows, "RecipientEmailAddress"))}`, `Senders: ${topOf(tally(rows, "SenderFromAddress"))}`], mitre: ["T1566.002 Spearphishing Link"] };
    },
  },
};

/** Step 10's input: read the prompt, choose the hunt, the time window, and whether a ticket was asked for. */
export function planInvestigation(prompt, { user, ids }) {
  const text = String(prompt ?? "");
  const t = text.toLowerCase();
  const wantsTicket = /\b(jira|ticket|issue|incident ticket|escalat)/.test(t);
  if (/who am i|acting as|whoami|on behalf of me|my identity/.test(t) && !/sign-?in|hunt|kql|alert|token/.test(t))
    return { intent: "identity", wantsTicket: false, steps: ["Read T_APP_A1: who asked, through which client"] };
  const upn = /\b[\w.+-]+@[\w-]+(\.[\w-]+)+\b/.exec(text)?.[0] ?? null;
  const key = /\b(agent|a1|labsobo|t1|blueprint|token exchange|token request|service principal|workload)\b/.test(t) ? "agent"
    : /powershell|encoded|base64|process/.test(t) ? "powershell"
    : /phish|e-?mail|click/.test(t) ? "phishing"
    : /(fail|spray|brute|password|lockout)/.test(t) && /sign-?in|logon|log-?in|auth/.test(t) ? "failedSignins"
    : /sign-?in|logon|log-?in/.test(t) ? "userSignins"
    : "alerts";
  const h = HUNTS[key];
  const m = /\b(\d+)\s*(h|hr|hrs|hours?|d|days?)\b/.exec(t);
  const window = m ? `${m[1]}${m[2].startsWith("h") ? "h" : "d"}` : /today|last day/.test(t) ? "24h" : /week/.test(t) ? "7d" : /month/.test(t) ? "30d" : h.window;
  const who = { oid: user.oid, upn, label: upn ?? user.name };
  return { intent: "hunt", hunt: key, title: h.title, table: h.table, window, who, wantsTicket, kql: h.kql({ window, ids, who }),
    steps: ["Get T1: prove I am labsOBO-agent1", "Find the Defender tool in the runtime registry",
            "Get T_A1_DEFENDER by OBO: Entra grants whatever an admin consented for A1; you stay the user",
            `Run KQL on ${h.table}, last ${window}${upn ? ` for ${upn}` : ""}`, "Analyse the rows",
            wantsTicket ? "If it needs a ticket: T_A1_BROKER by OBO, then the Jira broker creates it as you" : "Report back (no ticket asked for)"] };
}

/** Step 10: POST the KQL to the Advanced Hunting endpoint (from the registry) with T_A1_DEFENDER. */
export async function runHunt(token, kql, endpoint) {
  const r = await doHttp({ method: "POST", url: endpoint, headers: { Authorization: `Bearer ${token}` }, json: { Query: kql },
                           secretNames: { bearer: "T_A1_DEFENDER" }, timeoutMs: 90000 });
  const b = r.response.body && typeof r.response.body === "object" ? r.response.body : {};
  const columns = (b.Schema ?? []).map((c) => c.Name);
  const rows = b.Results ?? [];
  return { ok: r.ok, http: r, columns, rows, rowCount: rows.length, ms: r.response.durationMs,
           error: r.ok ? null : (b.error?.message ?? (typeof r.response.body === "string" ? r.response.body.slice(0, 300) : `HTTP ${r.response.status}`)) };
}

/** Step 11: deterministic analysis of the rows, and the decision whether a Jira ticket is needed. */
export function triage(plan, result, user) {
  const h = HUNTS[plan.hunt];
  const ctx = { window: plan.window, who: plan.who };
  if (!result.ok) return { finding: null, needsTicket: false, summary: `Defender refused the query: ${result.error}`, reason: "the hunt failed" };
  if (!result.rowCount) return { finding: null, needsTicket: false, summary: `No matching events in ${h.table} for the last ${plan.window}.`,
                                 reason: plan.wantsTicket ? "nothing was found, so there is nothing to ticket" : null };
  const finding = h.read(result.rows, ctx);
  const needsTicket = plan.wantsTicket && SEV.indexOf(finding.severity) >= SEV.indexOf("Medium");
  const reason = !plan.wantsTicket ? null : needsTicket ? `severity is ${finding.severity}` : `severity is only ${finding.severity}, below the Medium bar for a ticket`;
  const issue = needsTicket ? {
    summary: finding.title,
    labels: ["labsOBO", "defender", plan.hunt],
    description: [`Found by labsOBO-agent1 while hunting ${h.table} (last ${plan.window}) in Microsoft Defender Advanced Hunting.`, "",
                  `Severity: ${finding.severity}`, "", "Evidence:", ...finding.evidence.map((e) => `- ${e}`), "",
                  ...(finding.mitre.length ? [`MITRE ATT&CK: ${finding.mitre.join(", ")}`, ""] : []),
                  "Query:", "```", plan.kql, "```"],
  } : null;
  return { finding, needsTicket, reason, issue,
           summary: `${finding.title}. ${plural(result.rowCount, "row")} from ${h.table}, queried as ${user.name}.` };
}
