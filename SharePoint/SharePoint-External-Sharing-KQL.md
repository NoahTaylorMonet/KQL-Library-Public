# SharePoint Online — External Sharing Detection (KQL)

Advanced Hunting query for **Microsoft Defender XDR** (or Sentinel with the M365 Defender connector) that surfaces moments when SharePoint Online content is granted access to a user **outside your organization** — including anonymous links, guest invitations, "specific people" links sent externally, and direct ACL grants.

---

## What it does

For the last 30 days, the query inspects `CloudAppEvents` for SharePoint Online sharing/permission actions and keeps only the rows where the recipient is external. It enriches each event with the actor's UPN by joining to `IdentityInfo`, and returns who shared what, with whom, where, and from which IP.

### Actions covered

| Action | Why it's included |
|---|---|
| `AnonymousLinkCreated` / `AnonymousLinkUpdated` | "Anyone with the link" — external by definition |
| `SharingInvitationCreated` / `SharingInvitationAccepted` | Direct B2B guest invitation flow |
| `SecureLinkCreated` / `AddedToSecureLink` | "Specific people" links — kept only when recipient domain is not in your verified list |
| `SharingSet` | Explicit ACL grant on a file or folder |

### External logic

A row is treated as external if **any** of the following is true:
- It's an anonymous link (`ActionType` starts with `AnonymousLink`).
- The target user has no resolvable domain yet (`SharingInvitationCreated` before acceptance).
- The target domain is **not** in your `MyDomains` allowlist.

### Columns returned

`Timestamp`, `Actor` (UPN, falls back to display name), `ActionType`, `TargetUser`, `TargetDomain`, `IsAnonymous`, `SiteUrl`, `FileName`, `ClientIP`.

---

## Before you run it

1. Update `MyDomains` with **every verified domain** in your tenant (including `*.onmicrosoft.com`). Missing one will produce false positives.
2. Confirm `RawEventData` field names match your tenant by running:
   ```kusto
   CloudAppEvents
   | where ActionType == "SharingInvitationCreated"
   | take 5
   | project RawEventData
   ```
   Some tenants surface `UserSharedWith` vs `TargetUserOrGroupName` differently.

## Known limitations

- **Event-based, not standing access.** Shows the moment access is granted, not who currently has access. For a current-state inventory, use SharePoint admin sharing reports or the Graph `permissions` API.
- **Group grants can look anonymous.** A `SharingSet` to a security group containing a guest will have no domain and pass the "empty domain" branch — investigate group membership before concluding.
- **OneDrive personal sites** are not included here (scoped to `Microsoft SharePoint Online` only). Add `"Microsoft OneDrive for Business"` to the `Application` filter if you want OD4B too.
- **No DLP/sensitivity context.** "Externally shared" ≠ "sensitive data leaked." Join with `DataLossPreventionEvents` or label data for risk scoring.

---

## Query

```kusto
// SharePoint Online — access/permissions granted to EXTERNAL users only
let lookback = 30d;
let MyDomains = dynamic(["yourtenant.com","yourtenant.onmicrosoft.com"]);  // <-- Example domains, update with yours
let GrantActions = dynamic([
    // anonymous "Anyone with the link" — by definition external
    "AnonymousLinkCreated", "AnonymousLinkUpdated",
    // direct guest invitations
    "SharingInvitationCreated", "SharingInvitationAccepted",
    // "specific people" links — only external when target isn't internal
    "SecureLinkCreated", "AddedToSecureLink",
    // explicit ACL grant on an item
    "SharingSet"
]);
CloudAppEvents
| where Timestamp > ago(lookback)
| where Application == "Microsoft SharePoint Online"
| where ActionType in (GrantActions)
| extend Props = parse_json(RawEventData)
| extend TargetUser = tostring(coalesce(
        Props.TargetUserOrGroupName,
        Props.UserSharedWith,
        Props.TargetUserOrGroupType))
| extend TargetDomain = tolower(tostring(split(TargetUser, "@")[1]))
| extend IsAnonymous = ActionType startswith "AnonymousLink"
| where IsAnonymous
     or isempty(TargetDomain)            // sharing invitation before acceptance
     or TargetDomain !in (MyDomains)     // truly external recipient
| join kind=leftouter (
    IdentityInfo
    | summarize arg_max(Timestamp, AccountUpn) by AccountObjectId
) on AccountObjectId
| project Timestamp,
          Actor      = coalesce(AccountUpn, AccountDisplayName),
          ActionType,
          TargetUser,
          TargetDomain,
          IsAnonymous,
          SiteUrl    = tostring(Props.SiteUrl),
          FileName   = tostring(Props.ObjectId),
          ClientIP   = IPAddress
| order by Timestamp desc
```

---

## Where to run

- **Microsoft Defender portal** → Hunting → Advanced hunting
- **Microsoft Sentinel** (with M365 Defender connector enabled for `CloudAppEvents` + `IdentityInfo`)

## Suggested follow-ups

- Pivot by `Actor` to find top external sharers.
- Pivot by `TargetDomain` to spot unexpected partner domains.
- Schedule as a custom detection rule and alert when `IsAnonymous == true` on labeled-sensitive sites.
