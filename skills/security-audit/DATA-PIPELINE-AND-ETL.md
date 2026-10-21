# Data Pipeline and ETL Hunting

#### When to use this file

Reach for this file when the target extracts, transforms, or loads business data: scheduled scripts, notebooks, SQL or stored-procedure jobs, Power Query (M) and Power BI or Fabric models, dbt, Airflow, or other orchestrators, SaaS API syncs (Shopify, CRM, Dataverse, marketing platforms), shared-folder file drops, and CSV or Excel exports. This domain treats every source system as a writer the pipeline does not control and follows each record into every copy the pipeline makes. Use `DATA-ISOLATION-AND-LIFECYCLE.md` for multi-tenant application stores, `SUPPLY-CHAIN-AND-RELEASE.md` for CI and dependency trust, and `AI-AND-LLM.md` when pipeline data reaches a model or agent.

Split large targets into secrets and connections, source-data sinks, exports and derived copies, BI access models, and pipeline identities and scheduling.

## Core discipline (include in every agent prompt for this domain)

```
- Source-system data is lower-trust input. Customers, vendors, form submitters, and other staff write the values, column headers, sheet names, file names, and JSON keys a pipeline reads. Being "internal" does not make a source trusted.
- An exposed credential is a boundary failure, not a best-practice gap. Anyone who can read the repository, its history, a synced or shared folder, a notebook output, or a log gains that credential's authority. Name that reader as the lower-trust principal and the system the credential unlocks as the affected resource.
- Personal or regulated data copied to a place with a broader audience than its source (a repository, fixture, shared folder, email attachment, log, or wider BI audience) is a disclosure boundary. Require a real reader who is outside the data's intended audience.
- Follow each record through every copy: staging tables, temp files, notebook outputs, CSV and Excel extracts, logs, caches, BI datasets, and synced folders. Each copy has its own readers and retention.
- Pipeline identities (service accounts, app registrations, gateway credentials, API tokens, personal accounts used for scheduled refresh) are principals. Missing least privilege is hardening unless a lower-trust input or exposure can drive that identity.
- Never print, copy, or store a full secret value in any result, artifact, or report. Record the file, line, credential type, and a masked form such as the first four characters followed by `…`.
- Never connect to a real source, warehouse, tenant, SaaS API, gateway, or BI service, and never test whether a found credential works. Use local fixture files and local databases only.
- Use `confirmed` for source-visible failures with bounded local evidence. Use `needs_validation` for workspace sharing, tenant roles, gateway configuration, service-principal scopes, folder permissions, or retention settings that source does not show.
```

## Secrets and connection attack classes (subagent_type: `general`)

**Credentials in source, configuration, and notebooks**
Check `.env*`, `config.*`, `appsettings*.json`, `secrets.*`, YAML and TOML job configs, connection strings (`Password=`, `pwd=`, `User ID=` with a password, `AccountKey=`, `SharedAccessSignature=`, `sig=`), Power Query M (API keys in `Web.Contents` headers or query strings, embedded basic-auth), `.pbix` and `.pbit` files (the DataMashup part and connection metadata), `.ipynb` cells and saved outputs, shell and PowerShell scripts, and scheduler definitions. Look for vendor token formats such as `shpat_`, `shpss_`, `xoxb-`, `ghp_`, `AKIA`, `sk-`, Azure client secrets, `Bearer `, and `-----BEGIN`. Confirm that the file is tracked or shared and that the value is not an obvious placeholder (`changeme`, `<your-key>`, `xxx`, a documented sample key).

**Secrets in history and synced copies**
A secret removed from the current tree remains readable in version-control history, forks, cloned copies, OneDrive or SharePoint sync, backups, and previously shared exports. Search history for removed credential files and changed lines (`git log -p --all -S <pattern>` locally, on the local clone only). The fix is rotation plus removal; deleting the file alone is not a fix.

**Credential leakage through logs, errors, and outputs**
Jobs log full connection strings, request URLs that carry keys, environment dumps, HTTP debug traces with authorization headers, or exception text containing connection details. Notebooks persist printed tokens or authenticated responses in saved outputs. Confirm that the sink has readers beyond the credential's owner.

## Source-data injection attack classes (subagent_type: `general`)

**Query construction from source values**
Source values or identifiers are concatenated, f-string formatted, or `.format`ted into SQL, `Value.NativeQuery` M, DAX, OData `$filter`, FetchXML, GraphQL, Kusto, or shell commands. Include identifiers: table, column, schema, and sheet names derived from file headers, API keys, or folder names. The fix is parameters for values and allowlists for identifiers. Confirm the lower-trust writer of the field and the privileges of the executing connection.

**Unsafe deserialization and file loading**
Files from shared folders, vendor drops, email, or downloads are loaded with `pickle`, `joblib`, `pandas.read_pickle`, `numpy.load(allow_pickle=True)`, `torch.load` without `weights_only`, `yaml.load` without a safe loader, `eval`, or `exec`. XML parsers resolve external entities. Archive extraction trusts member paths (zip slip), and output paths are built from incoming file names. Require a writer to the input location who has lower trust than the job's identity.

**Spreadsheet formula injection in exports**
Source-controlled text beginning with `=`, `+`, `-`, `@`, tab, or carriage return is written to CSV or XLSX files that staff open in a spreadsheet application. Confirm that a lower-trust party controls the field, that the export reaches a human spreadsheet user, and that no escaping (a leading `'` or equivalent) happens at the export boundary. Machine-only consumers are not affected.

**Dynamic evaluation and templating of data**
Source strings reach `DataFrame.query`, `DataFrame.eval`, `eval`, `exec`, dynamic imports, regular expressions compiled from data (for denial of service against a shared job), or HTML templates for emailed reports rendered without autoescaping. Confirm the recipient context and what the evaluated content can reach.

## Data exposure and lifecycle attack classes (subagent_type: `general`)

**Personal and regulated data in extracts and fixtures**
Names, emails, phone numbers, addresses, payment data, HR or payroll fields, or health data are written to committed test fixtures, sample files, notebooks, local or synced folders, email attachments, or logs. Confirm the data class from schema or code and a reader broader than the source system's audience. Field names alone are not enough; show that real values flow there.

**BI row-level security and sharing**
In Power BI, Fabric, or similar models, check the following:
- RLS roles that use static filters where a per-user filter (`USERPRINCIPALNAME()`, `USERNAME()`) is intended.
- Roles defined but not applied to the secured table's filter path.
- Bidirectional or many-to-many relationships that propagate around a role filter.
- Measures on secured tables that use `ALL`, `REMOVEFILTERS`, `CROSSFILTER`, or `USERELATIONSHIP` in ways that expose totals or rows outside the role.
- Object-level security gaps.
- Report-level filters, hidden pages, or hidden visuals used as the only access control, even though Build permission, Analyze in Excel, export, and XMLA readers bypass them.

Workspace roles, app audiences, publish-to-web, and export settings are rarely in source; use `needs_validation` with the exact setting an owner must check.

**Staging, temp, and incremental-load residue**
Staging tables, temp files, scratch folders, caches, and failed-run leftovers keep full data longer or in a more widely readable place than the target. Incremental loads never propagate source deletions, so deleted or opted-out records persist downstream. Require a stated deletion or retention obligation, or a broader reader.

## Pipeline identity and scheduling attack classes (subagent_type: `general`)

**Over-privileged pipeline identities**
Extract jobs run as database owner, tenant or system administrator, all-scope SaaS tokens, or a person's own account for scheduled refresh, while needing read access to a few objects. This is hardening unless a lower-trust input, an exposed credential, or a shared writable job definition can drive the identity to an action outside the job's purpose. When one of those exists, the identity's excess authority sets the impact.

**Untrusted inputs steering job behavior**
Drop-folder files, config tables, spreadsheet tabs, or source records choose destination tables, file paths, URLs that the job fetches (SSRF), deletion scope, or which scripts run. Jobs read definitions or scripts from folders that more people can write than can run the job's identity. Compare who can write the input with who is trusted to run the job.

**Integrity failures a lower-trust party can trigger**
Upserts or dedupe keyed on a field that a source-side party controls, which overwrites or merges another customer's or company's records. Keys that omit company, entity, or environment. Partial-failure paths that commit half a load and then publish it. Pure data-quality defects with no lower-trust influence are hardening, not findings.

## Universal moves (apply across the above)

- For each source, name who can write it: customers, vendors, the public, other departments, or only the job owner. Treat everyone outside the last group as lower trust.
- Walk forward from each source field to every sink: query, file path, spreadsheet, template, log, BI model, and downstream API. Walk backward from each credential to every place it is stored, printed, or synced.
- Compare what the pipeline identity can do with what the job needs, then check whether any lower-trust input or exposure reaches that identity.
- Check failure and retry paths. Error handlers are where connection strings are logged, staging data is left behind, and partial loads are published.

## Validation rules (apply before reporting ANY finding here)

1. Name the lower-trust writer or reader, the field, file, or location it controls or can read, the sink or copy, and the resulting unauthorized query, code execution, credential authority, or disclosure.
2. A real-format credential in tracked source, history, a shared artifact, or a log is `confirmed` on source evidence alone. The observed result is its location, credential type, and masked value. Do not test validity; recommend rotation whether or not it still works. Base severity on the authority that source shows (scopes, target system, role). If that authority is not source-visible, rate it `medium` and put the scope check in the remediation.
3. Verify parameterization, escaping, safe loaders, and autoescape defaults for the pinned library version before claiming an injection or deserialization finding.
4. Keep local validation bounded: use a fixture file, a local SQLite or in-memory database, a dummy credential marker, and a scratch output directory. Do not refresh, publish, or query a real dataset, tenant, or service.
5. Return `needs_validation` with the precise setting when the decisive fact is workspace sharing, folder ACLs, gateway configuration, service-principal scope, or retention policy.
