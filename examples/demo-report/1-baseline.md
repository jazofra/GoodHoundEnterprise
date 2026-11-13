# GoodHound Enterprise report

## Grand totals
| Metric | Value |
|---|---|
| Tenant | demo (CONTOSO.LOCAL) |
| Generated (UTC) | 2026-11-06 18:42 |
| Domains | CONTOSO.LOCAL |
| Risk model | probability |
| Enabled non-Tier Zero users | 386 |
| Non-Tier Zero users with a path | 386 |
| % of enabled non-Tier Zero users with a path | 100.0% |
| Probability-weighted exposure | 35.84% |
| Start nodes with a path (total paths) | 9 |
| History | First run for this tenant: baseline recorded |
| Queries sent | 54 |

## Busiest paths
| # | Starting Node | Users | % of Users | Hops | Paths | Path Prob. | Reach Prob. | Risk | Path |
|---|---|---|---|---|---|---|---|---|---|
| 1 | DOMAIN USERS@CONTOSO.LOCAL | 386 | 100.0% | 2 | 1 | 20.8% | 20.8% | 20.75 | DOMAIN USERS@CONTOSO.LOCAL - CanRDP -> APP01.CONTOSO.LOCAL - HasSession -> ADM.KLEE@CONTOSO.LOCAL |
| 2 | FINANCE@CONTOSO.LOCAL | 38 | 9.8% | 1 | 1 | 85.5% | 85.5% | 8.42 | FINANCE@CONTOSO.LOCAL - ADCSESC1 -> CONTOSO.LOCAL |
| 3 | IT SUPPORT@CONTOSO.LOCAL | 40 | 10.4% | 3 | 2 | 46.7% | 71.6% | 7.42 | IT SUPPORT@CONTOSO.LOCAL - MemberOf -> WORKSTATION ADMINS@CONTOSO.LOCAL - AdminTo -> WS-ADMIN01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL |
| 4 | DEVELOPERS@CONTOSO.LOCAL | 68 | 17.6% | 3 | 1 | 39.9% | 39.9% | 7.03 | DEVELOPERS@CONTOSO.LOCAL - GenericWrite -> SQL ADMINS@CONTOSO.LOCAL - AdminTo -> SQL01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL |
| 5 | HELPDESK@CONTOSO.LOCAL | 29 | 7.5% | 4 | 2 | 46.7% | 71.6% | 5.38 | HELPDESK@CONTOSO.LOCAL - MemberOf -> IT SUPPORT@CONTOSO.LOCAL - MemberOf -> WORKSTATION ADMINS@CONTOSO.LOCAL - AdminTo -> WS-ADMIN01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL |

_Risk = reach probability x users in the starting node / all enabled non-Tier Zero users x 100: the expected % of users whose compromise reaches Tier Zero through it. Reach = chance that at least one visible path works; each hop's probability combines technique success, session freshness and a 5% chance per attacker action of being caught. Path shown = the most likely one. See docs/RISK_MODEL.md._

### Queries to view these paths

1. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-513'})-[:CanRDP]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1303'})-[:HasSession]->(n2 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1106'}) RETURN p LIMIT 1`
2. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1207'})-[:ADCSESC1]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330'}) RETURN p LIMIT 1`
3. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1202'})-[:MemberOf]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1209'})-[:AdminTo]->(n2 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1301'})-[:HasSession]->(n3 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1105'}) RETURN p LIMIT 1`
4. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1205'})-[:GenericWrite]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1204'})-[:AdminTo]->(n2 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1302'})-[:HasSession]->(n3 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1105'}) RETURN p LIMIT 1`
5. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1201'})-[:MemberOf]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1202'})-[:MemberOf]->(n2 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1209'})-[:AdminTo]->(n3 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1301'})-[:HasSession]->(n4 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1105'}) RETURN p LIMIT 1`

## The weakest links
| # | Weakest Link | Start Nodes | Users (distinct) | Exposure Removed | Suggested Action |
|---|---|---|---|---|---|
| 1 | APP01.CONTOSO.LOCAL - HasSession -> ADM.KLEE@CONTOSO.LOCAL | 1 | 386 | 12.85 pts | Stop privileged accounts logging on to this host (tiering, PAWs, logon restrictions). |
| 2 | DOMAIN USERS@CONTOSO.LOCAL - CanRDP -> APP01.CONTOSO.LOCAL | 1 | 386 | 12.85 pts | Restrict Remote Desktop Users / RDP logon rights. |
| 3 | FINANCE@CONTOSO.LOCAL - ADCSESC1 -> CONTOSO.LOCAL | 1 | 38 | 6.37 pts | Fix the vulnerable certificate template (ESC1). |
| 4 | SQL01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL | 6 | 109 | 6.03 pts | Stop privileged accounts logging on to this host (tiering, PAWs, logon restrictions). |
| 5 | SQL ADMINS@CONTOSO.LOCAL - AdminTo -> SQL01.CONTOSO.LOCAL | 3 | 69 | 3.45 pts | Remove local admin rights; use LAPS and least privilege. |

_Exposure removed = how far probability-weighted exposure drops if only this relationship is removed, counting each user once at their best remaining path. Users = distinct users whose risk depends on it. * = estimate._
