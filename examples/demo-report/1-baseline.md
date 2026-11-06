# GoodHound Enterprise report

## Grand totals
| Metric | Value |
|---|---|
| Tenant | demo (CONTOSO.LOCAL) |
| Generated (UTC) | 2026-11-06 13:10 |
| Domains | CONTOSO.LOCAL |
| Enabled non-Tier Zero users | 386 |
| Non-Tier Zero users with a path | 386 |
| % of enabled non-Tier Zero users with a path | 100.0% |
| Start nodes with a path (total paths) | 9 |
| History | First run for this tenant: baseline recorded |
| Queries sent | 21 |

## Busiest paths
| # | Starting Node | Users with Path | % of Users | Hops | Exploit Cost | Risk Score | Path |
|---|---|---|---|---|---|---|---|
| 1 | DOMAIN USERS@CONTOSO.LOCAL | 386 | 100.0% | 2 | 3 | 90.3 | DOMAIN USERS@CONTOSO.LOCAL - CanRDP -> APP01.CONTOSO.LOCAL - HasSession -> ADM.KLEE@CONTOSO.LOCAL |
| 2 | DEVELOPERS@CONTOSO.LOCAL | 68 | 17.6% | 3 | 5 | 14.8 | DEVELOPERS@CONTOSO.LOCAL - GenericWrite -> SQL ADMINS@CONTOSO.LOCAL - AdminTo -> SQL01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL |
| 3 | FINANCE@CONTOSO.LOCAL | 38 | 9.8% | 1 | 2 | 9.2 | FINANCE@CONTOSO.LOCAL - ADCSESC1 -> CONTOSO.LOCAL |
| 4 | SERVER ADMINS@CONTOSO.LOCAL | 40 | 10.4% | 2 | 4 | 9.1 | SERVER ADMINS@CONTOSO.LOCAL - AdminTo -> SQL01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL |
| 5 | WORKSTATION ADMINS@CONTOSO.LOCAL | 40 | 10.4% | 2 | 4 | 9.1 | WORKSTATION ADMINS@CONTOSO.LOCAL - AdminTo -> WS-ADMIN01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL |

### Queries to view these paths

1. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-513'})-[:CanRDP]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1303'})-[:HasSession]->(n2 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1106'}) RETURN p LIMIT 1`
2. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1205'})-[:GenericWrite]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1204'})-[:AdminTo]->(n2 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1302'})-[:HasSession]->(n3 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1105'}) RETURN p LIMIT 1`
3. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1207'})-[:ADCSESC1]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330'}) RETURN p LIMIT 1`
4. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1203'})-[:AdminTo]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1302'})-[:HasSession]->(n2 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1105'}) RETURN p LIMIT 1`
5. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1209'})-[:AdminTo]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1301'})-[:HasSession]->(n2 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1105'}) RETURN p LIMIT 1`

## The weakest links
| # | Weakest Link | Paths | % of Paths | Users Exposed (sum) | Suggested Action |
|---|---|---|---|---|---|
| 1 | SQL01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL | 4 | 44.4% | 134 | Stop privileged accounts logging on to this host (tiering, PAWs, logon restrictions). |
| 2 | WORKSTATION ADMINS@CONTOSO.LOCAL - AdminTo -> WS-ADMIN01.CONTOSO.LOCAL | 3 | 33.3% | 109 | Remove local admin rights; use LAPS and least privilege. |
| 3 | WS-ADMIN01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL | 3 | 33.3% | 109 | Stop privileged accounts logging on to this host (tiering, PAWs, logon restrictions). |
| 4 | SQL ADMINS@CONTOSO.LOCAL - AdminTo -> SQL01.CONTOSO.LOCAL | 3 | 33.3% | 94 | Remove local admin rights; use LAPS and least privilege. |
| 5 | DEVELOPERS@CONTOSO.LOCAL - GenericWrite -> SQL ADMINS@CONTOSO.LOCAL | 2 | 22.2% | 93 | Remove the write ACE. |
