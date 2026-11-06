# GoodHound Enterprise report

## Grand totals
| Metric | Value |
|---|---|
| Tenant | demo (CONTOSO.LOCAL) |
| Generated (UTC) | 2026-11-06 13:10 |
| Domains | CONTOSO.LOCAL |
| Enabled non-Tier Zero users | 386 |
| Non-Tier Zero users with a path | 147 |
| % of enabled non-Tier Zero users with a path | 38.1% |
| Start nodes with a path (total paths) | 8 |
| Previous run | 2026-11-06T13:10:59+00:00 |
| New paths since last run | 0 |
| % of paths seen before | 100.0% |
| Paths no longer seen | 1 |
| Queries sent | 20 |

## Busiest paths
| # | Starting Node | Users with Path | % of Users | Hops | Exploit Cost | Risk Score | Path |
|---|---|---|---|---|---|---|---|
| 1 | DEVELOPERS@CONTOSO.LOCAL | 68 | 17.6% | 3 | 5 | 14.8 | DEVELOPERS@CONTOSO.LOCAL - GenericWrite -> SQL ADMINS@CONTOSO.LOCAL - AdminTo -> SQL01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL |
| 2 | FINANCE@CONTOSO.LOCAL | 38 | 9.8% | 1 | 2 | 9.2 | FINANCE@CONTOSO.LOCAL - ADCSESC1 -> CONTOSO.LOCAL |
| 3 | SERVER ADMINS@CONTOSO.LOCAL | 40 | 10.4% | 2 | 4 | 9.1 | SERVER ADMINS@CONTOSO.LOCAL - AdminTo -> SQL01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL |
| 4 | WORKSTATION ADMINS@CONTOSO.LOCAL | 40 | 10.4% | 2 | 4 | 9.1 | WORKSTATION ADMINS@CONTOSO.LOCAL - AdminTo -> WS-ADMIN01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL |
| 5 | IT SUPPORT@CONTOSO.LOCAL | 40 | 10.4% | 3 | 4 | 9.1 | IT SUPPORT@CONTOSO.LOCAL - MemberOf -> WORKSTATION ADMINS@CONTOSO.LOCAL - AdminTo -> WS-ADMIN01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL |

### Queries to view these paths

1. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1205'})-[:GenericWrite]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1204'})-[:AdminTo]->(n2 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1302'})-[:HasSession]->(n3 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1105'}) RETURN p LIMIT 1`
2. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1207'})-[:ADCSESC1]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330'}) RETURN p LIMIT 1`
3. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1203'})-[:AdminTo]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1302'})-[:HasSession]->(n2 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1105'}) RETURN p LIMIT 1`
4. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1209'})-[:AdminTo]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1301'})-[:HasSession]->(n2 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1105'}) RETURN p LIMIT 1`
5. `MATCH p=(n0 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1202'})-[:MemberOf]->(n1 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1209'})-[:AdminTo]->(n2 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1301'})-[:HasSession]->(n3 {objectid: 'S-1-5-21-1004336348-1177238915-682003330-1105'}) RETURN p LIMIT 1`

## The weakest links
| # | Weakest Link | Paths | % of Paths | Users Exposed (sum) | Suggested Action |
|---|---|---|---|---|---|
| 1 | SQL01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL | 4 | 50.0% | 134 | Stop privileged accounts logging on to this host (tiering, PAWs, logon restrictions). |
| 2 | WORKSTATION ADMINS@CONTOSO.LOCAL - AdminTo -> WS-ADMIN01.CONTOSO.LOCAL | 3 | 37.5% | 109 | Remove local admin rights; use LAPS and least privilege. |
| 3 | WS-ADMIN01.CONTOSO.LOCAL - HasSession -> ADM.JSMITH@CONTOSO.LOCAL | 3 | 37.5% | 109 | Stop privileged accounts logging on to this host (tiering, PAWs, logon restrictions). |
| 4 | SQL ADMINS@CONTOSO.LOCAL - AdminTo -> SQL01.CONTOSO.LOCAL | 3 | 37.5% | 94 | Remove local admin rights; use LAPS and least privilege. |
| 5 | DEVELOPERS@CONTOSO.LOCAL - GenericWrite -> SQL ADMINS@CONTOSO.LOCAL | 2 | 25.0% | 93 | Remove the write ACE. |

## Paths no longer seen since the previous run

- **DOMAIN USERS@CONTOSO.LOCAL**: DOMAIN USERS@CONTOSO.LOCAL - CanRDP -> APP01.CONTOSO.LOCAL - HasSession -> ADM.KLEE@CONTOSO.LOCAL
