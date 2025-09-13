# SAFE-MCP: Security Analysis Framework for Evaluation of Model Context Protocol

## About SAFE-MCP

SAFE-MCP is a comprehensive security framework for documenting and mitigating threats in the Model Context Protocol (MCP) ecosystem. This framework adapts the proven MITRE ATT&CK methodology specifically for MCP environments, providing structured documentation of adversary tactics, techniques, and procedures (TTPs) that target MCP implementations and AI-powered applications.

### Key Features

- **MITRE ATT&CK Alignment**: We use patterns and methodologies from the MITRE ATT&CK Framework, explicitly targeting MCP-specific threats while maintaining compatibility with established security practices.
- **Compliance Mapping**: Each SAFE-MCP technique links to corresponding MITRE ATT&CK techniques where applicable, helping organizations determine compliance with existing security frameworks and controls.
- **Comprehensive Coverage**: Documenting attack techniques across 14 tactical categories, from initial access to impact, with continuous additions as new threats emerge.
- **Actionable Mitigations**: Each technique includes detailed mitigation strategies and detection rules to help defenders protect their MCP deployments.

### How to Use This Framework

1. **Security Teams**: Use the TTP reference table below to understand potential threats to your MCP implementation
2. **Developers**: Review techniques relevant to your MCP tools and implement recommended mitigations
3. **Compliance Officers**: Map SAFE-MCP techniques to your existing security controls via MITRE ATT&CK linkages
4. **Red Teams**: Reference attack techniques for security testing of MCP deployments

## TTP Reference Table

This table provides a comprehensive reference of all Tactics, Techniques, and Procedures (TTPs) defined in the SAFE-MCP framework.

## SAFE-MCP Tactics

The SAFE-MCP framework defines 14 tactics that align with the MITRE ATT&CK methodology:

| Tactic ID | Tactic Name | Description |
|-----------|-------------|-------------|
| ATK-TA0043 | Reconnaissance | The adversary is trying to gather information they can use to plan future operations |
| ATK-TA0042 | Resource Development | The adversary is trying to establish resources they can use to support operations |
| ATK-TA0001 | Initial Access | The adversary is trying to get into your MCP environment |
| ATK-TA0002 | Execution | The adversary is trying to run malicious code via MCP |
| ATK-TA0003 | Persistence | The adversary is trying to maintain their foothold in MCP |
| ATK-TA0004 | Privilege Escalation | The adversary is trying to gain higher-level permissions |
| ATK-TA0005 | Defense Evasion | The adversary is trying to avoid being detected |
| ATK-TA0006 | Credential Access | The adversary is trying to steal account names and passwords |
| ATK-TA0007 | Discovery | The adversary is trying to figure out your MCP environment |
| ATK-TA0008 | Lateral Movement | The adversary is trying to move through your environment |
| ATK-TA0009 | Collection | The adversary is trying to gather data of interest |
| ATK-TA0011 | Command and Control | The adversary is trying to communicate with compromised systems |
| ATK-TA0010 | Exfiltration | The adversary is trying to steal data |
| ATK-TA0040 | Impact | The adversary is trying to manipulate, interrupt, or destroy systems and data |

## TTP Overview

| Tactic ID | Tactic Name | Technique ID | Technique Name | Description |
|-----------|-------------|--------------|----------------|-------------|
| **ATK-TA0043** | **Reconnaissance** | | | *No MCP-specific techniques currently documented* |
| **ATK-TA0042** | **Resource Development** | | | *No MCP-specific techniques currently documented* |
| **ATK-TA0001** | **Initial Access** | [SAFE-T1001](techniques/SAFE-T1001/README.md) | Tool Poisoning Attack (TPA) | Attackers embed malicious instructions within MCP tool descriptions that are invisible to users but processed by LLMs |
| ATK-TA0001 | Initial Access | SAFE-T1002 | Supply Chain Compromise | Distribution of backdoored MCP server packages through unofficial repositories or compromised legitimate sources |
| ATK-TA0001 | Initial Access | SAFE-T1003 | Malicious MCP-Server Distribution | Adversary ships a trojanized server package or Docker image that users install, gaining foothold when the host registers its tools |
| ATK-TA0001 | Initial Access | SAFE-T1004 | Server Impersonation / Name-Collision | Attacker registers a server with the same name/URL as a trusted one, or hijacks discovery, so the client connects to them instead |
| ATK-TA0001 | Initial Access | SAFE-T1005 | Exposed Endpoint Exploit | Misconfigured public MCP endpoints (no auth, debug on) let attackers connect, enumerate tools or trigger RCE |
| ATK-TA0001 | Initial Access | SAFE-T1006 | User-Social-Engineering Install | Phishing/social posts persuade developers to "try this cool tool"; the installer silently registers dangerous capabilities |
| ATK-TA0001 | Initial Access | [SAFE-T1007](techniques/SAFE-T1007/README.md) | OAuth Authorization Phishing | Malicious MCP servers exploit OAuth flows to steal access tokens from legitimate services by tricking users during authorization |
| ATK-TA0001 | Initial Access | SAFE-T1008 | Authorization Server Mix-up | Client follows redirect to look-alike AS domain (e.g., accounts-google.com vs accounts.google.com), causing authorization codes or tokens to be leaked to attacker-controlled server |
| **ATK-TA0002** | **Execution** | SAFE-T1101 | Command Injection | Exploitation of unsanitized input in MCP server implementations leading to remote code execution |
| ATK-TA0002 | Execution | [SAFE-T1102](techniques/SAFE-T1102/README.md) | Prompt Injection (Multiple Vectors) | Malicious instructions injected through various vectors to manipulate AI behavior via MCP |
| ATK-TA0002 | Execution | SAFE-T1103 | Fake Tool Invocation (Function Spoofing) | Adversary forges JSON that mimics an MCP function-call message, tricking the host into running a tool that was never offered |
| ATK-TA0002 | Execution | [SAFE-T1104](techniques/SAFE-T1104/README.md) | Over-Privileged Tool Abuse | Legit tool (e.g. "Shell") runs with broader OS rights than necessary; LLM can be induced to perform arbitrary commands |
| ATK-TA0002 | Execution | [SAFE-T1105](techniques/SAFE-T1105/README.md) | Path Traversal via File Tool | File-handling tool accepts relative paths like ../../secret.key; attacker leaks host secrets |
| ATK-TA0002 | Execution | [SAFE-T1106](techniques/SAFE-T1106/README.md) | Autonomous Loop Exploit | Craft prompts that push an agent into infinite "self-invoke" loop to exhaust CPU or hit rate limits (DoS) |
| ATK-TA0002 | Execution | [SAFE-T1109](techniques/SAFE-T1109/README.md) | Debugging Tool Exploitation | Browser-based remote code execution via vulnerable MCP Inspector (CVE-2025-49596) |
| ATK-TA0002 | Execution | [SAFE-T1110](techniques/SAFE-T1110/README.md) | Multimodal Prompt Injection via Images/Audio | Embedding malicious instructions within image or audio content to manipulate multimodal AI behavior |
| **ATK-TA0003** | **Persistence** | [SAFE-T1201](techniques/SAFE-T1201/README.md) | MCP Rug Pull Attack | Time-delayed malicious tool definition changes after initial approval |
| ATK-TA0003 | Persistence | SAFE-T1202 | OAuth Token Persistence | Theft and reuse of OAuth access/refresh tokens for persistent access to MCP-connected services, including replay of refresh tokens after legitimate client sessions end |
| ATK-TA0003 | Persistence | SAFE-T1203 | Backdoored Server Binary | Inserts cron job or reverse shell on install; persists even if MCP service is uninstalled |
| ATK-TA0003 | Persistence | SAFE-T1204 | Context Memory Implant | Malicious agent writes itself into long-term vector store; re-loaded in every future session |
| ATK-TA0003 | Persistence | SAFE-T1205 | Persistent Tool Redefinition | Attacker modifies server's tool metadata to keep hidden commands across restarts |
| ATK-TA0003 | Persistence | SAFE-T1206 | Credential Implant in Config | Adds attacker's API/SSH keys to server .env, giving re-entry |
| ATK-TA0003 | Persistence | SAFE-T1207 | Hijack Update Mechanism | Man-in-the-middle an auto-update channel to re-install malicious build later on |
| ATK-TA0003 | Persistence | [SAFE-T2106](techniques/SAFE-T2106/README.md) | Context Memory Poisoning via Vector Store Contamination | Attackers manipulate vector databases storing long-term memory for AI agents, creating persistent malicious content that contaminates knowledge across all future sessions |
| **ATK-TA0004** | **Privilege Escalation** | SAFE-T1301 | Cross-Server Tool Shadowing | Malicious MCP servers override legitimate tool calls to gain elevated privileges |
| ATK-TA0004 | Privilege Escalation | SAFE-T1302 | High-Privilege Tool Abuse | Invoke a VM-level or root tool from normal user context |
| ATK-TA0004 | Privilege Escalation | SAFE-T1303 | Sandbox Escape via Server Exec | Exploit vulnerable server to break container/seccomp isolation |
| ATK-TA0004 | Privilege Escalation | [SAFE-T1304](techniques/SAFE-T1304/README.md) | Credential Relay Chain | Use one tool to steal tokens, feed them to second tool with higher privileges |
| ATK-TA0004 | Privilege Escalation | SAFE-T1305 | Host OS Priv-Esc (RCE) | Achieve root via misconfigured service running as root, then alter host |
| ATK-TA0004 | Privilege Escalation | SAFE-T1306 | Rogue Authorization Server | Malicious MCP server redirects OAuth flows to attacker-controlled AS that ignores audience restrictions and Proof of Possession (PoP), minting overly-permissive "super-tokens" with expanded scopes |
| ATK-TA0004 | Privilege Escalation | SAFE-T1307 | Confused Deputy Attack | MCP server receives token for one user (Alice) and forwards it to another user's (Bob) MCP instance, allowing Bob to perform actions as Alice by exploiting the server's trusted position |
| ATK-TA0004 | Privilege Escalation | SAFE-T1308 | Token Scope Substitution | Attacker swaps a limited-scope token with one that has broader permissions but same audience, exploiting insufficient scope validation to gain elevated privileges |
| **ATK-TA0005** | **Defense Evasion** | SAFE-T1401 | Line Jumping | Bypassing security checkpoints through context injection before tool invocation |
| ATK-TA0005 | Defense Evasion | SAFE-T1402 | Instruction Steganography | Zero-width chars/HTML comments hide directives in tool metadata |
| ATK-TA0005 | Defense Evasion | SAFE-T1403 | Consent-Fatigue Exploit | Repeated benign prompts desensitize user; crucial request hidden mid-flow |
| ATK-TA0005 | Defense Evasion | SAFE-T1404 | Response Tampering | Model instructed not to mention risky action, keeping UI output "harmless" |
| ATK-TA0005 | Defense Evasion | SAFE-T1405 | Tool Obfuscation/Renaming | Malicious tool named "Utils-Helper" to blend in among 30 legit tools |
| ATK-TA0005 | Defense Evasion | SAFE-T1406 | Metadata Manipulation | Strip safety flags or lower risk scores in tool manifest before host logs it |
| ATK-TA0005 | Defense Evasion | SAFE-T1407 | Server Proxy Masquerade | Malicious server silently proxies legit API so traffic looks normal in network logs |
| ATK-TA0005 | Defense Evasion | SAFE-T1408 | OAuth Protocol Downgrade | Attacker forces use of less secure OAuth 2.0 implicit flow instead of authorization code flow, bypassing PKCE protections and enabling easier token theft |
| **ATK-TA0006** | **Credential Access** | SAFE-T1501 | Full-Schema Poisoning (FSP) | Exploitation of entire MCP tool schema beyond descriptions for credential theft |
| ATK-TA0006 | Credential Access | SAFE-T1502 | File-Based Credential Harvest | Use file tools to read SSH keys, cloud creds |
| ATK-TA0006 | Credential Access | SAFE-T1503 | Env-Var Scraping | Ask read_file for .env; exfil API secrets |
| ATK-TA0006 | Credential Access | SAFE-T1504 | Token Theft via API Response | Prompt LLM to call "session.token" tool, then leak result |
| ATK-TA0006 | Credential Access | SAFE-T1505 | In-Memory Secret Extraction | Query vector store for "api_key" embedding strings |
| ATK-TA0006 | Credential Access | SAFE-T1506 | Infrastructure Token Theft | Steal OAuth/session tokens from logs, TLS termination proxies, or other infrastructure components where tokens may be inadvertently stored or exposed, then replay at intended service |
| ATK-TA0006 | Credential Access | SAFE-T1507 | Authorization Code Interception | Man-in-the-browser attack steals OAuth authorization codes during the redirect flow and attempts to exchange them at the token endpoint before the legitimate client |
| **ATK-TA0007** | **Discovery** | SAFE-T1601 | MCP Server Enumeration | Unauthorized discovery and mapping of available MCP servers and tools |
| ATK-TA0007 | Discovery | SAFE-T1602 | Tool Enumeration | Call tools/list to see available functions |
| ATK-TA0007 | Discovery | SAFE-T1603 | System-Prompt Disclosure | Coax model into printing its system prompt/tool JSON |
| ATK-TA0007 | Discovery | SAFE-T1604 | Server Version Enumeration | GET /version or header analysis for vulnerable builds |
| ATK-TA0007 | Discovery | SAFE-T1605 | Capability Mapping | Ask "what can you do?"; model outlines high-value tools |
| ATK-TA0007 | Discovery | SAFE-T1606 | Directory Listing via File Tool | List root dir to find sensitive paths |
| **ATK-TA0008** | **Lateral Movement** | SAFE-T1701 | Cross-Tool Contamination | Using compromised MCP tools to access other connected services and systems |
| ATK-TA0008 | Lateral Movement | SAFE-T1702 | Shared-Memory Poisoning | Write false tasks to shared vector DB so peer agents execute them |
| ATK-TA0008 | Lateral Movement | SAFE-T1703 | Tool-Chaining Pivot | Compromise low-priv tool, then leverage it to call another privileged tool indirectly |
| ATK-TA0008 | Lateral Movement | SAFE-T1704 | Compromised-Server Pivot | Use hijacked server as beachhead to infect other hosts in same IDE/workspace |
| ATK-TA0008 | Lateral Movement | SAFE-T1705 | Cross-Agent Instruction Injection | Inject directives in multi-agent message bus to seize control of cooperating agents |
| ATK-TA0008 | Lateral Movement | SAFE-T1706 | OAuth Token Pivot Replay | Attacker reuses OAuth tokens across different services by exploiting either shared Authorization Server trust (e.g., GitHub token used at Slack) or Resource Servers that fail to validate audience claims, enabling unauthorized cross-service access |
| ATK-TA0008 | Lateral Movement | SAFE-T1707 | CSRF Token Relay | Leaked OAuth token is passed via Cross-Site Request Forgery to access different resources on the same Resource Server (e.g., pivoting between GCP projects under same Google AS) |
| **ATK-TA0009** | **Collection** | SAFE-T1801 | Automated Data Harvesting | Systematic data collection through manipulated MCP tool calls |
| ATK-TA0009 | Collection | SAFE-T1802 | File Collection | Batch-read sensitive files for later exfil |
| ATK-TA0009 | Collection | SAFE-T1803 | Database Dump | Use SQL tool to SELECT * from prod DB |
| ATK-TA0009 | Collection | SAFE-T1804 | API Data Harvest | Loop over customer REST endpoints via HTTP tool |
| ATK-TA0009 | Collection | SAFE-T1805 | Context Snapshot Capture | Query vector store embeddings wholesale |
| **ATK-TA0011** | **Command and Control** | SAFE-T1901 | Outbound Webhook C2 | LLM calls "http.post" to attacker URL with commands/results |
| ATK-TA0011 | Command and Control | SAFE-T1902 | Covert Channel in Responses | Encode data in whitespace or markdown links returned to chat |
| ATK-TA0011 | Command and Control | SAFE-T1903 | Malicious Server Control Channel | Attacker operates rogue server; every tool call doubles as heartbeat |
| ATK-TA0011 | Command and Control | SAFE-T1904 | Chat-Based Backchannel | LLM embeds base64 blobs in normal answers that another bot decodes |
| **ATK-TA0010** | **Exfiltration** | SAFE-T1910 | Covert Channel Exfiltration | Data smuggling through tool parameters, error messages, or legitimate-appearing operations |
| ATK-TA0010 | Exfiltration | SAFE-T1911 | Parameter Exfiltration | Sneak secrets into unused JSON arg (note) |
| ATK-TA0010 | Exfiltration | SAFE-T1912 | Stego Response Exfil | Hide data in code blocks shown to user then copied elsewhere |
| ATK-TA0010 | Exfiltration | SAFE-T1913 | HTTP POST Exfil | Use outbound web tool to POST to attacker server |
| ATK-TA0010 | Exfiltration | SAFE-T1914 | Tool-to-Tool Exfil | Chain two tools so second one emails data out |
| **ATK-TA0040** | **Impact** | SAFE-T2101 | Data Destruction | delete_file or drop_table commands wipe assets |
| ATK-TA0040 | Impact | SAFE-T2102 | Service Disruption | Flood external API causing rate-limit or DoS |
| ATK-TA0040 | Impact | SAFE-T2103 | Code Sabotage | Agent commits malicious PR into repo |
| ATK-TA0040 | Impact | SAFE-T2104 | Fraudulent Transactions | Payment-tool instructed to move funds |
| ATK-TA0040 | Impact | SAFE-T2105 | Disinformation Output | Manipulate LLM to generate false or harmful content to downstream consumers |

## Summary Statistics

- **Total Tactics**: 14
- **Total Techniques**: 79
- **Average Techniques per Tactic**: 5.6

## Tactic Distribution

| Tactic | Number of Techniques |
|--------|---------------------|
| Reconnaissance | 0 |
| Resource Development | 0 |
| Initial Access | 8 |
| Execution | 8 |
| Persistence | 8 |
| Privilege Escalation | 8 |
| Defense Evasion | 8 |
| Credential Access | 7 |
| Discovery | 6 |
| Lateral Movement | 7 |
| Collection | 5 |
| Command and Control | 4 |
| Exfiltration | 5 |
| Impact | 5 |

## Usage Guidelines

- Use technique IDs (e.g., SAFE-T1001) for consistent reference across documentation
- Map these techniques to your specific MCP deployment for risk assessment
- Prioritize mitigation based on your threat model and the techniques most relevant to your environment
- Regular review as new techniques emerge in the rapidly evolving MCP threat landscape
