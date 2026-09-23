# Framework coverage report: NIST SP 800-171 Rev. 2 (110 security requirements)

**Subject:** Example Machining LLC (synthetic)  
**Framework:** NIST SP 800-171 Rev. 2 (110 security requirements)  
**Crosswalk:** `vcri.crosswalk.nist-sp800-171r2/0.1`

> **Indicative, evidence-backed, NOT a certification.** This shows where the subject's collected evidence maps to the framework's controls, and the grade of evidence behind each. It is not a conformance determination. Independent verification (a Cairn Risk Co. engagement) upgrades `attested` and `subject_claim` lines toward `observed`.

**Coverage:** 60 covered · 2 partial · 2 absent · 46 no automated source  
**Evidence grade:** 39 observed · 23 attested · 0 stated · 48 none

| Control | Coverage | Evidence grade | Source evidence |
|---|---|---|---|
| **3.1.1** Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems). | covered | observed | people-v1:jml, people-v1:mfa |
| **3.1.2** Limit system access to the types of transactions and functions that authorized users are permitted to execute. | covered | observed | people-v1:least-privilege |
| **3.1.3** Control the flow of CUI in accordance with approved authorizations. | covered | attested | technology-v1:4.4c |
| **3.1.4** Separate the duties of individuals to reduce the risk of malevolent activity without collusion. | covered | observed | people-v1:least-privilege |
| **3.1.5** Employ the principle of least privilege, including for specific security functions and privileged accounts. | covered | observed | people-v1:least-privilege |
| **3.1.6** Use non-privileged accounts or roles when accessing nonsecurity functions | covered | observed | people-v1:least-privilege |
| **3.1.7** Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs. | covered | observed | people-v1:least-privilege, technology-v1:6.6a |
| **3.1.8** Limit unsuccessful logon attempts. | manual | none | — |
| **3.1.9** Provide privacy and security notices consistent with applicable CUI rules. | manual | none | — |
| **3.1.10** Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity | manual | none | — |
| **3.1.11** Terminate (automatically) a user session after a defined condition. | manual | none | — |
| **3.1.12** Monitor and control remote access sessions. | covered | observed | technology-v1:6.6a |
| **3.1.13** Employ cryptographic mechanisms to protect the confidentiality of remote access sessions. | covered | attested | data-v1:in-transit |
| **3.1.14** Route remote access via managed access control points. | manual | none | — |
| **3.1.15** Authorize remote execution of privileged commands and remote access to security-relevant information. | manual | none | — |
| **3.1.16** Authorize wireless access prior to allowing such connections | manual | none | — |
| **3.1.17** Protect wireless access using authentication and encryption | covered | attested | data-v1:in-transit |
| **3.1.18** Control connection of mobile devices. | manual | none | — |
| **3.1.19** Encrypt CUI on mobile devices and mobile computing platforms.[23] | manual | none | — |
| **3.1.20** Verify and control/limit connections to and use of external systems. | covered | attested | technology-v1:4.4c |
| **3.1.21** Limit use of portable storage devices on external systems. | manual | none | — |
| **3.1.22** Control CUI posted or processed on publicly accessible systems. | manual | none | — |
| **3.2.1** Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems. | manual | none | — |
| **3.2.2** Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities. | manual | none | — |
| **3.2.3** Provide security awareness training on recognizing and reporting potential indicators of insider threat. | manual | none | — |
| **3.3.1** Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity | covered | observed | technology-v1:6.6a |
| **3.3.2** Ensure that the actions of individual system users can be uniquely traced to those users, so they can be held accountable for their actions. | covered | observed | people-v1:jml, technology-v1:6.6a |
| **3.3.3** Review and update logged events. | covered | observed | technology-v1:6.6a |
| **3.3.4** Alert in the event of an audit logging process failure. | covered | observed | technology-v1:6.6a |
| **3.3.5** Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity. | covered | observed | technology-v1:6.6a |
| **3.3.6** Provide audit record reduction and report generation to support on-demand analysis and reporting. | covered | observed | technology-v1:6.6a |
| **3.3.7** Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records | manual | none | — |
| **3.3.8** Protect audit information and audit logging tools from unauthorized access, modification, and deletion. | covered | observed | technology-v1:6.6a |
| **3.3.9** Limit management of audit logging functionality to a subset of privileged users. | covered | observed | people-v1:least-privilege, technology-v1:6.6a |
| **3.4.1** Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles. | covered | observed | technology-v1:1.1a, technology-v1:1.1b |
| **3.4.2** Establish and enforce security configuration settings for information technology products employed in organizational systems. | partial | observed | technology-v1:1.1b |
| **3.4.3** Track, review, approve or disapprove, and log changes to organizational systems. | covered | attested | process-v1:change-management |
| **3.4.4** Analyze the security impact of changes prior to implementation. | covered | attested | process-v1:change-management |
| **3.4.5** Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems. | covered | observed | people-v1:least-privilege, process-v1:change-management |
| **3.4.6** Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities. | partial | observed | technology-v1:1.1b |
| **3.4.7** Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services. | covered | observed | technology-v1:1.1b, technology-v1:4.4c |
| **3.4.8** Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software. | covered | observed | technology-v1:1.1a |
| **3.4.9** Control and monitor user-installed software. | covered | observed | technology-v1:1.1a |
| **3.5.1** Identify system users, processes acting on behalf of users, and devices. | covered | observed | people-v1:jml, technology-v1:2.2a |
| **3.5.2** Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems. | covered | observed | people-v1:mfa, technology-v1:2.2a |
| **3.5.3** Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.[24] [25]. | covered | observed | people-v1:mfa |
| **3.5.4** Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts. | covered | observed | people-v1:mfa |
| **3.5.5** Prevent reuse of identifiers for a defined period. | covered | observed | people-v1:jml |
| **3.5.6** Disable identifiers after a defined period of inactivity. | covered | observed | people-v1:jml |
| **3.5.7** Enforce a minimum password complexity and change of characters when new passwords are created. | manual | none | — |
| **3.5.8** Prohibit password reuse for a specified number of generations. | manual | none | — |
| **3.5.9** Allow temporary password use for system logons with an immediate change to a permanent password. | manual | none | — |
| **3.5.10** Store and transmit only cryptographically-protected passwords. | covered | attested | data-v1:in-transit, technology-v1:2.2a |
| **3.5.11** Obscure feedback of authentication information | manual | none | — |
| **3.6.1** Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities. | covered | attested | process-v1:incident-response |
| **3.6.2** Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization. | covered | observed | process-v1:incident-response, technology-v1:6.6a |
| **3.6.3** Test the organizational incident response capability. | covered | attested | process-v1:incident-response |
| **3.7.1** Perform maintenance on organizational systems.[26]. | manual | none | — |
| **3.7.2** Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance. | manual | none | — |
| **3.7.3** Ensure equipment removed for off-site maintenance is sanitized of any CUI. | manual | none | — |
| **3.7.4** Check media containing diagnostic and test programs for malicious code before the media are used in organizational systems. | manual | none | — |
| **3.7.5** Require multifactor authentication to establish nonlocal maintenance sessions via external network connections and terminate such connections when nonlocal maintenance is complete. | covered | observed | people-v1:mfa |
| **3.7.6** Supervise the maintenance activities of maintenance personnel without required access authorization. | manual | none | — |
| **3.8.1** Protect (i.e., physically control and securely store) system media containing CUI, both paper and digital. | manual | none | — |
| **3.8.2** Limit access to CUI on system media to authorized users | manual | none | — |
| **3.8.3** Sanitize or destroy system media containing CUI before disposal or release for reuse. | absent | none | — |
| **3.8.4** Mark media with necessary CUI markings and distribution limitations.[27] | manual | none | — |
| **3.8.5** Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas. | manual | none | — |
| **3.8.6** Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport unless otherwise protected by alternative physical safeguards. | covered | attested | data-v1:in-transit |
| **3.8.7** Control the use of removable media on system components. | manual | none | — |
| **3.8.8** Prohibit the use of portable storage devices when such devices have no identifiable owner. | manual | none | — |
| **3.8.9** Protect the confidentiality of backup CUI at storage locations. | absent | none | — |
| **3.9.1** Screen individuals prior to authorizing access to organizational systems containing CUI. | manual | none | — |
| **3.9.2** Ensure that organizational systems containing CUI are protected during and after personnel actions such as terminations and transfers | covered | observed | people-v1:jml |
| **3.10.1** Limit physical access to organizational systems, equipment, and the respective operating environments to authorized individuals. | manual | none | — |
| **3.10.2** Protect and monitor the physical facility and support infrastructure for organizational systems. | manual | none | — |
| **3.10.3** Escort visitors and monitor visitor activity. | manual | none | — |
| **3.10.4** Maintain audit logs of physical access. | manual | none | — |
| **3.10.5** Control and manage physical access devices. | manual | none | — |
| **3.10.6** Enforce safeguarding measures for CUI at alternate work sites. | manual | none | — |
| **3.11.1** Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI | manual | none | — |
| **3.11.2** Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified. | covered | observed | technology-v1:4.4a |
| **3.11.3** Remediate vulnerabilities in accordance with risk assessments. | covered | observed | technology-v1:4.4a |
| **3.12.1** Periodically assess the security controls in organizational systems to determine if the controls are effective in their application. | covered | attested | process-v1:control-effectiveness |
| **3.12.2** Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational systems. | covered | attested | process-v1:control-effectiveness |
| **3.12.3** Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls. | covered | observed | process-v1:control-effectiveness, technology-v1:6.6a |
| **3.12.4** Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems.[28] | covered | attested | process-v1:control-effectiveness |
| **3.13.1** Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems. | covered | observed | technology-v1:4.4c, technology-v1:6.6a |
| **3.13.2** Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems. | manual | none | — |
| **3.13.3** Separate user functionality from system management functionality. | manual | none | — |
| **3.13.4** Prevent unauthorized and unintended information transfer via shared system resources. | manual | none | — |
| **3.13.5** Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks. | covered | attested | technology-v1:4.4c |
| **3.13.6** Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception). | covered | attested | technology-v1:4.4c |
| **3.13.7** Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks (i.e., split tunneling). | manual | none | — |
| **3.13.8** Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards. | covered | attested | data-v1:in-transit |
| **3.13.9** Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity. | manual | none | — |
| **3.13.10** Establish and manage cryptographic keys for cryptography employed in organizational systems. | covered | attested | data-v1:in-transit |
| **3.13.11** Employ FIPS-validated cryptography when used to protect the confidentiality of CUI. | covered | attested | data-v1:in-transit |
| **3.13.12** Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device.[29]. | manual | none | — |
| **3.13.13** Control and monitor the use of mobile code. | manual | none | — |
| **3.13.14** Control and monitor the use of Voice over Internet Protocol (VoIP) technologies. | manual | none | — |
| **3.13.15** Protect the authenticity of communications sessions. | covered | attested | technology-v1:2.2a |
| **3.13.16** Protect the confidentiality of CUI at rest. | covered | attested | data-v1:in-transit |
| **3.14.1** Identify, report, and correct system flaws in a timely manner. | covered | observed | technology-v1:4.4a |
| **3.14.2** Provide protection from malicious code at designated locations within organizational systems. | covered | attested | technology-v1:4.4b |
| **3.14.3** Monitor system security alerts and advisories and take action in response. | covered | observed | technology-v1:4.4a, technology-v1:6.6a |
| **3.14.4** Update malicious code protection mechanisms when new releases are available. | covered | attested | technology-v1:4.4b |
| **3.14.5** Perform periodic scans of organizational systems and real-time scans of files from external sources as files are downloaded, opened, or executed. | covered | attested | technology-v1:4.4b |
| **3.14.6** Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks. | covered | observed | technology-v1:4.4c, technology-v1:6.6a |
| **3.14.7** Identify unauthorized use of organizational systems. | covered | observed | technology-v1:6.6a |

## Where verification would help most
- **3.1.8 Limit unsuccessful logon attempts.** — partial coverage.
- **3.1.9 Provide privacy and security notices consistent with applicable CUI rules.** — partial coverage.
- **3.1.10 Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity** — partial coverage.
- **3.1.11 Terminate (automatically) a user session after a defined condition.** — partial coverage.
- **3.1.14 Route remote access via managed access control points.** — partial coverage.
- **3.1.15 Authorize remote execution of privileged commands and remote access to security-relevant information.** — partial coverage.
- **3.1.16 Authorize wireless access prior to allowing such connections** — partial coverage.
- **3.1.18 Control connection of mobile devices.** — partial coverage.
- **3.1.19 Encrypt CUI on mobile devices and mobile computing platforms.[23]** — partial coverage.
- **3.1.21 Limit use of portable storage devices on external systems.** — partial coverage.
- **3.1.22 Control CUI posted or processed on publicly accessible systems.** — partial coverage.
- **3.2.1 Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems.** — partial coverage.
- **3.2.2 Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities.** — partial coverage.
- **3.2.3 Provide security awareness training on recognizing and reporting potential indicators of insider threat.** — partial coverage.
- **3.3.7 Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records** — partial coverage.
- **3.4.2 Establish and enforce security configuration settings for information technology products employed in organizational systems.** — partial coverage.
- **3.4.6 Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities.** — partial coverage.
- **3.5.7 Enforce a minimum password complexity and change of characters when new passwords are created.** — partial coverage.
- **3.5.8 Prohibit password reuse for a specified number of generations.** — partial coverage.
- **3.5.9 Allow temporary password use for system logons with an immediate change to a permanent password.** — partial coverage.
- **3.5.11 Obscure feedback of authentication information** — partial coverage.
- **3.7.1 Perform maintenance on organizational systems.[26].** — partial coverage.
- **3.7.2 Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance.** — partial coverage.
- **3.7.3 Ensure equipment removed for off-site maintenance is sanitized of any CUI.** — partial coverage.
- **3.7.4 Check media containing diagnostic and test programs for malicious code before the media are used in organizational systems.** — partial coverage.
- **3.7.6 Supervise the maintenance activities of maintenance personnel without required access authorization.** — partial coverage.
- **3.8.1 Protect (i.e., physically control and securely store) system media containing CUI, both paper and digital.** — partial coverage.
- **3.8.2 Limit access to CUI on system media to authorized users** — partial coverage.
- **3.8.3 Sanitize or destroy system media containing CUI before disposal or release for reuse.** — no evidence collected.
- **3.8.4 Mark media with necessary CUI markings and distribution limitations.[27]** — partial coverage.
- **3.8.5 Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas.** — partial coverage.
- **3.8.7 Control the use of removable media on system components.** — partial coverage.
- **3.8.8 Prohibit the use of portable storage devices when such devices have no identifiable owner.** — partial coverage.
- **3.8.9 Protect the confidentiality of backup CUI at storage locations.** — no evidence collected.
- **3.9.1 Screen individuals prior to authorizing access to organizational systems containing CUI.** — partial coverage.
- **3.10.1 Limit physical access to organizational systems, equipment, and the respective operating environments to authorized individuals.** — partial coverage.
- **3.10.2 Protect and monitor the physical facility and support infrastructure for organizational systems.** — partial coverage.
- **3.10.3 Escort visitors and monitor visitor activity.** — partial coverage.
- **3.10.4 Maintain audit logs of physical access.** — partial coverage.
- **3.10.5 Control and manage physical access devices.** — partial coverage.
- **3.10.6 Enforce safeguarding measures for CUI at alternate work sites.** — partial coverage.
- **3.11.1 Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI** — partial coverage.
- **3.13.2 Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems.** — partial coverage.
- **3.13.3 Separate user functionality from system management functionality.** — partial coverage.
- **3.13.4 Prevent unauthorized and unintended information transfer via shared system resources.** — partial coverage.
- **3.13.7 Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks (i.e., split tunneling).** — partial coverage.
- **3.13.9 Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity.** — partial coverage.
- **3.13.12 Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device.[29].** — partial coverage.
- **3.13.13 Control and monitor the use of mobile code.** — partial coverage.
- **3.13.14 Control and monitor the use of Voice over Internet Protocol (VoIP) technologies.** — partial coverage.

*Generated by the Beacon Collector. No score is assigned; leveling and verified rating are Cairn Risk Co. Schema vcri.beacon.evidence-package/v0.*