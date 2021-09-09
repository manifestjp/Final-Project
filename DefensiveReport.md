# Blue Team: Summary of Operations

## Table of Contents
- [Network Topology](#network-topology)
- [Description of Targets](#description-of-targets)
- [Monitoring the Targets](#monitoring-the-targets)
- [Suggestions for Going Further](#suggestions-for-going-further)

### Network Topology

The following machines were identified o the network:

- Target 1
  - **Operating System**: Linux
  - **Purpose**: HTTP Server
  - **IP Address**: 192.168.1.110
- Target 2
  - **Operating System**: Linux
  - **Purpose**: HTTP Server
  - **IP Address**: 192.168.1.115
- ELK
  - **Operating System**: Linux
  - **Purpose**: Holds Kibana Dashboards
  - **IP Address**: 192.168.1.100
- Capstone
  - **Operating System**: Linux
  - **Purpose**: HTTP Server (test platform)
  - **IP Address**: 192.168.1.105
- Host Machine
  - **Operating System**: Microsoft Windows
  - **Purpose**: Gateway
  - **IP Address**: 192.168.1.1
  
### Description of Targets

The target of this attack was: `Target 1` `(192.168.1.110)`.

Target 1 is an Apache web server and has SSH enabled, so ports 80 and 22 are possible ports of entry for attackers. As such, the following alerts have been implemented:

* [Excessive HTTP Errors](#excessive-http-errors)
* [HTTP Request Size Monitor](#http-request-size-monitor)
* [CPU Usage Monitor](#cpu-usage-monitor)

### Monitoring the Targets

Traffic to these services should be carefully monitored. To this end, we have implemented the alerts below:

#### Excessive HTTP Errors

Alert 1 is implemented as follows:
  - **Metric**: `ftp.response.status_code > 400`
  - **Threshold**: 5 in the last 5 minutes
  - **Vulnerability Mitigated**: The security team can identify attacks and block the attacking IP address/s, change the password and filter or close port 22.
  - **Reliability**: This alert will not generate a lot of flase positives. It is highly reliable in identifying brute force attacks.
  
#### HTTP Request Size Monitor
Alert 2 is implemented as follows:
  - **Metric**: `http.request.bytes`
  - **Threshold**: 3500 in the last 1 minute
  - **Vulnerability Mitigated**: By limiting the number of HTTP request size through a filter, the system will be protected from DDoS attacks.
  - **Reliability**: This alert will not generate a lot of false positives. It is highly reliable in indentifying DDoS attacks.
  
#### CPU Usage Monitor
Alert 3 is implemented as follows:
  - **Metric**: `system.process.cpu.total.pct`
  - **Threshold**: 0.5 in the last 5 minutes
  - **Vulnerability Mitigated**: By controlling the CPU usage percentage it will trigger a memory dump of the stored information.
  - **Reliability**: This alert can generate a lot of false positives because the CPU usage can spike even if there is no attack. It is not very reliable in discerning between normal CPU usage and an attack.
  
### Suggestions for Going Further
- Each alert above pertains to a specific vulnerability/exploit. Recall that alerts only detect malicious behavior, but do not stop it. For each vulnerability/exploit identifed by the alerts above, suggest a patch. E.g., implementing a blocklist is an effective tactic against brute-force attacks. It is not necessary to explain_how_to implement each patch.

The logs and alerts generated during the assessment suggest that this network is susceptible to several active threats, identified by the alerts above. In addition to watchin for occurrences of such threats, the network should be hardened against them. The Blue Team suggests that IT implement the fixes below to protect the network:
- Vulnerability 1- Excessive HTTP Errors
  - **Patch**: Require a stronger password policy in the user account settings and update the group policy in Windows and Linux.
  - **Why It Works**: By changing the password policy and updating the group policy it should be almost impossible to brute-force and gain access to the system.

- Vulnerability 2- HTTP Request Size Monitor
  - **Patch**: Use of proper threat management and intrusion prevention systems such as firewalls, anti-spam filters, load balancing, DDoS guard, a VPN and other DDoS prevention systems and techniques.
  - **Why It Works**: Using said systems and techniques together will help to identify and stop a DDoS threat before it can have catashtrophic effects on the system.
  
- Vulnerability 3- CPU Usage Monitor
  - **Patch**: Use of host intrusion prevention system to identify DOS attack.
  - **Why It Works**: This will stop malware and malicious code by monitoring the behavior of the code.
