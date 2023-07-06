# Rekall Corportation Penetration Test Report

## Introduction

This report documents the findings of a penetration test performed on the Rekall Corportation internal network, conducted between May 1st, 2023 through May 5th, 2023. Testing focused on the following:

* Black Box texting of Rekall's web application and internal network, discovering and exploiting vulnerabilities with no prior knowledge of the environment or communication with Rekall's administrators.
* Enumeration of sensitive data accessible on Rekall's databases, to provide accurate impact analysis and determine risk exposure.
* Documentation of steps taken during the testing process, and recommendations for mitigation and hardening of discovered vulnerabilities.

Rekall's defined objectives for the penetration test were outlined as follows:

1. Find and exfiltrate any sensitive information within the domain.
2. Escalate privileges.
3. Compromise as many machines as possible.


## Methodology

### Reconnaissance

All assessments begin with open source intelligence (OSINT) gathering to identify and enumerate publically available information about the target and any associated entities. After passive information gathering, active information gathering is performed using tools such as Nmap and Bloodhound.

### Identification of Vulnerabilities and Services

After enumerating possible attack vectors, a combination of public, private, and custom-built tools such as Metasploit, hashcat, and Burp Suite are used to develop an understanding of the target environment and attempt to exploit any discovered vulnerabilities. Network architecture is mapped, hosts and services are identified, network and system vulnerabilities are discovered, and and false positives are tested and eliminated.

### Vulnerability Exploitation

Vulnerabilities are both manually and automatically exploited to determine exploitability, impact, and likelihood of success. Exploits in this penetration test are defined as any action that allows unauthorized access to a system or information.

### Reporting

After testing is completed, all tools and files are removed from the testing environment and a detailed report is written documenting the methodology, vulnerabilities, and exploits used. This report is then delivered to the customer for review.

## Scope

As described by Rekall, the scope of this penetration test includes:

* Rekall's web application
* Rekall's internal network, including:
    * Linux Servers
    * Windows Workstations
    * Active Directory Domain Controller

## Executive Summary

We conducted the penetration test in three phases - Web application, Linux systems, and Windows system. Multiple vulnerabilities were discovered across all targets, resulting in remote code execution and unauthorized administrative access. Our key findings are that Rekall’s security posture limits the impact of non-privileged employee compromise, but struggles to account for proper operational procedure when auditing employee practices and ensuring all devices are patched and properly secured.

The web application assessment focused on testing submission forms, including text, files, and logins. We searched for sensitive data in public areas and attempted to access private areas and other users' sessions. We identified several vulnerabilities, including cross-site scripting, sensitive data exposure, and session management compromise, which could pose significant risks to the organization if left unaddressed. Additionally, brute-force attacks were not prevented through methods such as Mutli-Factor Authentication (MFA) and rate limiting of requests. Ultimately, administrative access was acquired through multiple vectors and unprivileged code execution on the web application’s OS was possible.

The Linux penetration test began with Open Source Intelligence (OSINT) information gathering, followed by network and vulnerability scans. While not directly a threat, confidential employee information was unnecessarily exposed on OSINT data streams such as WHOIS registrar information and SSL certification records. We exploited various Remote Code Execution (RCE) vulnerabilities and tested valid root logins. Critical vulnerabilities identified include Apache Tomcat CVE-2017-12617, Shellshock CVE-2014-6271, and Sudo CVE-2019-14287. 

The Windows penetration test involved gathering OSINT information, followed by gaining "authorized" unauthorized access, exploiting RCE vulnerabilities, and performing enumeration using Schtasks and secrets dumping. We was able to gain SYSTEM access on the Domain Controller and dump password hashes. Some of the critical vulnerabilities discovered include OS Credential Dumping (SAM, LSASS, and DCSync attack) and acquiring persistence through a Schtasks event launching a Command & Control (C2) agent upon login. 

These vulnerabilities pose immediate threats to primary business processes and need to be addressed promptly. As such, we recommend that the organization address the identified vulnerabilities by implementing proper security controls, ensuring timely patching as policy, and monitoring for unauthorized access. Additionally, ensure strong password policies and access controls are in place for both internal and external network resources to minimize the risk of future breaches.

## Vulnerability Overview:

(FORMAT: Vulnerability | Severity)

* Remote Code Execution - Apache Tomcat CVE-2017-12617 | Critical
* Remote Code Execution - Shellshock CVE-2014-6271 | Critical
* Remote Code Execution -  Apache Struts CVE-2017-5638 | Critical
* Remote Code Execution -  Drupal CVE-2019-6340 | Critical
* Remote Code Execution - SLMail CVE-2003-0264 | Critical
* Privilege Escalation - Sudo CVE-2019-14287 | Critical
* Privilege Escalation - SMB Valid Credentials | Critical
* OS Credential Dumping - SAM | Critical
* OS Credential Dumping - LSASS | Critical
* OS Credential Dumping - DCSync Attack | Critical
* Session Management Compromise | Critical
* Create/Modify System Processes - Schtasks | Critical
* Sensitive Data Exposure - HTML File Contents | Critical
* Sensitive Data Exposure - File System Access | Critical
* Stored Cross Site Scripting (XSS) - Unfiltered Input | High
* Local File Inclusion - Unfiltered Input | High
* Local FIle Inclusion - Improperly Configured Filters | High
* SQL Injection | High
* Command Injection - Unfiltered Input | High
* Command Injection - Improperly Configured Filters | High
* PHP Injection | High
* Directory Traversal Compromise | High
* Credential Stuffing - Intranet Web Page | High
* Anonymous FTP Access | High
* Sensitive Data Exposure - Public Repository | High
* Sensitive Data Exposure - Shared Directories | Medium
* Reflected Cross Site Scripting (XSS) - Unfiltered Input | Medium
* Reflected Cross Site Scripting (XSS) - Improperly Configured Filters | Medium
* Brute Force Attack | Medium
* Sensitive Data Exposure - HTTP Response Header | Medium
* Sensitive Data Exposure - robots.txt | Medium
* Sensitive Data Exposure - WHOIS | Low
* Sensitive Data Exposure - SSL Certificates | Low
* Sensitive Data Exposure - IP Address | Informational

For full details on the vulnerabilities discovered, please see the Vulnerability Findings document.
