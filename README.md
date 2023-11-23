# Get-RiskyProcesses

Checks running processes for a list of potentially "risky" ones that should not be spawned by certain parent processes. If found, the results could indicate abnormal behavior.

A blog post by the Microsoft Defender ATP Research Team on June 24, 2020 detailed some scenarios in which an attacker might exploit a remote code execution (RCE) vulnerability in the IIS component of an Exchange Server, and thereby gain system privileges. One indication of such an exploit might be a "cmd.exe" or "mshta.exe" process (among others) that is spawned by "w3wp.exe" or the IIS application pool. See: https://www.microsoft.com/security/blog/2020/06/24/defending-exchange-servers-under-attack/.

While Windows Defender ATP or other endpoint detection and response (EDR) products may natively be able to detect such behavior, systems without those protections may not. This script provides a working concept that could notify admins of these potential exploits, when the script is run as a scheduled task or when used in conjunction with a monitoring platform.