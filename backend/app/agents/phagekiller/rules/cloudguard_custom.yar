
/*
 * CloudGuard AI — Custom YARA Rules
 * Built-in rules targeting common threats on Windows systems
 * Updated: auto-generated
 */

rule CG_Suspicious_PowerShell_Download
{
    meta:
        description = "Detects PowerShell scripts downloading and executing payloads"
        author = "CloudGuard AI"
        severity = "high"
        reference = "CloudGuard ThreatHound Intel"

    strings:
        $ps1 = "IEX" nocase
        $ps2 = "Invoke-Expression" nocase
        $ps3 = "DownloadString" nocase
        $ps4 = "WebClient" nocase
        $ps5 = "FromBase64String" nocase
        $ps6 = "EncodedCommand" nocase

    condition:
        2 of ($ps1, $ps2, $ps3, $ps4) or
        ($ps5 and $ps6)
}

rule CG_Credential_Harvester
{
    meta:
        description = "Detects credential harvesting patterns"
        author = "CloudGuard AI"
        severity = "critical"

    strings:
        $cred1 = "password" nocase
        $cred2 = "credential" nocase
        $cred3 = "mimikatz" nocase
        $cred4 = "sekurlsa" nocase
        $cred5 = "lsass" nocase
        $dump1 = "procdump" nocase
        $dump2 = "comsvcs.dll" nocase

    condition:
        $cred3 or $cred4 or
        ($cred5 and 1 of ($dump1, $dump2)) or
        (all of ($cred1, $cred2) and 1 of ($dump1, $dump2))
}

rule CG_Ransomware_Pattern
{
    meta:
        description = "Detects common ransomware behavioral patterns"
        author = "CloudGuard AI"
        severity = "critical"

    strings:
        $enc1 = "CryptEncrypt" nocase
        $enc2 = "CryptoAPI" nocase
        $ransom1 = "YOUR FILES" nocase
        $ransom2 = "DECRYPT" nocase
        $ransom3 = "bitcoin" nocase
        $ransom4 = "tor browser" nocase
        $ext1 = ".locked" nocase
        $ext2 = ".encrypted" nocase
        $ext3 = ".crypto" nocase
        $vss1 = "vssadmin" nocase
        $vss2 = "delete shadows" nocase

    condition:
        ($vss1 and $vss2) or
        (2 of ($ransom1, $ransom2, $ransom3, $ransom4)) or
        (1 of ($enc1, $enc2) and 1 of ($ext1, $ext2, $ext3))
}

rule CG_Reverse_Shell
{
    meta:
        description = "Detects reverse shell payloads"
        author = "CloudGuard AI"
        severity = "critical"

    strings:
        $nc1 = "nc -e" nocase
        $nc2 = "ncat" nocase
        $bash1 = "/bin/bash -i" nocase
        $bash2 = "bash -i >& /dev/tcp" nocase
        $ps_rev = "System.Net.Sockets.TCPClient" nocase
        $py_rev = "socket.connect" nocase

    condition:
        any of them
}

rule CG_Crypto_Miner
{
    meta:
        description = "Detects cryptocurrency mining software"
        author = "CloudGuard AI"
        severity = "high"

    strings:
        $miner1 = "xmrig" nocase
        $miner2 = "stratum+tcp" nocase
        $miner3 = "monero" nocase
        $miner4 = "nicehash" nocase
        $miner5 = "cryptonight" nocase
        $miner6 = "--donate-level" nocase
        $pool1 = "pool.minexmr" nocase
        $pool2 = "supportxmr.com" nocase

    condition:
        2 of them
}

rule CG_Suspicious_PE_Executable
{
    meta:
        description = "Detects suspicious PE executables with known bad indicators"
        author = "CloudGuard AI"
        severity = "medium"

    strings:
        $mz = { 4D 5A }
        $sus1 = "This program cannot be run in DOS mode"
        $anti1 = "IsDebuggerPresent"
        $anti2 = "CheckRemoteDebuggerPresent"
        $inject1 = "VirtualAllocEx"
        $inject2 = "WriteProcessMemory"
        $inject3 = "CreateRemoteThread"

    condition:
        $mz at 0 and
        $sus1 and
        (2 of ($inject1, $inject2, $inject3) or
         all of ($anti1, $anti2))
}

rule CG_Webshell_Generic
{
    meta:
        description = "Detects common webshell patterns"
        author = "CloudGuard AI"
        severity = "critical"

    strings:
        $php1 = "<?php" nocase
        $php2 = "eval(" nocase
        $php3 = "base64_decode(" nocase
        $php4 = "system(" nocase
        $php5 = "exec(" nocase
        $php6 = "shell_exec(" nocase
        $php7 = "passthru(" nocase
        $asp1 = "<%@ Page" nocase
        $asp2 = "cmd.exe" nocase

    condition:
        ($php1 and 2 of ($php2, $php3, $php4, $php5, $php6, $php7)) or
        ($asp1 and $asp2)
}
