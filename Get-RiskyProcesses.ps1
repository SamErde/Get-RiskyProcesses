<#
    .SYNOPSIS
    Checks running processes for a list of "risky" processes that should not be spawned by "risky" parent processes.

    .DESCRIPTION
    A blog post by the Microsoft Defender ATP Research Team on June 24, 2020 detailed some scenarios in which an attacker 
    might exploit a remote code execution (RCE) vulnerability in IIS component of an Exchange Server, and thereby gain 
    system privileges. See: https://www.microsoft.com/security/blog/2020/06/24/defending-exchange-servers-under-attack/. 
    One indication of such an exploit might be a "cmd.exe" process (among others) that is spawned by "w3wp.exe", or the 
    IIS application pool. 
    
    While Windows Defender ATP or other endpoint detection and response (EDR) products may natively be able to detect 
    such behavior, systems without those protections may not. This script provides a working concept that could notify 
    admins of these potential exploits, when the script is run as a scheduled task or when used in conjunction with a 
    monitoring platform such as SolarWinds Orion.

    .NOTES
    Name: Get-RiskyProcesses
    Author: Sam Erde
    Last Modified: June 26, 2020

    .LINK
    https://github.com/SturdyErde/Get-RiskyProcesses

    .PARAMETER Output
    A string that specifies how results will be displayed. Valid options include Host, Email, and Orion. 
    The default output is 'Host' if none is specified.

    .EXAMPLE
        #Display results on the host.
        Get-RiskyProcesses

        #Email the results to an address that is specified in the script declarations.
        Get-RiskyProcesses -Output Email

        #Format the host output in a way that can be used by a component script monitor in SolarWinds Orion.
        Get-RiskProcesses -Output Orion
#>

[CmdletBinding(DefaultParameterSetName = 'Output')]
param (
    [Parameter()]
    [ValidateSet('Here','Orion','Email')]
    [string]$Output = 'Here'
)

# ---------- Custom Declarations ---------- 
$emailTo = ""
$emailFrom = ""
$emailSubject = ""
$emailServer = ""
# ---------- End Custom Declarations ---------- 

# ---------- Standard Declarations ---------- 
# List of processes that might sometimes be used by exploits, and parent processes that should not spawn them.
$riskyProcesses = "cmd.exe", "net.exe", "mshta.exe"
$riskyParents = "w3wp.exe","w3wp"
$riskDetails = @()
# ---------- End Standard Declarations ---------- 

# Get a list of all processes and from that extract a second list of processes that we want to examine.
$allProcesses = Get-CimInstance -ClassName win32_process
$checkProcesses = $allProcesses | Where-Object -Property Name -in -Value $riskyProcesses

# In the resulting list, we need to know the parent process name so we can evaluate whether or not there is a risk in this context.
foreach ($thisProcess in $checkProcesses) {
    # Create a custom object that adds the parent process name to the existing process details.
    $processDetails = $thisProcess | Select-Object -Property *, @{Name = 'ParentProcessName'; Expression= { ($allProcesses | Where-Object {$_.ProcessId -eq $thisProcess.ParentProcessId}).Name } }
    Write-Verbose $processDetails | Select-Object Name,ProcessId,ParentProcessName,ParentProcessId,CommandLine
}

# Note details if a riskyProcess is spawned by a riskyParent.
foreach ($detail in $processDetails) {
    if ($detail.ParentProcessName -in $riskyParents) {
        Write-Verbose $detail | Select-Object Name,ProcessId,ParentProcessName,ParentProcessId,CommandLine
        $riskDetails += $detail | Select-Object Name,ProcessId,ParentProcessName,ParentProcessId,CommandLine
    }
}

<#  ----------------------------------- OUTPUT -----------------------------------
    This script will write output to the host if no -Output parameter is specified.

    To create your own output actions, add values to the -Output parameter at the beginning of this script and 
    then process them in else/elseif blocks below. Create separate functions for the extra outputs to keep the 
    if/else block simple. OUTPUT FUNCTIONS MUST BE WRITTEN ABOVE THE IF BLOCK IN ORDER TO RUN WHEN CALLED.

    Syntax for an Orion monitoring component output is included as one option.
#>

Function OutputOrion {
    #Format the output for Orion. The message can be a string, but the statistic must be a number.
        if ($riskDetails.Count -gt 0) {
            Write-Host "Statistic.RiskyProcesses: $($riskDetails.Count)" 
            Write-Host "Message.RiskyProcesses: $($riskDetails)"
        }
        else {
            Write-Host "Statistic.RiskyProcesses: 0"
            Write-Host "Message.RiskyProcesses: None"
        }
    }

Function OutputEmail {
    # A very basic function that could be beautified.
    Send-MailMessage -From $emailFrom -To $emailTo -Subject $emailSubject -SmtpServer $emailServer -Body $riskDetails
}

# Finally show the output at the end, using this if block.
if ([string]::IsNullOrEmpty($Output) -or $Output -eq 'Here') {
    $riskDetails
}
# Customized output functions must be above this if/else block!
elseif ($Output -eq 'Orion') { OutputOrion }
elseif ($Output -eq 'Email') { OutputEmail }
