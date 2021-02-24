<#

.SYNOPSIS
    Show Windows Defender Firewall with Advanced Security (WFAS) status, statistics and rules

.PARAMETER Status
    Show Status
	
.PARAMETER Statistics
    Show Statistics

.PARAMETER ListActive
    list active firewall rules

.PARAMETER Detailed
    show detailed information for listed firewall rules

.PARAMETER InterfaceALias
    Alias of the interface to show firewall rules for

.EXAMPLE
    .\Show-NetFirewallRules.ps1 -Status
    Show actual status of the WFAS

.EXAMPLE
    .\Show-NetFirewallRules.ps1 -Statistics
    show statistic information

.EXAMPLE
    .\Show-NetFirewallRules.ps1 -ListActive -Detailed
    List all active firewall rules and show details

.EXAMPLE
    .\Show-NetFirewallRules.ps1 -ListActive -InterfaceAlias 'Ethernet 2'
    List all active firewall rules for interface 'Ethernet 2'

.DESCRIPTION
    This script will show information abount the Windows Defender Firewall with Advanced Security (WFAS).


.NOTES
    Version:            0.3
    Creation Date:      Feb 10, 2021
    Last Updated:       Feb 24, 2021
    Author:             Thomas Gusset
    Organization:       NetSec.co AG
    Contact:            thomas.gusset@netsec.co
    Web Site:           https://netsec.co/

#>

[CmdletBinding(SupportsShouldProcess)]

Param (
    [Parameter(HelpMessage = 'Enter Interface alias.')]        
    [string]$InterfaceAlias,
    [switch]$Status,
	[switch]$Statistics,
    [switch]$ListActive,
    [switch]$Detailed
)

$DetailMaxLength = 30

function CountRules($store, $direction)
{
    Try
	{
		$noRules = (Get-NetFirewallRule -PolicyStore $store -PrimaryStatus ok -Direction $direction -erroraction Ignore).count
    }
    Catch [Exception] 
	{
		$noRules = 0
    }
    return $noRules
}

function Trunc($string, $length)
{
    $result = $string
    If ($string.Length -gt $DetailMaxLength)
    {
        $result = $string.substring(0, $DetailMaxLength) + "..."
    }
    return $result
}



function ListRules($store, $direction, $action, $profile)
{
    $profileFilter = switch ($profile)
    {
        Public { '*Public*'  }
        Private { '*Private*' }
        Domain { '*Domain*' }
        default {'*'}
    }

    Try
    {
        If ($Detailed)
        {
          $rules = Get-NetFirewallRule -PolicyStore $store -Direction $direction -Action $action -PrimaryStatus ok -erroraction Stop | Where { $_.Profile –like $profileFilter –or $_.Profile –eq ‘Any’ }
          $detailedRules = @()
          ForEach ($rule in $rules)
          {
              $address = $rule | Get-NetFirewallAddressFilter
              $port = $rule | Get-NetFirewallPortFilter
              $application = $rule | Get-NetFirewallApplicationFilter
              $service = $rule | Get-NetFirewallServiceFilter
              $detailedRules += [pscustomobject]@{
                DisplayName = Trunc $rule.DisplayName
                Description = Trunc $rule.Description
                #Enabled = $rule.Enabled
                #Direction = $rule.Direction
                Profile = $rule.Profile
                DisplayGroup = Trunc $rule.DisplayGroup
                Protocol = $port.Protocol
                lAddress = $address.LocalAddress
                lPort = $port.LocalPort
                rAddress = $address.RemoteAddress
                rPort = $port.RemotePort
                #EdgeTraversalPolicy = $rule.EdgeTraversalPolicy
                Program = Split-Path $application.Program -Leaf
                Service = $service.ServiceName
                #Action = $rule.Action
                SourceType = $rule.PolicyStoreSourceType
                Source = $rule.PolicyStoreSource
                } 
           } 
           $detailedRules | Format-Table -Property * -Wrap -AutoSize
        }
        Else
        {
            Get-NetFirewallRule -PolicyStore $store -Direction $direction -Action $action -PrimaryStatus ok -erroraction Stop  | Where { $_.Profile –like $profileFilter –or $_.Profile –eq ‘Any’ } | select -Property DisplayName, Profile, PolicyStoreSourceType
        }
    }
    Catch [Exception] 
	{
		Write-Output "none"
    }
}


function GetProfile($IfAlias)
{
    [string]$result = ''
    Try
    {
        $result = (Get-NetConnectionProfile -InterfaceAlias $IfAlias -erroraction Stop).NetworkCategory
    }
    Catch
    {
        $result = ''
    }
    If ($result -eq 'DomainAuthenticated') { $result = 'Domain' }
    return $result
}


If ($Status)
{
	Write-Output "Windows Firewall Status"
    Write-Output "======================="
    $activeProfiles = (Get-NetFirewallSetting -PolicyStore ActiveStore).ActiveProfile
    Write-Output "ActiveProfile(s): $activeProfiles"
    Write-Output "`n"
    Write-Output "Interfaces"
    Write-Output "----------"
    $netProfiles = Get-NetConnectionProfile
    $interfaces = @()
    ForEach ($p in $netProfiles)
    {
    $description = ""
    $speed = ""
        Try
        {
            $adapter = Get-NetAdapter -Name $p.InterfaceAlias -erroraction Stop
            $description = $adapter.InterfaceDescription
            $speed = $adapter.LinkSpeed
        }
        catch {}

        $interfaces +=[pscustomobject]@{
            Name = $p.name
            Category = $p.NetworkCategory
            InterfaceAlias = $p.InterfaceAlias
            Description = $description
            Speed = $speed
        }
    }
    $interfaces | Format-Table
}


If ($Statistics)
{
	Write-Output "Windows Firewall Statistics"
    Write-Output "==========================="
	$noRules = CountRules ActiveStore Inbound
	Write-Output "Number of currently active INBOUND rules: $noRules"
	$noRules = CountRules ActiveStore Outbound
	Write-Output "Number of currently active OUTBOUND rules: $noRules"
	$noRules = CountRules RSOP Inbound
	Write-Output "Number of INBOUND rules from GPO: $noRules"
	$noRules = CountRules RSOP Outbound
	Write-Output "Number of OUTBOUND rules from GPO: $noRules"
	$noRules = CountRules PersistentStore Inbound
	Write-Output "Number of INBOUND rules created local: $noRules"
	$noRules = CountRules PersistentStore Outbound
	Write-Output "Number of OUTBOUND rules created local: $noRules"

    Write-Output "`n"
}



If ($ListActive)
{
    [string]$profile = ''
    If ($InterfaceAlias -ne "")
    {
        $profile = GetProfile $InterfaceAlias

        If ($profile -ne '')
        {
            Write-Output "`n"
            Write-Output "Listing Firewall Rules ONLY for Interface $InterfaceAlias"
            Write-Output "============================================================"
            Write-Output "`n"
        }
        Else
        {
            Write-Warning "Interface $InterfaceAlias not found"
        }

    }

    Write-Output "`nActive ALLOW Rules INBOUND"
    Write-Output "=========================="
    ListRules ActiveStore Inbound Allow $profile
    Write-Output "`nActive ALLOW Rules OUTBOUND"
    Write-Output "==========================="
    ListRules ActiveStore Outbound Allow $profile
    Write-Output "`nActive BLOCK Rules INBOUND"
    Write-Output "==========================="
    ListRules ActiveStore Inbound Block $profile
    Write-Output "`nActive BLOCK Rules OUTBOUND"
    Write-Output "==========================="
    ListRules ActiveStore Outbound Block $profile
}


