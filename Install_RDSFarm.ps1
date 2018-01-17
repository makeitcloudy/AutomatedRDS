<#
DESCRIPTION   This script will create a configured Remote Desktop Session Farm.
Current script is a modification of the work which has been already done by 

Author            : Julian Mooren |  
Blog              : https://citrixguyblog.com
GitHub Link       : https://github.com/citrixguyblog/PowerShellRDSDeployment
Creation Date     : 12.V.2017

which is wrapped with functions and more work in very verbose mode

Author            : Piotr Ostrowski
Modification Date : 11.XII.2017

Howto:
Get-Help .\RDS\Install_RDSFarm.ps1 -ShowWindow

Tip:
+ Run this script on the management node from which you'll be creating your deployment.
+ Check that your Connection Brokers have the following update: KB4053579 before you start

ToDo:
+ Import SQL Module to automate the login permissions on the SQL side
+ Rewrite as much as possible with DSC

Issues:
RDS:\ provider on the RDGW - throws errors
Needs slight attention / rework to finish that part so proper groups are configured with RAP and CAP Policies
It should be enough to configure it once from the GUI, then check the RDS:\ provider entries and replicate it
properly within the script.
Once you run this this script - check your Remote Desktop Gateway RAP / CAP Policies and customize them according
to your needs.
#>

#Requires -version 5.0
#Requires -RunAsAdministrator

<#
    .SYNOPSIS
    Script installs Remote Desktop Services Deployment.
    .DESCRIPTION
    Script installs Remote Desktop Services.
    2018.01.03 - It was tested on RDS 2016 and Windows Server 2016.
    Should be run under account which has enough administartive privileges to:
    + create DNS records
    + create AD accounts for the RD Connection Broker Servers
    + install Roles on the Destination Servers
    .EXAMPLE
    . .\Install_RDSFarm.ps1 -Deployment Multi
    It installs RDS with: 1x Gateway, WebAccess Server, Delivery Controller, Session Host Server
        Based on the details specified in file rds_config_Multi.
    .EXAMPLE
    . .\Install_RDSFarm.ps1 -Deployment Multi -DownloadKB
    It installs RDS with: 1x Gateway, WebAccess Server, Delivery Controller, Session Host Server
        Based on the details specified in file rds_config_Multi.psd1
        And downloads the KB for the Connection Broker HA mode - if you plan to configure it later.
    .EXAMPLE
    . .\Install_RDSFarm.ps1 -Deployment HA
    It installs RDS with at least: 2x Gateways, WebAccess Servers, Delivery Controllers, Session Host Servers
        Based on the details specified in the file rds_config_HA.psd1
    .EXAMPLE
    . .\Install_RDSFarm.ps1 -Deployment HA -DownloadKB
    It installs RDS with at least: 2x Gateways, WebAccess Servers, Delivery Controllers, Session Host Servers
        Based on the details specified in the file rds_config_HA.psd1
        And downloads the KB for the Connection Broker HA mode.
    .PARAMETER Deployment
    .LINK
    https://github.com/citrixguyblog/PowerShellRDSDeployment
    .LINK
    https://citrixguyblog.com
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true,
    HelpMessage = "Deployment Type")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Multi", "HA")]
    [string]$DeploymentType,

    [Switch]
    $DownloadKB
)
#region Initialize Variables
$configFileMulti = "rds_config_Multi.psd1" #uncoment this for the multi deployment 1xRDGW,1xRDWA,1xRDCB - internal DB
$configFileHA = "rds_config_HA.psd1" #uncomment this for the HA deployment NxRDGW,NxRDWA,NxRDCB - SQL
$configPath= "$env:SystemDrive\Resources\RDS\$configFile"
$StartDate = (Get-Date)
$Vendor = "Microsoft"
$Product = "RemoteDesktopServices"
$Version = "2016"
$LogPath = "${env:SystemRoot}" + "\Temp\$($StartDate.toString('yyyyMMdd_HHMMss'))" + "_" + $Vendor + "_" + $Product + "_" + "$Version.log"
$RSATfeatures = @("RSAT-AD-Tools","RSAT-DNS-Server")
#$config = Get-JSONFile -configPath $configPath -Verbose
#endregion

##### Default Configuration Parameters ##### 

# Thanks @xenappblog.com for the Transcript Log idea

Start-Transcript $LogPath
Write-Verbose "Starting Installation of $Vendor $Product $Version" -Verbose
Get-Prerequisite -windowsFeature $RSATfeatures -Verbose

#Get-JSONDetails -configPath $configPath -Verbose
Get-SSLCertificate -config $config -Verbose

#region Import the RemoteDesktop Module
Write-Verbose "Importing RemoteDesktop Module" -Verbose
Import-Module RemoteDesktop

if($DownloadKB){
    Import-LocalizedData -BaseDirectory "$env:SystemDrive\Resources\rds" -FileName $configFileHA -BindingVariable config
    Get-WindowsKB -config $config -Verbose  #grab the crucial KB's

    $connectionBrokerWinRM = New-PSSession -ComputerName ($config.RDConnectionBroker | % Values)
    #it will copy the KB4053579 for all Connection Brokers in parallel using workflows
    #before copying make sure that the folder exists in remote location
    #create functions which will craete those folders 
    Copy-WindowsKB -connectionBrokerWinRM $connectionBrokerwinRM -Path "$($config.RDSResourcesPackages)\$($config.KB.KB4053579)" -Destination "$($config.RDSResourcesPackages)\$($config.KB.KB4053579)" -Verbose
    Invoke-Command -ComputerName ($config.RDConnectionBroker | % Values) -scriptblock {New-Item -ItemType Directory -Path $using:config.RDSResourcesPackages}
    Copy-Item -Path "$($config.RDSResourcesPackages)\$($config.KB.KB4053579)" -Destination "$($config.RDSResourcesPackages)\$($config.KB.KB4053579)" -ToSession $connectionBrokerWinRM[1]
    #Copy-Item -Path "$($config.RDSResourcesPackages)\$($config.KB.KB4053579)" -Destination "$($config.RDSResourcesPackages)\$($config.KB.KB4053579)" -ToSession $connectionBrokerWinRM[0]
    #Copy-Item -Path "$($config.RDSResourcesPackages)\$($config.KB.KB4053579)" -Destination "\\ctxlab-rdcb02.test.lab\c$\Resources\Packages\$($config.KB.KB4053579)" -ToSession $connectionBrokerWinRM[0]
    Remove-PSSession -ComputerName ($config.RDConnectionBroker | % Values)
}
else{
    Write-Verbose "Windows KB won't be downloaded." -Verbose
}

switch($deploymentType){
    "Multi"{
        Import-LocalizedData -BaseDirectory "$env:SystemDrive\Resources\rds" -FileName $configFileMulti -BindingVariable config
        
        if($config.MultiDeployment -match "Yes") {
                [System.Collections.ArrayList]$rdsInfrastructureMulti = @()
                $rdsInfrastructureMulti.Clear()
                #rewrite this part of code that it reflects the rds_config_HA.psd1 and rds_ConfigMulti.psd1 files
                ($config.License.GetEnumerator() | Where Name -match "LicServer*" | % Value).foreach({$rdsInfrastructureMulti.Add("$_")})
                ($config.RDGateway.GetEnumerator() | Where Name -match "RDGatewayServer*" | % Value).foreach({$rdsInfrastructureMulti.Add("$_")})
                ($config.RDWebAccess.GetEnumerator() | Where Name -match "WebAccessServer*" | % Value).foreach({$rdsInfrastructureMulti.Add("$_")})
                ($config.RDConnectionBroker.GetEnumerator() | Where Name -match "ConnectionBroker*" | % Value).foreach({$rdsInfrastructureMulti.Add("$_")})
                ($config.RDSessionHost.GetEnumerator() | Where Name -match "SessionHost*" | % Value).foreach({$rdsInfrastructureMulti.Add("$_")})
                #$rdsInfrastructureMulti

                Test-PSRemoting -rdsdeployment $rdsInfrastructureMulti -Verbose
                New-RDSDeployment -config $config -Verbose
                Edit-RDSDesktopCollection -config $config -Verbose
                Add-RDGateway -config $config -Verbose
                Set-RDGatewayCAPRAP -config $config -Verbose #some issues with configuration of the gateway
                Add-DNSRecordAWebAccess -config $config -Verbose
                Set-IISDefaultWebPage -config $config -Verbose
                Edit-RDSCollection -config $config -Verbose
                Set-RDSLicensing -config $config -Verbose
                Set-SSLCertificateConfiguration -config $config -Verbose
                Set-RDGatewayMapping -config $config -Verbose
                Add-DNSRecordTXTWebFeed -config $config -Verbose
                Add-DNSRecordARDSBroker -config $config -Verbose
                Set-RDPublishedName -config $config -Verbose
            }
        Break
    }
    "HA" {
        #Import-LocalizedData -BaseDirectory "$env:SystemDrive\Resources\rds" -FileName $configFileMulti -BindingVariable config
        #
        #if($config.MultiDeployment -match "Yes") {
        #        [System.Collections.ArrayList]$rdsInfrastructureMulti = @()
        #        $rdsInfrastructureMulti.Clear()
        #        #rewrite this part of code that it reflects the rds_config_HA.psd1 and rds_ConfigMulti.psd1 files
        #        ($config.License.GetEnumerator() | Where Name -match "LicServer*" | % Value).foreach({$rdsInfrastructureMulti.Add("$_")})
        #        ($config.RDGateway.GetEnumerator() | Where Name -match "RDGatewayServer*" | % Value).foreach({$rdsInfrastructureMulti.Add("$_")})
        #        ($config.RDWebAccess.GetEnumerator() | Where Name -match "WebAccessServer*" | % Value).foreach({$rdsInfrastructureMulti.Add("$_")})
        #        ($config.RDConnectionBroker.GetEnumerator() | Where Name -match "ConnectionBroker*" | % Value).foreach({$rdsInfrastructureMulti.Add("$_")})
        #        ($config.RDSessionHost.GetEnumerator() | Where Name -match "SessionHost*" | % Value).foreach({$rdsInfrastructureMulti.Add("$_")})
        #        #$rdsInfrastructureMulti
        #
        #        Test-PSRemoting -rdsdeployment $rdsInfrastructureMulti -Verbose
        #        New-RDSDeployment -config $config -Verbose
        #        Edit-RDSDesktopCollection -config $config -Verbose
        #        Add-RDGateway -config $config -Verbose
        #        Set-RDGatewayCAPRAP -config $config -Verbose #some issues with configuration of the gateway
        #        Add-DNSRecordAWebAccess -config $config -Verbose
        #        Set-IISDefaultWebPage -config $config -Verbose
        #        Edit-RDSCollection -config $config -Verbose
        #        Set-RDSLicensing -config $config -Verbose
        #        Set-SSLCertificateConfiguration -config $config -Verbose
        #        Set-RDGatewayMapping -config $config -Verbose
        #        Add-DNSRecordTXTWebFeed -config $config -Verbose
        #        Add-DNSRecordARDSBroker -config $config -Verbose
        #        Set-RDPublishedName -config $config -Verbose
        #    }

        Import-LocalizedData -BaseDirectory "$env:SystemDrive\Resources\rds" -FileName $configFileHA -BindingVariable config
        
        if($config.HADeployment -match "Yes") {
            [System.Collections.ArrayList]$rdsInfrastructureHA = @()
            $rdsInfrastructureHA.Clear()
            ($config.License.GetEnumerator() | Where Name -match "LicServer*" | % Value).foreach({$rdsInfrastructureHA.Add("$_")})
            ($config.RDGateway.GetEnumerator() | Where Name -match "RDGatewayServer*" | % Value).foreach({$rdsInfrastructureHA.Add("$_")})
            ($config.RDWebAccess.GetEnumerator() | Where Name -match "WebAccessServer*" | % Value).foreach({$rdsInfrastructureHA.Add("$_")})
            ($config.RDConnectionBroker.GetEnumerator() | Where Name -match "ConnectionBroker*" | % Value).foreach({$rdsInfrastructureHA.Add("$_")})
            ($config.RDSessionHost.GetEnumerator() | Where Name -match "SessionHost*" | % Value).foreach({$rdsInfrastructureHA.Add("$_")})
            $rdsInfrastructureHA

            Test-PSRemoting -rdsdeployment $rdsInfrastructureHA -Verbose
            Add-BrokerSecurityGroupHA -config $config -Verbose #for SQL Database Access
            Restart-BrokerServer -config $config -Verbose #restart all RD Connection Broker Servers
            Add-DNSRecordARoundRobinLB -config $config -Verbose #configuring DNS A Entries for Round Robin Load Balancing Connection Brokers, Web Access Servers
            Get-SQLNativeClient -config $config -Verbose
            #Install-SQLNativeClient -config $config -suffix "-rdcb" -Verbose
            Install-SQLNativeClient -config $config -Verbose
            #region Configure RDSBrokerHighAvailability
            Write-Warning "Preconfigure the SQL Server for the Remote Desktop Servicer HA configuration"
            Write-Warning "Please create SQL Login $($config.ADGroup.RDConnectionBrokersGroup) and give it the 'dbcreator' ServerRole. That allows RDCB to create the $($config.SQLDatabase) database."
            Read-Host "Press Enter when finished"
            #the prerequisite for this to apply properly is the KB4053579 to be installed on the Remote Desktop Connection Brokers
            Set-SQLHighAvailability -config $config -Verbose #test it once you recreate the deployment and test this script in another go (usind adaptec Array)
            #RDS_Connection_Broker SQL USer Mapping -> db_owner
            Write-Warning "Please withdraw 'dbcreator' Server Role for $($config.ADGroup.RDConnectionBrokersGroup) Security Group"
            Write-Warning "Then under the User Mapping add the 'db_owner' permissions for the $($config.SQLDatabase) database"
            Read-Host "Press Enter when finished"
            Add-SubsequentRDConnectionBroker -config $config -Verbose #OK
            $primaryBroker = Get-ActiveBroker -config $config -Verbose #OK
            Add-SubsequentRDWebAccessServer -config $config -Verbose #OK
            Set-SubsequentIISDefaultWebPage -config $config -Verbose #OK
            Get-MachineKeyRDWebServices -config $config -Verbose #NOK - rdwa is unreachable
            Add-SubsequentRDGateway -config $config -Verbose #OK
            Set-SubsequentRDGatewayPolicy -config $config -Verbose #NOK wali bledem RDS:\GatewayServer\RAP\RDG_RAP_FArm1 is denied for cmdlet New-Item, value not valid or not sufficient permissions
            #drugi blad RDS:\GatewayServer\CAP\RDG_CAP_Farm1 to co wyzej
            Remove-FirstRDGatewayPolicy -config $config -Verbose #OK
            Expand-FirstRDGatewayFarmSettings -config $config -Verbose #OK
            Redo-SSLCertificateConfiguration -config $config -primaryBroker $primaryBroker -Verbose
        }
        Break
    }
    default {
        Write-Host "Something went wrong"
    }
}

Write-Verbose "Stop logging" -Verbose
Stop-Transcript
$EndDate = (Get-Date)
Write-Verbose "Elapsed Time: $(($EndDate-$StartDate).TotalSeconds) Seconds" -Verbose
Write-Verbose "Elapsed Time: $(($EndDate-$StartDate).TotalMinutes) Minutes" -Verbose

#region Functions
#Start-Process "http://www.leeholmes.com/blog/2009/11/20/testing-for-powershell-remoting-test-psremoting/"
#Start-Process "https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-disaster-recovery"
function Get-WindowsKB {
    <#
        .SYNOPSIS
        .DESCRIPTION
        .EXAMPLE
        .PARAMETER ComputerName
        .PARAMETER FunctionName
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Get-WindowsKB",

        [Parameter(Mandatory = $true)]
        [Alias("ConfigFile")]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try{
            Invoke-WebRequest -Uri $config.URL.KB4053579 -OutFile "$($config.RDSResourcesPackages)\$($config.KB.KB4053579)"
        }
        catch{
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Test-PSRemoting {
    <#
        .SYNOPSIS
        .DESCRIPTION
        .EXAMPLE
        .PARAMETER ComputerName
        .PARAMETER FunctioName
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Test-PSRemoting",

        [Parameter(Mandatory = $true,
        HelpMessage = "List of computers acting as Remote Desktop Server Deployment")]
        [ValidateNotNullOrEmpty()]
        [string[]]$rdsDeployment
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
        #$result = @()
    }
    process {
        Write-Verbose "$computerName - $functionName - Testing PowerShell Remoting against $($rdsDeployment.GetEnumerator())"
        try {
            #$errorActionPreference = "Stop"
            $result = Invoke-Command -ComputerName $rdsDeployment {$env:COMPUTERNAME}
            if ($rdsDeployment.Length -eq $result.Length) {
                Write-Information "INFO   : $computerName - $functionName - All your Remote Desktop Deployment hosts are available via PowerShell Remoting"
            }
            else {
                Write-Warning "$computerName - $functionName - Make sure that all your Remote Desktop Deployment hosts are available via PowerShell Remoting"
                break;
            }
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds."
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Get-Prerequisite {
    <#
        .SYNOPSIS
        .DESCRIPTION
        .EXAMPLE
        .PARAMETER ComputerName
        .PARAMETER FunctionName
        .PARAMETER WindowsFeature
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the computer when function is run")]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Get-Prerequisite",

        [Parameter(Mandatory=$true,
        HelpMessage = "Remote Server Administartion Tools to be complemented with PowerShell modules")]
        [ValidateSet("RSAT-AD-Tools","RSAT-DNS-Server")]
        [string[]]$windowsFeature
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            Write-Verbose "$computerName - $functionName - Checking RSAT Prerequisites."
            if (Get-WindowsFeature -Name $windowsFeature) {
               Write-Information "$computerName - $functionName - RSAT Features with PowerShell Modules are already available."
               Write-Information "$computerName - $functionNAme - No need to perform any actions with RSAT Prerequisities."
            }
            else {    
                Write-Verbose "$computerName - $functionName - RSAT Features are getting installed."
                Write-Information "$computerName - $functionName - Complementary PowerShell Modules should be available on $env:ComputerName."
                Install-WindowsFeature $windowsFeature
                Write-Verbose "$computerName - $functionName - RSAT Features and PowerShell Modules are available." -Verbose
            }
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Get-JSONFile {
    <#
        .SYNOPSIS
        .DESCRIPTION
        .EXAMPLE
        .PARAMETER ComputerName
        .PARAMETER FunctioName
        .PARAMETER ConfigPath
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Get-JSONFile",

        [Parameter(Mandatory=$true,
        HelpMessage = "Path to the JSON file")]
        [string]$configPath
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            if (Test-Path $configPath) {
                Write-Verbose "$computerName - $functionName - JSON File $configPath was found." -Verbose
                $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
                Write-Verbose "$computerName - $functionName - JSON File $configPath was imported." -Verbose
            }
            else {
                Write-Error "$computerName - $functionName - Failed to find $configPath File."
                break
            }
            return $config
        }
        catch {
            Write-Error "$computerName - $functionName - Error $_" 
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Get-SSLCertificate {
    <#
        .SYNOPSIS
        .DESCRIPTION
        .EXAMPLE
        .PARAMETER ComputerName
        .PARAMETER FunctionName
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Get-SSLCertificate",

        [Parameter(Mandatory=$true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            $certificateFiles = $config.CertificatePath.Values | out-string -Stream
            #there is possibility that separate certificates are used for deployment 
            #rather than one wildcard certificate which is covering that part
            $certificateFiles.ForEach({
                if (Test-Path $_) {
                    Write-Verbose "$computerName - $functionName - SSL Certificate $_ was found." -Verbose
                }
                else {
                    Write-Warning "$computerName - $functionName - Failed to find the $_ SSL Certificate."
                    Write-Warning "$computerName - $functionName - SSL Certificate is a prerequisite for Remote Desktop Services 2016 deployment."
                    Write-Warning "$computerName - $functionName - Request for the pfx certificate first, then try again with the deployment."
                    break
                }
            })            
            
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

#region multi deployment
function New-RDSDeployment {
    <#
        .SYNOPSIS
        .DESCRIPTION
        .EXAMPLE
        .PARAMETER ComputerName
        .PARAMETER FunctionName
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "New-RDSDeployment",

        [Parameter(Mandatory = $true)]
        [Alias("ConfigFile")]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try{
            Write-Verbose "$computerName - $functionName - Creating new RDS deployment"
            #New-RDSessionDeployment -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01 -WebAccessServer $config.RDWebAccess.WebAccessServer01 -SessionHost @($config.RDSHost01, $config.RDSHost02)
            New-RDSessionDeployment -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01 -WebAccessServer $config.RDWebAccess.WebAccessServer01 -SessionHost $config.RDSessionHost.Values
            Write-Verbose "$computerName - $functionName - New RDS deployment - DONE."
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Edit-RDSDesktopCollection {
    <#
        .SYNOPSIS
        .DESCRIPTION
        .EXAMPLE
        .PARAMETER ComputerName
        .PARAMETER FunctionName
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Edit-RDSDesktopCollection",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
        
    }
    process {
        try {
            Write-Verbose "$computerName - $functionName - Creating new RDS Desktop Collection $($config.RDCollection01.DesktopCollectionName)"
            #New-RDSessionCollection  -CollectionName $config.DesktopCollectionName -SessionHost @($config.RDSHost01, $config.RDSHost02)  -CollectionDescription $config.DesktopDescription  -ConnectionBroker $config.ConnectionBroker01
            New-RDSessionCollection  -CollectionName $config.RDCollection01.DesktopCollectionName -SessionHost $config.RDSessionHost.Values  -CollectionDescription $config.RDCollection01.DesktopDiscription  -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01
            Write-Verbose "$computerName - $functionName - RDS Desktop Collection $($config.RDCollection01.DesktopCollectionName) - DONE."
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

#rewrite this function that you invoke the function itself than invoking commands from the function
function Add-RDGateway {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Add-RDGateway",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try{
            Write-Verbose "$computerName - $functionName - Installing RDS Gateway on $($config.RDGateway.GatewayServer01)"
            Add-WindowsFeature -Name RDS-Gateway -IncludeManagementTools -ComputerName $config.RDGateway.GatewayServer01
            
            Write-Verbose "$computerName - $functionName - Joining RDS Gateway $($config.RDGateway.GatewayServer01) to Broker $($config.RDConnectionBroker.ConnectionBroker01)"
            Add-RDServer -Server $config.RDGateway.GatewayServer01 -Role "RDS-GATEWAY" -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01 -GatewayExternalFqdn $config.DNSEntry.RDGatewayExternalFqdn
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }

}

#2018.01.02 - still some issues with this function
#problems with The RDS:\ psprovider
function Set-RDGatewayCAPRAP {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK
        https://blogs.technet.microsoft.com/ptsblog/2011/12/09/extending-remote-desktop-services-using-powershell
        .LINK
        https://blogs.technet.microsoft.com/ptsblog/2011/12/09/extending-remote-desktop-services-using-powershell-part-2
        .LINK
        https://blogs.technet.microsoft.com/ptsblog/2011/12/09/extending-remote-desktop-services-using-powershell-part-3
        .LINK
        https://blogs.technet.microsoft.com/ptsblog/2011/12/09/extending-remote-desktop-services-using-powershell-part-4
        .LINK
        https://blogs.technet.microsoft.com/ptsblog/2011/12/09/extending-remote-desktop-services-using-powershell-part-5
        .LINK
        https://blogs.technet.microsoft.com/ptsblog/2011/12/09/extending-remote-desktop-services-using-powershell-part-6
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Set-RDGatewayCAPRAP",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            Write-Verbose "$computerName - $functionName - Configuring GW Policies on RDS Gateway $($config.RDGateway.GatewayServer01)"
            Invoke-Command -ComputerName $config.RDGateway.GatewayServer01 -ScriptBlock {
               #$RDGatewayFarmName = $args[0]
               #$RDGatewayAccessGroup = $args[1]
               #$RDBrokerDNSInternalName = $args[2]
               #$RDBrokerDNSInternalZone = $args[3]
               #$RDSHost01 = $args[4]
               #$RDSHost02 = $args[5]
               Import-Module -Name RemoteDesktopServices #this will bring the RDS PSProvider
               Remove-Item -Path "RDS:\GatewayServer\CAP\RDG_CAP_AllUsers" -Force -recurse
               Remove-Item -Path "RDS:\GatewayServer\RAP\RDG_RDConnectionBrokers" -Force -recurse
               Remove-Item -Path "RDS:\GatewayServer\RAP\RDG_AllDomainComputers" -Force -recurse
               Remove-Item  -Path "RDS:\GatewayServer\GatewayManagedComputerGroups\RDG_RDCBComputers"-Force -recurse
               New-Item -Path "RDS:\GatewayServer\GatewayManagedComputerGroups" -Name $using:config.RDGatewayFarmName -Description $using:config.RDGatewayFarmName -Computers "$($using:config.RDBrokerDNSInternalName).$($using:config.RDBrokerDNSInternalZone)" -ItemType "String"
               #New-Item -Path "RDS:\GatewayServer\GatewayManagedComputerGroups" -Name $RDGatewayFarmName -Description $RDGatewayFarmName -Computers "$RDBrokerDNSInternalName.$RDBrokerDNSInternalZone" -ItemType "String"
               $temp = $using:config.RDSessionHost.Values | sort
               $temp.foreach({
                   New-Item -Path "RDS:\GatewayServer\GatewayManagedComputerGroups\$($using:config.RDGatewayFarmName)\Computers" -Name $_ -ItemType "String"
               })
               #New-Item -Path "RDS:\GatewayServer\GatewayManagedComputerGroups\$RDGatewayFarmName\Computers" -Name $RDSHost01 -ItemType "String"
               #New-Item -Path "RDS:\GatewayServer\GatewayManagedComputerGroups\$RDGatewayFarmName\Computers" -Name $RDSHost02 -ItemType "String"
        
               New-Item -Path "RDS:\GatewayServer\RAP" -Name "RDG_RAP_$($using:config.RDGatewayFarmName)" -UserGroups $using:config.ADGroup.RDGatewayAccessGroup -ComputerGroupType 0 -ComputerGroup $using:config.RDGatewayFarmName
               New-Item -Path "RDS:\GatewayServer\CAP" -Name "RDG_CAP_$($using:config.RDGatewayFarmName)" -UserGroups $using:config.ADGroup.RDGatewayAccessGroup -AuthMethod 1
        
           } #-ArgumentList $config.RDGatewayFarmName, $config.RDGatewayAccessGroup, $config.RDBrokerDNSInternalName, $config.RDBrokerDNSInternalZone, $config.RDSHost01, $config.RDSHost02
           Write-Verbose "$computerName - $functionName - CAP & RAP Policies on: $($using:config.RDGateway.GatewayServer01) - DONE."
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Add-DNSRecordAWebAccess {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Add-DNSRecordAWebAccess",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process{
        #rewrite this function so it is invoking-command - rething whether we are passing function to invoke or invking inside function
        try{
            Write-Verbose "$computerName - $functionName - Importing DNSServer Module from $($config.DomainController)."
            $dcPSSession = New-PSSession -ComputerName $config.DomainController
            $VerbosePreference = "SilentlyContinue"
            Import-Module -PSSession $dcPSSession -Name DNSServer
            $VerbosePreference = "Continue"
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }

        try{
            Write-Verbose "$computerName - $functionName - Creating WebAcces DNS-A-Record $($config.DNSEntry.RDWebAccessDNSInternalName)."
            $IPWebAccess01 = [System.Net.Dns]::GetHostAddresses("$($config.RDWebAccess.WebAccessServer01)")[0].IPAddressToString
            Add-DnsServerResourceRecordA -ComputerName $config.DomainController -Name $config.DNSEntry.RDWebAccessDNSInternalName -ZoneName $config.DNSEntry.RDWebAccessDNSInternalZone -AllowUpdateAny -IPv4Address $IPWebAccess01
            Write-Verbose "$computerName - $functionName - WebAccess DNS-Record $($config.DNSEntry.RDWebAccessDNSInternalName) - DONE."
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        Write-Verbose "$computerName - $functionName - Removing DNSServer Module."
        $VerbosePreference = "SilentlyContinue"
        Remove-Module DNSServer -Force
        $VerbosePreference = "Continue"
        Write-Verbose "$computerName - $functionName - Closing PowerShell Remoting Connection to $($config.DomainController)"
        Get-PSSession -ComputerName $config.DomainController | Remove-PSSession
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

#rewrite this function that you invoke the function itself than invoking commands from the function
function Set-IISDefaultWebPage {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Set-IISDefaultWebPage",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            #region Redirect to RDWeb (IIS)
            Write-Verbose "$computerName - $functionName - Redirecting IIS default webpage to RDWeb"
            Invoke-Command -ComputerName $config.RDWebAccess.WebAccessServer01 -ScriptBlock {
                #$RDWebAccessDNSInternalName = $args[0]
                #$RDWebAccessDNSInternalZone = $args[1]
                $siteName = "Default Web Site"
                Import-Module webAdministration
                Set-WebConfiguration system.webServer/httpRedirect "IIS:\sites\$siteName" -Value @{enabled="true";destination="https://$($using:config.DNSEntry.RDWebAccessDNSInternalName).$($using:config.DNSEntry.RDWebAccessDNSInternalZone)/RDWeb";exactDestination="true";httpResponseStatus="Found"} 
            } #-ArgumentList $config.RDWebAccessDNSInternalName, $config.RDWebAccessDNSInternalZone
            Write-Verbose "$computerName - $functionName - RDWeb Redirect on $($config.RDWebAccess.WebAccessServer01) -DONE."
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

#this function has a function help which can be used in other functions
function Edit-RDSCollection {
    <#
        .SYNOPSIS 
        one
        .DESCRIPTION 
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE 
        three
        .LINK 
        https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-storage-spaces-direct-deployment
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Edit-RDSCollection",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try{
            Write-Verbose "$computerName - $functionName - Allowing $($config.ADGroup.RDAccessGroup) having access to $($config.RDCollection01.DesktopCollectionName)."
            Set-RDSessionCollectionConfiguration -CollectionName $config.RDCollection01.DesktopCollectionName -UserGroup $config.ADGroup.RDAccessGroup -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01
            Write-Verbose "$computerName - $functionName - $($config.ADGroup.RDAccessGroup) acess to Collection $($config.RDCollection01.DesktopCollectionName) - READY."
            
            Write-Verbose "$computerName - $functionName - Configuring Profile Disk Settings - $($config.RDCollection01.ProfileDiskPath)."
            Set-RDSessionCollectionConfiguration -CollectionName $config.RDCollection01.DesktopCollectionName -EnableUserProfileDisk -MaxUserProfileDiskSizeGB $config.RDCollection01.ProfileDiskSize -DiskPath $config.RDCollection01.ProfileDiskPath -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01
            Write-Verbose "$computerName - $functionName - ProfileDisk $($config.ProfileDiskPath) combined with Collection $($config.RDCollection01.DesktopCollectionName) - READY."
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Set-RDSLicensing {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Set-RDSLicensing",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            Write-Verbose "$computerName - $functionName - Installing RDS License Server on $($config.License.LicServer01)"
            Add-RDServer -Server $config.License.LicServer01 -Role "RDS-LICENSING" -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01
            Write-Verbose "$computerName - $functionName - RDS Licence Server Role on $($config.License.LicServer01) - DONE."
            Set-RDLicenseConfiguration -LicenseServer $config.License.LicServer01 -Mode $config.License.LicMode -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01 -Force
            Write-Verbose "$computerName - $functionName - RDS Licening Mode on $($config.License.LicServer) - DONE."
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

#rewrite this function that it get's the password from the commandline
function Set-SSLCertificateConfiguration {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Set-SSLCertificateConfiguration",

        [Parameter(Mandatory = $true)]
        $config
    )

    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            # In case you can not use wildcard certificate for your deployment
            # Follow up with SAN certificates - depending from the scale of your deployment you may need few certs, as there is a limitation for 5alternative names within each cert
            # if you are using private CA, then take the benefit from the WebServer template
            Write-Verbose "$computerName - $functionName - Configuring SSL Certificates for the RDS deployment"
            $RDPublishing = ConvertTo-SecureString -String $config.CertificatePassword.RDPublishing -AsPlainText -Force
            $RDRedirector = ConvertTo-SecureString -String $config.CertificatePassword.RDRedirector -AsPlainText -Force
            $RDWebAccess = ConvertTo-SecureString -String $config.CertificatePassword.RDWebAccess -AsPlainText -Force
            $RDGateway = ConvertTo-SecureString -String $config.CertificatePassword.RDGateway -AsPlainText -Force
            Set-RDCertificate -Role RDPublishing -ImportPath $config.CertificatePath.RDPublishing  -Password $RDPublishing -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01 -Force -Verbose
            Set-RDCertificate -Role RDRedirector -ImportPath $config.CertificatePath.RDRedirector -Password $RDRedirector -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01 -Force -Verbose
            Set-RDCertificate -Role RDWebAccess -ImportPath $config.CertificatePath.RDWebAccess -Password $RDWebAccess -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01 -Force -Verbose
            Set-RDCertificate -Role RDGateway -ImportPath $config.CertificatePath.RDGateway  -Password $RDGateway -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01 -Force -Verbose
            Write-Verbose "$computerName - $functionName - Configuration of SSL Certificates - DONE."
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Set-RDGatewayMapping {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Set-RDGatewayMapping",

        [Parameter(Mandatory = $true)]
        $config = $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            #region Configure WebAccess (when RDBroker is available, no Gateway will be used)
            Write-Verbose "$computerName - $functionName - Configuring Gateway Mapping for $($config.DNSEntry.RDGatewayExternalFqdn)"
            Set-RDDeploymentGatewayConfiguration -GatewayMode Custom -GatewayExternalFqdn $config.DNSEntry.RDGatewayExternalFqdn -LogonMethod Password -UseCachedCredentials $True -BypassLocal $True -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01 -Force
            Write-Verbose "$computerName - $functionName - Gateway Mapping - READY."
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
        
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Add-DNSRecordTXTWebFeed {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Add-DNSRecordTXTWebFeed",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            Write-Verbose "$computerName - $functionName - Importing DNSServer Module from $($config.DomainController)."
            $dcPSSession = New-PSSession -ComputerName $config.DomainController
            $VerbosePreference = "SilentlyContinue"
            Import-Module -PSSession $dcPSSession -Name DNSServer
            $VerbosePreference = "Continue"
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
        try {
            #region Create TXT WebFeed DNS Record - Create RemoteAccess connection via e-Mail address
            Write-Verbose "$computerName - $functionName - Creating TXT WebFeed DNS Record."
            Add-DnsServerResourceRecord -ZoneName $config.RDWebAccessDNSInternalZone -Name "_msradc" -Txt -DescriptiveText "https://$($config.DNSEntry.RDWebAccessDNSInternalName).$($config.DNSEntry.RDWebAccessDNSInternalZone)/RDWeb/Feed"
            Write-Verbose "$computerName - $functionName - TXT WebFeed DNS Record - READY."
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        Write-Verbose "$computerName - $functionName - Removing DNSServer Module."
        $VerbosePreference = "SilentlyContinue"
        Remove-Module DNSServer -Force
        $VerbosePreference = "Continue"
        Write-Verbose "$computerName - $functionName - Closing PowerShell Remoting Connection to $($config.DomainController)."
        Get-PSSession -ComputerName $config.DomainController | Remove-PSSession
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Add-DNSRecordARDSBroker {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Add-DNSRecordARDSBroker",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            Write-Verbose "$computerName - $functionName - Importing DNSServer Module from $($config.DomainController)."
            $dcPSSession = New-PSSession -ComputerName $config.DomainController
            $VerbosePreference = "SilentlyContinue"
            Import-Module -PSSession $dcPSSession -Name DNSServer
            $VerbosePreference = "Continue"
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
        try {
            #region Create RDS Broker DNS-Record
            Write-Verbose "$computerName - $functionName - Configuring RDSBroker DNS-Record"
            $IPBroker01 = [System.Net.Dns]::GetHostAddresses("$($config.RDConnectionBroker.ConnectionBroker01)")[0].IPAddressToString
            Add-DnsServerResourceRecordA -ComputerName $config.DomainController  -Name $config.DNSEntry.RDBrokerDNSInternalName -ZoneName $config.DNSEntry.RDBrokerDNSInternalZone -AllowUpdateAny -IPv4Address $IPBroker01
            Write-Verbose "$computerName - $functionName - RDS Broker DNS-Record $($config.DNSEntry.RDBrokerDNSInternalName).$($config.DNSEntry.RDBrokerDNSInternalZone) - READY."
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        Write-Verbose "$computerName - $functionName - Removing DNSServer Module."
        $VerbosePreference = "SilentlyContinue"
        Remove-Module DNSServer -Force
        $VerbosePreference = "Continue"
        Write-Verbose "$computerName - $functionName - Closing PowerShell Remoting Connection to $($config.DomainController)."
        Get-PSSession -ComputerName $config.DomainController | Remove-PSSession
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

#rewrite this function that it is invoked itself than invoking commands from the function
#rewrite this function that it is using remoting instead of SMB for copying the files
function Set-RDPublishedName {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Set-RDPublishedName",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            #consider rewriting this function - that it uses powershell remoting to copy the content instead of regular SMB copy
            #region Change RDPublishedName
            #https://gallery.technet.microsoft.com/Change-published-FQDN-for-2a029b80
            Write-Verbose "$computerName - $functionName "
            $winRMConnectionBroker = New-PSSession -ComputerName $config.RDConnectionBroker.ConnectionBroker01
            Invoke-WebRequest -Uri $config.URL.RDPublishedNameUrl -OutFile "$env:SystemDrive\Resources\RDS\Set-RDPublishedName.ps1"
            #Copy-Item "$env:SystemDrive\Resources\RDS\Set-RDPublishedName.ps1" -Destination "\\$($config.RDConnectionBroker.ConnectionBroker01)\c$" -ToSession $winRMConnectionBroker
            Copy-Item "$env:SystemDrive\Resources\RDS\Set-RDPublishedName.ps1" -Destination "$env:SystemDrive\Set-RDPublishedName.ps1" -ToSession $winRMConnectionBroker
            Invoke-Command -Session $winRMConnectionBroker -ScriptBlock {
                #$RDBrokerDNSInternalName = $args[0]
                #$RDBrokerDNSInternalZone = $args[1]
                Set-Location C:\
                .\Set-RDPublishedName.ps1 -ClientAccessName "$($using:config.DNSEntry.RDBrokerDNSInternalName).$($using:config.DNSEntry.RDBrokerDNSInternalZone)"
                Remove-Item "C:\Set-RDPublishedName.ps1"
            } #-ArgumentList $config.RDBrokerDNSInternalName, $config.RDBrokerDNSInternalZone
            
            Write-Verbose "$computerName - $functionName - RDPublisher Name - READY."
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        Write-Verbose "$computerName - $functionName - Closing PowerShell Remoting Connection to $($config.RDConnectionBroker.ConnectionBroker01)"
        Get-PSSession -ComputerName $config.RDConnectionBroker.ConnectionBroker01 | Remove-PSSession
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}
#endregion

#region HA deployment
function Add-BrokerSecurityGroupHA {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Add-BrokerSecurityGroupHA",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            Write-Verbose "$computerName - $functionName - Importing ActiveDirectory Module from $($config.DomainController)."
            $dcPSSession = New-PSSession -ComputerName $config.DomainController
            $VerbosePreference = "SilentlyContinue"
            Import-Module -PSSession $dcPSSession -Name ActiveDirectory
            $VerbosePreference = "Continue"
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
        try {
            #region Create HA Broker Security Group for SQL Database Access
            #add description for the RDConnectionBrokersGroup
            New-ADGroup  -Name $config.ADGroup.RDConnectionBrokersGroup -GroupCategory Security -GroupScope Global  -Server $config.DomainController
            Write-Verbose "$computerName - $functionName - $($config.ADGroup.RDConnectionBrokersGroup) Security Group has been added in ActiveDirectory."
            ($config.RDConnectionBroker.Values.GetEnumerator()).foreach({
                Write-Verbose "$computerName - $functionName - $($_.Split(".")[0]) has been added to $($config.ADGroup.RDConnectionBrokersGroup)"
                Add-ADGroupMember -Identity $config.ADGroup.RDConnectionBrokersGroup -Members "$($_.Split(".")[0])$" -Server $config.DomainController
            })
            #Add-ADGroupMember -Identity $config.ADGroup.RDConnectionBrokersGroup -Members "$($config.ConnectionBroker01.Split(".")[0])$" -Server $config.DomainController
            #Add-ADGroupMember -Identity $config.ADGroup.RDConnectionBrokersGroup -Members "$($config.ConnectionBroker02.Split(".")[0])$" -Server $config.DomainController
            #Add-ADGroupMember -Identity $config.ADGroup.RDConnectionBrokersGroup -Members "$($config.RDSessionHost.SessionHost01.Split(".")[0])$" -Server $config.DomainController
            #Add-ADGroupMember -Identity $config.ADGroup.RDConnectionBrokersGroup -Members "$($config.RDSessionHost.SessionHost02.Split(".")[0])$" -Server $config.DomainController
            Write-Verbose "$computerName - $functionName - Connection Brokers are members of $($config.ADGroup.RDConnectionBrokersGroup)"
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        Write-Verbose "$computerName - $functionName - Removing ActiveDirectory Module."
        $VerbosePreference = "SilentlyContinue"
        Remove-Module ActiveDirectory -Force
        $VerbosePreference = "Continue"
        Write-Verbose "$computerName - $functionName - Closing PowerShell Remoting Connection to $($config.DomainController)."
        Get-PSSession -ComputerName $config.DomainController | Remove-PSSession
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds."
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

#rewrite this function and introduce a loop inside it
#rewrite it this way that it is using pure remoting instead of WMI and DCOM
function Restart-BrokerServer {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Restart-BrokerServer",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            #region Restart Broker Server (that Broker Security Group is being applied)
            #for this to work make sure that on the remote host the following firewall rules are ON
            # Windows Management Instrumentation (ASync-In)
            # Windows Management Instrumentation (DCOM-In)
            # Windows Management Instrumentation (WMI-In)
            $connectionBrokers = $config.RDConnectionBroker.Values | sort | out-string -Stream
            Write-Verbose "$computerName - $functionName - Restarting $($connectionBrokers.Length) Connection Brokers."
            Restart-Computer -ComputerName $connectionBrokers -Wait -For WinRM -Delay 5 -Timeout 300 -Protocol WSMan -Force
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Add-DNSRecordARoundRobinLB {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Add-DNSRecordARoundRobinLB",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        [System.Collections.ArrayList] $connectionBrokersIPs = @()
        [System.Collections.ArrayList] $webAccessServersIPs = @()
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            #region Create HA RDS Broker DNS-Record - Round Robin
            Write-Verbose "$computerName - $functionName - Importing DNSServer Module from $($config.DomainController)."
            $dcPSSession = New-PSSession -ComputerName $config.DomainController
            $VerbosePreference = "SilentlyContinue"
            Import-Module -PSSession $dcPSSession -Name DNSServer
            $VerbosePreference = "Continue"
            $connectionBrokers = $config.RDConnectionBroker.Values | sort | out-string -Stream
            $webAccessServers = $config.RDWebAccess.Values | sort | out-string -Stream
            
            Write-Verbose "$computerName - $functionName - Getting IP address for Remote Desktop Connection Brokers."
            $connectionBrokers.ForEach({
                $connectionBrokersIPs.add([System.Net.Dns]::GetHostAddresses("$_")[0].IPAddressToString)
            })
            Write-Verbose "$computerName - $functionName - Adding A records for the Round Robin DNS load balancing."
            $webAccessServersIPs.ForEach({
                try{
                    Write-Verbose "$computerName - $functionNAme - Adding A record - $($config.DNSEntry.RDBrokerDNSInternalName) - $_" -Verbose
                    Add-DnsServerResourceRecordA -ComputerName $config.DomainController -Name $config.DNSEntry.RDBrokerDNSInternalName -ZoneName $config.DNSEntry.RDBrokerDNSInternalZone -AllowUpdateAny -IPv4Address $_
                }
                catch {
                    Write-Error "$computerName - $functionName - Error " $_
                }
                
            })
            
            Write-Verbose "$computerName - $functionName - Getting IP address for Remote Desktop Web Access Servers."
            $webAccessServers.ForEach({
                $webAccessServersIPs.add([System.Net.Dns]::GetHostAddresses("$_")[0].IPAddressToString)
            })
            Write-Verbose "$computerName - $functionName - Adding A records for the Round Robin DNS load balancing."
            $webAccessServersIPs.ForEach({
                try{
                    Write-Verbose "$computerName - $functionNAme - Adding A record - $($config.DNSEntry.RDWebAccessDNSInternalName) - $_" -Verbose
                    Add-DnsServerResourceRecordA -ComputerName $config.DomainController -Name $config.DNSEntry.RDWebAccessDNSInternalName -ZoneName $config.DNSEntry.RDWebAccessDNSInternalZone -AllowUpdateAny -IPv4Address $_
                }
                catch {
                    Write-Error "$computerName - $functionName - Error " $_
                }
                
            })
            #Add-DnsServerResourceRecordA -ComputerName $config.DomainController -Name $config.RDBrokerDNSInternalName -ZoneName $config.RDBrokerDNSInternalZone -AllowUpdateAny -IPv4Address $IPBroker02
            #Write-Verbose "$computerName - $functionName - Configured RDSBroker DNS-Record: $($config.RDBrokerDNSInternalName) - $IPBroker02"
            #Add-DnsServerResourceRecordA -ComputerName $config.DomainController  -Name $config.RDWebAccessDNSInternalName -ZoneName $config.RDWebAccessDNSInternalZone -AllowUpdateAny -IPv4Address $IPWebAccess02
            #Write-Verbose "$computerName - $functionName - Configured WebAccess DNS-Record: $($config.RDWebAccessDNSInternalName) - $IPWebAccess02"
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        Write-Verbose "$computerName - $functionName - Removing DNSServer Module."
        $VerbosePreference = "SilentlyContinue"
        Remove-Module DNSServer -Force
        $VerbosePreference = "Continue"
        Write-Verbose "$computerName - $functionName - Closing PowerShell Remoting Connection to $($config.DomainController)"
        Get-PSSession -ComputerName $config.DomainController | Remove-PSSession
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Get-SQLNativeClient {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Get-SQLNativeClient",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            #rewrite this function that all variables are covered inside the json file or defined within the script
            #region Download SQL Native Client
            #Invoke-WebRequest -Uri "https://download.microsoft.com/download/B/E/D/BED73AAC-3C8A-43F5-AF4F-EB4FEA6C8F3A/1033/amd64/sqlncli.msi" -OutFile "C:\rds\sqlncli.msi"
            if (Test-Path -Path $config.RDSResourcesPackages){
                Write-Verbose "$computerName - $functionName - $($config.RDSResourcesPackages) directory already exist."
            }
            else {
                Write-Verbose "$computerName - $functionName - Creating directory $($config.RDSResourcesPackages)."
                New-Item -ItemType Directory -Path $config.RDSResourcesPackages
            }
            Invoke-WebRequest -Uri $config.URL.SQLNativeClientUrl -OutFile $config.SQLNativeClientMsi
            if (Test-Path $config.SQLNativeClientMsi) {
                Write-Verbose "$computerName - $functionName - SQL Native Client has been downloaded to $($config.RDSResourcesPackages) on $env:COMPUTERNAME."
            }
            Else {
                Write-Warning "$computerName - $functionName - Couldn't Download SQL Native Client on $env:COMPUTERNAME."
                break
            }
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Install-SQLNativeClient {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Install-SQLNativeClient",

        [Parameter(Mandatory = $true)]
        $config

    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            #region Install SQLNativeClient on Connection Brokers
            Write-Verbose "$computerName - $functionName - Opening PowerShell Remoting Session to Remote Desktop Connection Brokers."
            $connectionBrokers = $config.RDConnectionBroker.Values | sort | Out-String -Stream
            Write-Information "$computerName - $functionName - $($connectionBrokers.count) Connection Brokers has been identified."
            #$winRMConnectionBroker01 = New-PSSession -ComputerName $config.ConnectionBroker01
            #$winRMConnectionBroker02 = New-PSSession -ComputerName $config.ConnectionBroker02
            
            $winRMConnectionBrokers = New-PSSession -ComputerName $connectionBrokers
            #$winRMConnectionBrokers = @($winRMConnectionBroker01,$winRMConnectionBroker02)

            Invoke-Command -Session $winRMConnectionBrokers -ScriptBlock {
                if (Test-Path -Path ($using:config.RDSResourcesPackages)) {
                    #Write-Verbose "$($using:computerName) - $($using:functionName) - $($using:config.RDSResourcesPackages) directory already exist."
                    Write-Verbose "$($env:COMPUTERNAME) - $($using:functionName) - $($using:config.RDSResourcesPackages) directory already exist."
                }
                else {
                    #Write-Verbose "$($using:computerName) - $($using:functionName) - Creating directory $($using:config.RDSResourcesPackages)."
                    Write-Verbose "$($env:COMPUTERNAME) - $($using:functionName) - Creating directory $($using:config.RDSResourcesPackages)."
                    New-Item -Path $($using:config.RDSResourcesPackages) -ItemType Directory
                }
            }
            
            try{
                Write-Verbose "$computerName - $functionName - Copying $($config.SQLNativeClientMsi) to RemoteDesktop Connection Brokers."
                $winRMConnectionBrokers.ForEach({
                    Write-Information "$computerName - $functionName - Copying $($config.SQLNativeClientMsi) to $($_.ComputerName)"
                    Copy-Item -Path $config.SQLNativeClientMsi -ToSession $_ -Destination $config.SQLNativeClientMsi -Force
                })
            }
            catch {
                Write-Error "$computerName - $functionName - Error " $_
            }
            
            #Copy-Item $config.SQLNativeClientMsi -Destination "\\$($config.ConnectionBroker01)\c$"
            Write-Verbose "$computerName - $functionName - Launching SQL Native Client Installation on RemoteDesktop Connection Brokers."
            Invoke-Command -session $winRMConnectionBrokers -ScriptBlock {
                #$ConnectionBroker01 = $args[0]
                $install = Start-Process "msiexec.exe" -ArgumentList "/i $($using:config.SQLNativeClientMsi)", "/qn", "IACCEPTSQLNCLILICENSETERMS=YES", "/log $($using:config.SQLNativeClientLog)" -PassThru -Wait 
                    if ($install.ExitCode -ne 0) {
                        Write-Warning "SQL Client failed to install with $($install.ExitCode) on $env:COMPUTERNAME"
                        break
                    }
                    else {
                        Write-Verbose "SQL Client installed succesfull on $env:COMPUTERNAME"
                    }
                Write-Verbose "$($env:COMPUTERNAME)- $($using:functionName) - Removing $($using:config.SQLNativeClientMsi) from $env:COMPUTERNAME."
                Remove-Item -Path $($using:config.SQLNativeClientMsi)
            } #-ArgumentList $config.ConnectionBroker01
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
        
        #try {
        #    #region Install SQLNativeClient on ConnectionBroker02
        #    Copy-Item "C:\rds\sqlncli.msi" -Destination "\\$($config.ConnectionBroker02)\c$"
        #    Invoke-Command -ComputerName $config.ConnectionBroker02 -ScriptBlock {
        #        $ConnectionBroker02 = $args[0]
        #        $install = Start-Process "msiexec.exe" -ArgumentList "/i C:\sqlncli.msi", "/qn", "IACCEPTSQLNCLILICENSETERMS=YES", "/log C:\sql.log" -PassThru -Wait 
        #        if ($install.ExitCode -ne 0) {
        #            Write-Warning "SQL Client failed to install with $($install.ExitCode) on $ConnectionBroker02"
        #            break
        #        }
        #        else {
        #        Write-Verbose "SQL Client installed succesfull on $ConnectionBroker02" -Verbose
        #        }
        #        Remove-Item "C:\sqlncli.msi"
        #    } -ArgumentList $config.ConnectionBroker02
        #    #endregion
        #}
        #catch {
        #    Write-Error "$computerName - $functionName - Error " $_
        #}
    }
    end {
        Write-Verbose "$computerName - $functionName - Closing $($connectionBrokers.count) PowerShell Remoting Connection to Connection Brokers."
        $connectionBrokers.ForEach({Get-PSSession -ComputerName $_}) | Remove-PSSession
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Set-SQLHighAvailability {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK
        https://docs.microsoft.com/en-us/sql/relational-databases/native-client/applications/installing-sql-server-native-client
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Set-SQLHighAvailability",
        
        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try{
            #here is an assumption that you are using particular version of the SQL - what if the Native Client is in diff. version
            #-DatabaseConnectionString "DRIVER=SQL Server Native Client 11.0;SERVER=$($config.SQLServer);Trusted_Connection=Yes;APP=Remote Desktop Services Connection Broker;DATABASE=$($config.SQLDatabase)" `
            Write-Verbose "$computerName - $functionName - Configuring RDS Connection Broker High Availablilty."
            Set-RDConnectionBrokerHighAvailability -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01 `
            -DatabaseConnectionString "DRIVER=$($config.SQLConnectionString.ServerNativeClient);SERVER=$($config.SQLServer.SQLServer01);Trusted_Connection=$($config.SQLConnectionString.TrustedConnection);APP=$($config.SQLConnectionString.APP);DATABASE=$($config.SQLDatabase)" `
            -ClientAccessName "$($config.DNSEntry.RDBrokerDNSInternalName).$($config.DNSEntry.RDBrokerDNSInternalZone)" `
            -DatabaseFilePath $config.SQLFilePath
            Write-Verbose "$computerName - $functionName - Remote Desktop Connection Broker High Availablilty configuration - DONE."
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Add-SubsequentRDConnectionBroker {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Add-SubsequentRDConnectionBroker",
        
        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        [System.Collections.ArrayList] $connectionBrokers = @()
        $startDate = Get-Date
    }
    process {
        try {
            #region Join subsequent Connection Broker
            $connectionBrokers = $config.RDConnectionBroker.Values | sort | out-string -Stream
            $connectionBrokers | select -skip 1 | ForEach({ #skipping first connection broker
                Add-RDServer -Server $_ -Role "RDS-CONNECTION-BROKER" -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01
                Write-Verbose "$computerName - $functionName - Remote Desktop Connection Broker Server: $($_) - JOINED."
                #region Reboot Subsequent Connection Broker (without Reboot, there can occur errors with the next commands)
                Write-Verbose "$computerName - $functionName - $_ will reboot."
                #Restart-Computer -ComputerName $_ -Wait -For WinRM -Timeout 300 -Delay 2 -Protocol WSMan -Force
                Write-Verbose "$computerName - $functionName - $_ online again."
            })
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Get-ActiveBroker {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Get-ActiveBroker",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        #region Determine ActiveBroker
        try {
            Write-Verbose "$computerName - $functionName - Retrieving Remote Desktop Broker which plays primary role"
            $primaryBroker = (Get-RDConnectionBrokerHighAvailability -ConnectionBroker $config.RDConnectionBroker.ConnectionBroker01).ActiveManagementServer
            return $primaryBroker
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
        #endregion
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Add-SubsequentRDWebAccessServer {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Add-SubsequentRDWebAccessServer",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        #[System.Collections.ArrayList] $webAccessServers = @()
        $startDate = Get-Date
    }
    process {
        try {
            #region Joinining Subsequent WebAccess Server
            $webAccessServers = $config.RDWebAccess.Values | sort | select -Skip 1 | out-string -Stream #skipping first RD Web Access Server
            Write-Verbose "$computerName - $functionName - Joining Subsequent Remote Desktop Web Access Server."
            #Add-RDServer -Server $config.RDWebAccess.WebAccessServer02 -Role "RDS-WEB-ACCESS" -ConnectionBroker $primaryBroker
            $webAccessServers.Foreach({
                Add-RDServer -Server $_ -Role "RDS-WEB-ACCESS" -ConnectionBroker $primaryBroker
                Write-Verbose "$($_) Remote Desktop WebAccess Server - JOINED."
            })
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

#rewrite this function that it is invoked itself, rather than invoking commands from the function
function Set-SubsequentIISDefaultWebPage {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Set-SubsequentIISDefaultWebPage",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        #[System.Collections.ArrayList] $webAccessServers = @()
        $startDate = Get-Date
    }
    process {
        try {
            #region Redirect to RDWeb (IIS) on Subsequent Web Access Servers
            $webAccessServers = $config.RDWebAccess.Values | sort | select -Skip 1 | out-string -Stream
            Write-Verbose "$computerName - $functionName - Redirecting Default IIS WebPage on Remote Desktop Web Access Server."
            Invoke-Command -ComputerName $webAccessServers -ScriptBlock {
                #$RDWebAccessDNSInternalName = $args[0]
                #$RDWebAccessDNSInternalZone = $args[1]
                $siteName = "Default Web Site"
                Import-Module webAdministration
                Set-WebConfiguration system.webServer/httpRedirect "IIS:\sites\$siteName" -Value @{enabled="true";destination="https://$($using:config.DNSEntry.RDWebAccessDNSInternalName).$($using:config.DNSEntry.RDWebAccessDNSInternalZone)/RDWeb";exactDestination="true";httpResponseStatus="Found"} 
            } #-ArgumentList $config.RDWebAccessDNSInternalName, $config.RDWebAccessDNSInternalZone
            Write-Verbose "$computerName - $functionName - Success"
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

#rewrite this function that the parameters are available in the json file
function Get-MachineKeyRDWebServices {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Get-MachineKeyRDWebServices",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $webAccessServers = $config.RDWebAccess.Values | sort | out-string -Stream
        $configureMachineKeys = "$($config.RDSResourcesPackages)\Configure-MachineKeys.ps1"
        $argumentList = "-ComputerName $webAccessServers -Mode Write"
        $startDate = Get-Date
    }
    process {
        try {
            $webAccessServers = $config.RDWebAccess.Values | sort | select -Skip 1 | out-string -Stream
            $webAccessServers = $config.RDWebAccess.Values | sort | out-string -Stream
            #region Create same Machine Key for RDWeb Services
            # Start-Process https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-rdweb-gateway-ha
            # Start-Process https://gallery.technet.microsoft.com/Get-and-Set-the-machineKeys-9a1e7b77
            Write-Verbose "$computerName - $functionName - Downloading Configure-MachineKeys Script."
            Invoke-WebRequest -Uri $config.URL.MachineKeysUrl -OutFile $configureMachineKeys
            if (Test-Path -Path $configureMachineKeys) {
                Invoke-Expression "& `"$configureMachineKeys`" -ComputerName $($webAccessServers -join ',') -Mode Write"
                #C:\Resources\RDS\Configure-MachineKeys.ps1 -ComputerName $webAccessServers -Mode Write
                Write-Verbose "$computerName - $functionName - Machine Keys for RDWeb Servers Configuration - DONE"
            }
            Else {
                Write-Warning "$computerName - $functionName - Couldn't download Configure-MachineKeys Script."
                break
            }
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

#verify whether the ConnectionBroker02 is the proper output in the Write-Verbose function
function Add-SubsequentRDGateway {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Add-SubsequentRDGateway",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        #[System.Collections.ArrayList] $gatewayServers = @()
        $startDate = Get-Date
    }
    process {
        try {
            $gatewayServers = $config.RDGateway.Values | sort | select -Skip 1 | out-string -Stream
            #region Join RDGatewayServer02
            #Write-Verbose "$computerName - $functionName - Joining Gateway Server: $($config.ConnectionBroker02)"
            $gatewayServers.Foreach({
                Add-RDServer -Server $_ -Role "RDS-GATEWAY" -ConnectionBroker $primaryBroker -GatewayExternalFqdn $config.DNSEntry.RDGatewayExternalFqdn
                Write-Verbose "$computerName - $functionName - Remote Desktop Gateway $_ - JOINED."
            })
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

#rewrite this function that it is invoked itself, than invoking commands from the function
function Set-SubsequentRDGatewayPolicy {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Set-SubsequentRDGatewayPolicy",
    
        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        #[System.Collections.ArrayList] $gatewayServers = @()
        #[System.Collections.ArrayList] $sessionHosts = @()
        $startDate = Get-Date
    }
    process {
        try {
            $gatewayServers = $config.RDGateway.Values | sort | out-string -Stream
            $sessionHosts = $config.RDSessionHost.Values | sort | out-string -Stream
            #region Configure GW Policies on RDGatewayServer02
            Invoke-Command -ComputerName ($gatewayServers | select -Skip 1) -ScriptBlock {
                param (
                    [System.Collections.ArrayList] $temp = @()
                )
                #$RDGatewayFarmName = $args[0]
                #$RDGatewayAccessGroup = $args[1]
                #$RDBrokerDNSInternalName = $args[2]
                #$RDBrokerDNSInternalZone = $args[3]
                #$RDSHost01 = $args[4]
                #$RDSHost02 = $args[5]
                #$RDGatewayServer01 = $args[6]
                #$RDGatewayServer02 = $args[7]
                
                Import-Module RemoteDesktopServices
                
                Remove-Item -Path "RDS:\GatewayServer\CAP\RDG_CAP_AllUsers" -Force -recurse
                Remove-Item -Path "RDS:\GatewayServer\RAP\RDG_RDConnectionBrokers" -Force -recurse
                Remove-Item -Path "RDS:\GatewayServer\RAP\RDG_AllDomainComputers" -Force -recurse
                Remove-Item -Path "RDS:\GatewayServer\RAP\RDG_HighAvailabilityBroker_DNS_RR" -Force -recurse
                Remove-Item  -Path "RDS:\GatewayServer\GatewayManagedComputerGroups\RDG_RDCBComputers"-Force -recurse
                Remove-Item  -Path "RDS:\GatewayServer\GatewayManagedComputerGroups\RDG_DNSRoundRobin"-Force -recurse
                
                New-Item -Path "RDS:\GatewayServer\GatewayManagedComputerGroups" -Name $using:config.RDGatewayFarmName -Description $using:config.RDGatewayFarmName -Computers "$($using:config.DNSEntry.RDBrokerDNSInternalName).$($using:config.DNSEntry.RDBrokerDNSInternalZone)" -ItemType "String"
                
                $temp = $using:sessionHosts
                $temp.ForEach({
                    New-Item -Path "RDS:\GatewayServer\GatewayManagedComputerGroups\$($using:config.RDGatewayFarmName)\Computers" -Name $_ -ItemType "String"
                })
                #New-Item -Path "RDS:\GatewayServer\GatewayManagedComputerGroups\$($using:config.RDGatewayFarmName)\Computers" -Name $RDSHost01 -ItemType "String"
                #New-Item -Path "RDS:\GatewayServer\GatewayManagedComputerGroups\$($using:config.RDGatewayFarmName)\Computers" -Name $RDSHost02 -ItemType "String"

                New-Item -Path "RDS:\GatewayServer\RAP" -Name "RDG_RAP_$($using:config.RDGatewayFarmName)" -UserGroups $using:config.ADGroup.RDGatewayAccessGroup -ComputerGroupType 0 -ComputerGroup $using:config.RDGatewayFarmName
                New-Item -Path "RDS:\GatewayServer\CAP" -Name "RDG_CAP_$($using:config.RDGatewayFarmName)" -UserGroups $using:config.ADGroup.RDGatewayAccessGroup -AuthMethod 1

                #not sure if 
                # 1. alias for the connection broker should be added there
                # 2. connection brokers
                # 3. web access servers
                $temp = $using:gatewayServers
                $temp.Foreach({
                    New-Item -Path "RDS:\GatewayServer\GatewayFarm\Servers" -Name $_ -ItemType "String"
                })
                #New-Item -Path "RDS:\GatewayServer\GatewayFarm\Servers" -Name $RDGatewayServer01 -ItemType "String"
                #New-Item -Path "RDS:\GatewayServer\GatewayFarm\Servers" -Name $RDGatewayServer02 -ItemType "String"

            } #-ArgumentList $config.RDGatewayFarmName, $config.RDGatewayAccessGroup, $config.RDBrokerDNSInternalName, $config.RDBrokerDNSInternalZone, $config.RDSHost01, $config.RDSHost02, $config.RDGatewayServer01, $config.RDGatewayServer02
            Write-Verbose "$computerName - $functionName - CAP & RAP Policies on $($gatewayServers.Length) Configuration on Remote Desktop Gateway Servers - DONE."
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
        
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

#rewrite this function that it is invoked itself, than invoking commanads from the funciton
function Remove-FirstRDGatewayPolicy {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Remove-FirstRDGatewayPolicy",

        [Parameter(Mandatory = $true)]
        $config = $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            #region Cleanup Gateway Policies on RDGatewayServer01
            Invoke-Command -ComputerName $config.RDGateway.RDGatewayServer01 -ScriptBlock {
                Import-Module RemoteDesktopServices
                Remove-Item -Path "RDS:\GatewayServer\RAP\RDG_HighAvailabilityBroker_DNS_RR" -Force -recurse
                Remove-Item  -Path "RDS:\GatewayServer\GatewayManagedComputerGroups\RDG_DNSRoundRobin"-Force -recurse
            }
            Write-Verbose "$comuterName - $functionName - Cleanup RAP Policy on: $($config.RDGateway.RDGatewayServer01) - DONE."
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

#rewrite this function that it is invoked itself, than invoking commands from the function
function Expand-FirstRDGatewayFarmSettings {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Expand-FirstRDGatewayFarmSettings",

        [Parameter(Mandatory = $true)]
        $config
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        [System.Collections.ArrayList] $gatewayServers = @()
        $startDate = Get-Date
    }
    process {
        try {
            #region Create Gateway Farm on RDGatewayServer01
            $gatewayServers = $config.RDGateway.Values | sort | out-string -Stream
            Invoke-Command -ComputerName $config.RDGateway.RDGatewayServer01 -ScriptBlock {
                #$RDGatewayServer01 = $args[0]
                #$RDGatewayServer02 = $args[1]
                Import-Module RemoteDesktopServices
                $temp = $using:gatewayServers
                $temp.foreach({
                    New-Item -Path "RDS:\GatewayServer\GatewayFarm\Servers" -Name $_ -ItemType "String"
                })
                #New-Item -Path "RDS:\GatewayServer\GatewayFarm\Servers" -Name $RDGatewayServer01 -ItemType "String"
                #New-Item -Path "RDS:\GatewayServer\GatewayFarm\Servers" -Name $RDGatewayServer02 -ItemType "String"
            } #-ArgumentList $config.RDGatewayServer01, $config.RDGatewayServer02
            Write-Verbose "$computerName - $functionName - Remote Desktop Gateway Server Farm on: $($config.RDGatewayServer01) - DONE."
            #endregion
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}

function Redo-SSLCertificateConfiguration {
    <#
        .SYNOPSIS
        one
        .DESCRIPTION
        two
        .PARAMETER ComputerName
        ComputerName
        .PARAMETER FunctionName
        FunctionName
        .EXAMPLE
        three
        .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
        HelpMessage = "ComputerName where function is run")]
        [ValidateNotNullOrEmpty()]
        [string]$computerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
        HelpMessage = "Name of the function")]
        [ValidateNotNullOrEmpty()]
        [string]$functionName = "Redo-SSLCertificateConfiguration",

        [Parameter(Mandatory = $true)]
        $config,

        [Parameter(Mandatory = $true,
        HelpMessage = "Name of the Primary Remote Desktop Broker")]
        $primaryBroker
    )
    begin {
        $WarningPreference = "Continue"
        $VerbosePreference = "Continue"
        $InformationPreference = "Continue"
        $startDate = Get-Date
    }
    process {
        try {
            #region Set Certificates (need to be applied again, that ConnectioBroker02 is getting the certificates)
            $RDPublishing = ConvertTo-SecureString -String $config.CertificatePassword.RDPublishing -AsPlainText -Force
            $RDRedirector = ConvertTo-SecureString -String $config.CertificatePassword.RDRedirector -AsPlainText -Force
            $RDWebAccess = ConvertTo-SecureString -String $config.CertificatePassword.RDWebAccess -AsPlainText -Force 
            $RDGateway = ConvertTo-SecureString -String $config.CertificatePassword.RDGateway -AsPlainText -Force 
            Set-RDCertificate -Role RDPublishing -ImportPath $config.CertificatePath.RDPublishing -Password $RDPublishing -ConnectionBroker $primaryBroker -Force
            Set-RDCertificate -Role RDRedirector -ImportPath $config.CertificatePath.RDRedirector -Password $RDRedirector -ConnectionBroker $primaryBroker -Force
            Set-RDCertificate -Role RDWebAccess -ImportPath $config.CertificatePath.RDWebAccess -Password $RDWebAccess -ConnectionBroker $primaryBroker -Force
            Set-RDCertificate -Role RDGateway -ImportPath $config.CertificatePath.RDGateway -Password $RDGateway -ConnectionBroker $primaryBroker -Force
            Write-Verbose "$computerName - $functionName - SSL Certificates configuration - DONE."
        }
        catch {
            Write-Error "$computerName - $functionName - Error " $_
        }
    }
    end {
        $endDate = Get-Date
        $x = New-TimeSpan -Start $startDate -End $endDate
        Write-Verbose "$computerName - $functionName - Time taken: $($x.TotalSeconds) seconds"
        $WarningPreference = "SilentlyContinue"
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
    }
}
#endregion
#endregion

#endregion
#endregion

#region WorkFlows
workflow Copy-WindowsKB {
    param (
        $connectionBrokerWinRM,
        $Path,
        $Destination
    )
    foreach -parallel ($session in $connectionBrokerWinRM){
        Copy-Item -Path $Path -Destination $Destination -Force -ToSession $session
    }
}
#endregion