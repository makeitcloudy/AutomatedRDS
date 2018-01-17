@{
	MultiDeployment = "Yes"
	HADeployment = "Yes"
    DomainController = "ctxlab-dc.test.lab"
    RDGatewayFarmName = "Farm1"
    SQLDatabase = "RDSFarm1"
	RDSResourcesPackages = "C:\Resources\Packages\RDS"
#   RDSResourcesPackagesKB = "C:\Resources\Packages\RDS\KB"
#	SQLFilePath2016 = "C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA" #verify this
#	SQLFilePath2014 = "C:\Program Files\Microsoft SQL Server\MSSQL12.MSSQLSERVER\MSSQL\DATA" #verify this
    SQLFilePath = "C:\Program Files\Microsoft SQL Server\MSSQL.MSSQLSERVER\MSSQL\DATA" #\MSSQL.MSSQLSERVER - SQL2014
	SQLNativeClientMsi = "C:\Resources\Packages\RDS\sqlncli.msi"
    SQLNativeClientLog = "C:\Resources\Packages\RDS\sqlncli.log"

    SQLServer = @{
        SQLServer01 = "ctxlab-sql01.test.lab"
    }
    SQLConnectionString = @{
        ServerNativeClient = "SQL Server Native Client 11.0" #11.0 - SQL2012
        TrustedConnection = "Yes"
        APP = "Remote Desktop Services Connection Broker"
    }
    MGMTNode = @{
        MGMTNode01 = "ctxlab-mgmt01.test.lab" #computerName from which the deployment scrpt is run
    }
    RDGateway = @{
	    RDGatewayServer01 = "ctxlab-rdgw01.test.lab"
	    RDGatewayServer02 = "ctxlab-rdgw02.test.lab"
       #RDGatewayServer03 = "ctxlab-rdgw03.test.lab"
    }
    RDWebAccess = @{
	    WebAccessServer01 = "ctxlab-rdwa01.test.lab"
	    WebAccessServer02 = "ctxlab-rdwa02.test.lab"
       #WebAccessServer03 = "ctxlab-rdwa03.test.lab"
    }
    RDConnectionBroker = @{
	    ConnectionBroker01 = "ctxlab-rdcb01.test.lab"
	    ConnectionBroker02 = "ctxlab-rdcb02.test.lab" #it seems that the RDS2012 accept only 2 connection brokers
       #ConnectionBroker03 = "ctxlab-rdcb03.test.lab" #starting RDS2016 there can be more than w connection brokers
    }
    RDSessionHost = @{
        SessionHost01 = "ctxlab-rdsh01.test.lab"
	    SessionHost02 = "ctxlab-rdsh02.test.lab"
       #SessionHost03 = "ctxlab-rdsh03.test.lab"
    }
	
	CertificatePath = @{
        # you can have single wildcard certificate which is applied for all four roles and
        # installed on the Session Host Servers
        # or you may utilize separate certificates (for instance SAN certs) which are used
        # separatelly for each single role
        RDPublishing = "C:\Resources\rds\WildcardRDS.pfx"
        RDRedirector = "C:\Resources\rds\WildcardRDS.pfx"
        RDWebAccess = "C:\Resources\rds\WildcardRDS.pfx"
        RDGateway = "C:\Resources\rds\WildcardRDS.pfx"
    }
    CertificatePassword = @{
        # each certificate can have different password
        # replace it with the prompt for password inside the code
        RDPublishing = "Password1!" 
        RDRedirector = "Password1!"
        RDWebAccess  = "Password1!"
        RDGateway    = "Password1!"
    }
    License = @{
        LICserver = "ctxlab-rdlic01.test.lab"
        LICmode = "PerUser"
    }
    KB = @{
        KB4053579 = "KB4053579.msu"
    }
    URL = @{
        MachineKeysUrl = "https://gallery.technet.microsoft.com/Get-and-Set-the-machineKeys-9a1e7b77/file/122500/1/Configure-MachineKeys.ps1"
        SQLNativeClientUrl = "https://download.microsoft.com/download/B/E/D/BED73AAC-3C8A-43F5-AF4F-EB4FEA6C8F3A/1033/amd64/sqlncli.msi"
        KB4053579 = "http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/12/windows10.0-kb4053579-x64_c8f23cbaf60b5093a6902ce64520c354cfe360c7.msu" #ConnectionBrokers fix to setup HA
    }
    ADGroup = @{
        RDConnectionBrokersGroup = "RDSConnectionBrokers"
        RDAccessGroup = "SG_RDP_Internal_Access@test.lab"
	    RDGatewayAccessGroup = "SG_RDP_External_Access@test.lab"
    }
    DNSEntry = @{
        RDGatewayExternalFqdn = "gateway.tru.io"
	    RDWebAccessDNSInternalName = "remoteaccess"
	    RDWebAccessDNSInternalZone = "test.lab"
	    RDBrokerDNSInternalName = "rdcb"
	    RDBrokerDNSInternalZone = "test.lab"
    }

    RDCollection01 = @{
        DesktopCollectionName = "RDS Lab"
	    DesktopDescription = "Test Deployment with PowerShell"
        ProfileDiskPath = "\\ctxlab-smb01\SharedFolder1"
	    ProfileDiskSize = "2" #GB
    }
    Profile = @{
        
    }
}
