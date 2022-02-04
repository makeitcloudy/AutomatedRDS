@{
    MultiDeployment = "Yes"
    DomainController = "ctxlab-dc.test.lab"
    RDGatewayFarmName = "Farm1"

    MGMTNode = @{
        MGMTNode01 = "ctxlab-mgmt01.test.lab" #computerName from which the deployment script is run
    }
    RDGateway = @{
        GatewayServer01 = "ctxlab-rdgw01.test.lab"
    }
    RDWebAccess = @{
        WebAccessServer01 = "ctxlab-rdwa01.test.lab"
    }
    RDConnectionBroker = @{
        ConnectionBroker01 = "ctxlab-rdcb01.test.lab"
       #ConnectionBroker02 = "ctxlab-rdcb02.test.lab"
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
        RDWebAccess  = "C:\Resources\rds\WildcardRDS.pfx"
        RDGateway    = "C:\Resources\rds\WildcardRDS.pfx"
    }
    CertificatePassword = @{
        # each certificate can have different password
        # replace it with the prompt for password inside the code
        RDPublishing = "Password1!" 
        RDRedirector = "Password1!"
        RDWebAccess  = "Password1!"
        RDGateway    = "Password1!"
    }
    #Certificate = @{
    #    CertPath = "C:\Resources\rds\WildcardRDS.pfx"
	#    CertPassword = "Password1!" #replace it with the prompt inside the code
    #}
	License = @{
        LicServer01 = "ctxlab-rdlic01.test.lab"
       #LicServer02 = "ctxlab-rdlic02.test.lab"
        LicMode = "PerUser"
    }
	URL = @{
        RDPublishedNameUrl = "https://gallery.technet.microsoft.com/Change-published-FQDN-for-2a029b80/file/103829/2/Set-RDPublishedName.ps1"
    }
	ADGroup = @{
        RDAccessGroup = "RDSFullAdmins@test.lab" #AD Group which will have access to the RDCollection
        RDGatewayAccessGroup = "RDSFullAdmins@test.lab" #AD Group which will be configured on the RD Gateway
    }
    DNSEntry = @{
        RDGatewayExternalFqdn = "gateway.ath.cx"
        RDWebAccessDNSInternalName = "remoteaccess"
        RDWebAccessDNSInternalZone = "test.lab"
        RDBrokerDNSInternalName = "rdcb"
        RDBrokerDNSInternalZone = "test.lab"
    }

    RDCollection01 = @{
        DesktopCollectionName = "RDS Lab"
	    DesktopDiscription = "Test Deployment with PowerShell"
        ProfileDiskPath = "\\ctxlab-smb01\SharedFolder1"
        ProfileDiskSize = "2" #GB
    }
   #RDCollection02 = @{
   #    DesktopCollectionName = "RDS Lab - Collection 02"
   #    DesktopDiscription = "Test Deployment with PowerShell"
   #    ProfileDiskPath = "\\ctxlab-smb01\SharedFolder1"
   #    ProfileDiskSize = "2" #GB
   #}

    Profile = @{
        
    }
}
