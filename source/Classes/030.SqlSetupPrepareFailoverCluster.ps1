<#
    .SYNOPSIS
        The SqlSetupPrepatreFailover cluster perfoms the PrepareFailoverCluster activity using the SQL setup.exe.

    .DESCRIPTION
        The SqlSetupPrepatreFailover cluster perfoms the PrepareFailoverCluster activity using the SQL setup.exe.

    .PARAMETER InstanceName
        The name of the _SQL Server_ instance to be configured. Default value is
        `'MSSQLSERVER'`.

    .EXAMPLE
        Invoke-DscResource -ModuleName SqlServerDsc -Name SqlPermission -Method Get -Property @{
            ServerName           = 'localhost'
            InstanceName         = 'SQL2017'
            Credential           = (Get-Credential -UserName 'myuser@company.local' -Message 'Password:')
            Name                 = 'INSTANCE\SqlUser'
            Permission           = [Microsoft.Management.Infrastructure.CimInstance[]] @(
                (
                    New-CimInstance -ClientOnly -Namespace root/Microsoft/Windows/DesiredStateConfiguration -ClassName ServerPermission -Property @{
                            State = 'Grant'
                            Permission = @('select')
                    }
                )
                (
                    New-CimInstance -ClientOnly -Namespace root/Microsoft/Windows/DesiredStateConfiguration -ClassName ServerPermission -Property @{
                        State = 'GrantWithGrant'
                        Permission = [System.String[]] @()
                    }
                )
                (
                    New-CimInstance -ClientOnly -Namespace root/Microsoft/Windows/DesiredStateConfiguration -ClassName ServerPermission -Property @{
                        State = 'Deny'
                        Permission = [System.String[]] @()
                    }
                )
            )
        }

        This example shows how to call the resource using Invoke-DscResource.

#>

[DscResource(RunAsCredential = 'NotSupported')]
class SqlSetupPrepareFailoverCluster : SqlSetupBase
{
    [DscProperty()]
    [System.String]
    $SourcePath

    [DscProperty()]
    [System.Management.Automation.PSCredential]
    $SourceCredential

    [DscProperty()]
    [ValidateSet(
        'SQL', 'SQLEngine', 'Replication', 'FullText', 'DQ', 'PolyBase',
        'PolyBaseCore', 'PolyBaseJava', 'AdvancedAnalytics', 'SQL_INST_MR',
        'SQL_INST_MPY', 'SQL_INST_JAVA', 'AS', 'RS', 'RS_SHP', 'RS_SHPWFE',
        'DQC', 'IS', 'IS_Master', 'IS_Worker', 'MDS', 'SQL_SHARED_MPY',
        'SQL_SHARED_MR', 'Tools', 'BC', 'Conn', 'DREPLAY_CTLR',
        'DREPLAY_CLT', 'SNAC_SDK', 'SDK', 'LocalDB'
    )]
    [System.String]
    $Features

    [DscProperty()]
    [System.String]
    $InstanceDir

    [DscProperty()]
    [System.String]
    $InstanceID

    [DscProperty(Mandatory)]
    [System.String]
    $InstanceName

    [DscProperty()]
    [System.String]
    $UpdateEnabled

    [DscProperty()]
    [System.String]
    $UpdateSource

    [DscProperty()]
    [System.String]
    $InstallSharedDir

    [DscProperty()]
    [System.String]
    $InstallSharedWOWDir

    [DscProperty()]
    [System.Management.Automation.PSCredential]
    $SQLSvcAccount

    [DscProperty()]
    [System.Management.Automation.PSCredential]
    $AgtSvcAccount

    [DscProperty()]
    [System.Management.Automation.PSCredential]
    $FTSvcAccount

    [DscProperty()]
    [System.Management.Automation.PSCredential]
    $RSSvcAccount

    [DscProperty()]
    [ValidateSet('SharePointFilesOnlyMode', 'DefaultNativeMode', 'FilesOnlyMode')]
    [System.String]
    $RSInstallMode

    [DscProperty()]
    [System.Management.Automation.PSCredential]
    $ASSvcAccount

    [DscProperty()]
    [System.Management.Automation.PSCredential]
    $ISSvcAccount

    [DscProperty()]
    [System.Boolean]
    $UseEnglish

    SqlSetupPrepareFailoverCluster() : base ()
    {
        $this.Action = "PrepareFailoverCluster"
    }

    [SqlSetupPrepareFailoverCluster] Get()
    {
        # Call the base method to return the properties.
        return ([SqlSetupBase] $this).Get()
    }

    [System.Boolean] Test()
    {
        # Call the base method to test all of the properties that should be enforced.
        return ([SqlSetupBase] $this).Test()
    }

    [void] Set()
    {
        # Call the base method to enforce the properties.
        ([SqlSetupBase] $this).Set()
    }
}
