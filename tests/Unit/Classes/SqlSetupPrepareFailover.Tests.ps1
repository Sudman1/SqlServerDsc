<#
    .SYNOPSIS
        Unit test for SqlSetupPrepareFailoverCluster DSC resource.
#>

# Suppressing this rule because Script Analyzer does not understand Pester's syntax.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
param ()

BeforeDiscovery {
    try
    {
        if (-not (Get-Module -Name 'DscResource.Test'))
        {
            # Assumes dependencies has been resolved, so if this module is not available, run 'noop' task.
            if (-not (Get-Module -Name 'DscResource.Test' -ListAvailable))
            {
                # Redirect all streams to $null, except the error stream (stream 2)
                & "$PSScriptRoot/../../build.ps1" -Tasks 'noop' 2>&1 4>&1 5>&1 6>&1 > $null
            }

            # If the dependencies has not been resolved, this will throw an error.
            Import-Module -Name 'DscResource.Test' -Force -ErrorAction 'Stop'
        }
    }
    catch [System.IO.FileNotFoundException]
    {
        throw 'DscResource.Test module dependency not found. Please run ".\build.ps1 -ResolveDependency -Tasks build" first.'
    }
}

BeforeAll {
    $script:dscModuleName = 'SqlServerDscX'

    Import-Module -Name $script:dscModuleName

    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '../../TestHelpers/CommonTestHelper.psm1')

    # Loading mocked classes
    Add-Type -Path (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '../Stubs') -ChildPath 'SMO.cs')

    # Load the correct SQL Module stub
    $script:stubModuleName = Import-SQLModuleStub -PassThru

    $PSDefaultParameterValues['InModuleScope:ModuleName'] = $script:dscModuleName
    $PSDefaultParameterValues['Mock:ModuleName'] = $script:dscModuleName
    $PSDefaultParameterValues['Should:ModuleName'] = $script:dscModuleName
}

AfterAll {
    $PSDefaultParameterValues.Remove('InModuleScope:ModuleName')
    $PSDefaultParameterValues.Remove('Mock:ModuleName')
    $PSDefaultParameterValues.Remove('Should:ModuleName')

    # Unload the module being tested so that it doesn't impact any other tests.
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force

    # Unload the stub module.
    Remove-SqlModuleStub -Name $script:stubModuleName

    # Remove module common test helper.
    Get-Module -Name 'CommonTestHelper' -All | Remove-Module -Force
}

Describe 'SqlSetupPrepareFailoverCluster' {
    Context 'When class is instantiated' {
        It 'Should not throw an exception' {
            InModuleScope -ScriptBlock {
                { [SqlSetupPrepareFailoverCluster]::new() } | Should -Not -Throw
            }
        }

        It 'Should have a default or empty constructor' {
            InModuleScope -ScriptBlock {
                $instance = [SqlSetupPrepareFailoverCluster]::new()
                $instance | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should be the correct type' {
            InModuleScope -ScriptBlock {
                $instance = [SqlSetupPrepareFailoverCluster]::new()
                $instance.GetType().Name | Should -Be 'SqlSetupPrepareFailoverCluster'
            }
        }
    }
}

Describe 'SqlSetupPrepareFailoverCluster\Get()' -Tag 'Get' {
    Context 'When the system is in the desired state' {
        Context 'When the desired settings are applied' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockCredential = [pscredential]::new('mockUser', (ConvertTo-SecureString -String 'mock' -Force -AsPlainText))
                    $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                        SourcePath          = 'C:\this\is\a\mocked\path\'
                        SourceCredential    = $script:mockCredential
                        Features            = @(
                            'SQL', 'SQLEngine', 'Replication', 'FullText', 'DQ', 'PolyBase',
                            'PolyBaseCore', 'PolyBaseJava', 'AdvancedAnalytics', 'SQL_INST_MR',
                            'SQL_INST_MPY', 'SQL_INST_JAVA', 'AS', 'RS', 'RS_SHP', 'RS_SHPWFE',
                            'DQC', 'IS', 'IS_Master', 'IS_Worker', 'MDS', 'SQL_SHARED_MPY',
                            'SQL_SHARED_MR', 'Tools', 'BC', 'Conn', 'DREPLAY_CTLR',
                            'DREPLAY_CLT', 'SNAC_SDK', 'SDK', 'LocalDB'
                        )
                        InstanceDir         = 'c:\mock'
                        InstanceID          = 'mock'
                        InstanceName        = 'mock'
                        UpdateEnabled       = $false
                        UpdateSource        = 'MU'
                        InstallSharedDir    = 'c:\mock'
                        InstallSharedWOWDir = 'c:\mock'
                        SQLSvcAccount       = $script:mockCredential
                        AgtSvcAccount       = $script:mockCredential
                        FTSvcAccount        = $script:mockCredential
                        RSSvcAccount        = $script:mockCredential
                        RSInstallMode       = 'DefaultNativeMode'
                        ASSvcAccount        = $script:mockCredential
                        ISSvcAccount        = $script:mockCredential
                        UseEnglish          = $true
                    }

                    <#
                        This mocks the method GetCurrentState().

                        Method Get() will call the base method Get() which will
                        call back to the derived class method GetCurrentState()
                        to get the result to return from the derived method Get().
                    #>
                    $script:mockSqlSetupPrepareFailoverClusterInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                Action                     = 'PrepareFailoverCluster'
                                SourcePath                 = 'c:\this\is\a\mocked\path\'
                                SourceCredential           = $script:mockCredential
                                InstanceName               = 'mock'
                                RSInstallMode              = 'DefaultNativeMode'
                                FeatureFlag                = $null
                                FailoverClusterNetworkName = $null
                                Features                   = @(
                                    'SQL', 'SQLEngine', 'Replication', 'FullText', 'DQ', 'PolyBase',
                                    'PolyBaseCore', 'PolyBaseJava', 'AdvancedAnalytics', 'SQL_INST_MR',
                                    'SQL_INST_MPY', 'SQL_INST_JAVA', 'AS', 'RS', 'RS_SHP', 'RS_SHPWFE',
                                    'DQC', 'IS', 'IS_Master', 'IS_Worker', 'MDS', 'SQL_SHARED_MPY',
                                    'SQL_SHARED_MR', 'Tools', 'BC', 'Conn', 'DREPLAY_CTLR',
                                    'DREPLAY_CLT', 'SNAC_SDK', 'SDK', 'LocalDB'
                                )
                                InstanceID                 = 'mock'
                                InstallSharedDir           = 'c:\mock'
                                InstallSharedWOWDir        = 'c:\mock'
                                InstanceDir                = 'c:\mock'
                                UpdateEnabled              = $false
                                UpdateSource               = 'MU'
                                SQLSvcAccountUsername      = 'mockUser'
                                SqlSvcStartupType          = $null
                                AgtSvcAccountUsername      = 'mockUser'
                                AgtSvcStartupType          = $null
                                SQLCollation               = $null
                                SQLSysAdminAccounts        = $null
                                SecurityMode               = $null
                                InstallSQLDataDir          = $null
                                SQLUserDBDir               = $null
                                SQLUserDBLogDir            = $null
                                SQLTempDBDir               = $null
                                SQLTempDBLogDir            = $null
                                SqlTempdbFileCount         = $null
                                SqlTempdbFileSize          = $null
                                SqlTempdbFileGrowth        = $null
                                SqlTempdbLogFileSize       = $null
                                SqlTempdbLogFileGrowth     = $null
                                SQLBackupDir               = $null
                                FTSvcAccountUsername       = 'mockUser'
                                RSSvcAccountUsername       = 'mockUser'
                                RsSvcStartupType           = $null
                                ASSvcAccountUsername       = 'mockUser'
                                AsSvcStartupType           = $null
                                ASCollation                = $null
                                ASSysAdminAccounts         = $null
                                ASDataDir                  = $null
                                ASLogDir                   = $null
                                ASBackupDir                = $null
                                ASTempDir                  = $null
                                ASConfigDir                = $null
                                ASServerMode               = $null
                                ISSvcAccountUsername       = 'mockUser'
                                IsSvcStartupType           = $null
                                FailoverClusterGroupName   = $null
                                FailoverClusterIPAddress   = $null
                                UseEnglish                 = $true
                            }
                        }
                }
            }

            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockSqlSetupPrepareFailoverClusterInstance.Get()

                    $currentState | Convertto-JSON | Write-Verbose -Verbose

                    $currentState.SourcePath | Should -Be 'C:\this\is\a\mocked\path\'
                    $currentState.SourceCredential.UserName | Should -Be $script:mockCredential.UserName
                    ($currentState.Features | Sort-Object) | Should -Be (@(
                            'SQL', 'SQLEngine', 'Replication', 'FullText', 'DQ', 'PolyBase',
                            'PolyBaseCore', 'PolyBaseJava', 'AdvancedAnalytics', 'SQL_INST_MR',
                            'SQL_INST_MPY', 'SQL_INST_JAVA', 'AS', 'RS', 'RS_SHP', 'RS_SHPWFE',
                            'DQC', 'IS', 'IS_Master', 'IS_Worker', 'MDS', 'SQL_SHARED_MPY',
                            'SQL_SHARED_MR', 'Tools', 'BC', 'Conn', 'DREPLAY_CTLR',
                            'DREPLAY_CLT', 'SNAC_SDK', 'SDK', 'LocalDB'
                        ) | Sort-Object)
                    $currentState.InstanceDir | Should -Be 'c:\mock'
                    $currentState.InstanceID | Should -Be 'mock'
                    $currentState.InstanceName | Should -Be 'mock'
                    $currentState.UpdateEnabled | Should -BeFalse
                    $currentState.UpdateSource | Should -Be 'MU'
                    $currentState.InstallSharedDir | Should -Be 'c:\mock'
                    $currentState.InstallSharedWOWDir | Should -Be 'c:\mock'
                    $currentState.SQLSvcAccount.UserName | Should -Be $script:mockCredential.UserName
                    $currentState.AgtSvcAccount.UserName | Should -Be $script:mockCredential.UserName
                    $currentState.FTSvcAccount.UserName | Should -Be $script:mockCredential.UserName
                    $currentState.RSSvcAccount.UserName | Should -Be $script:mockCredential.UserName
                    $currentState.RSInstallMode | Should -Be 'DefaultNativeMode'
                    $currentState.ASSvcAccount.UserName | Should -Be $script:mockCredential.UserName
                    $currentState.ISSvcAccount.UserName | Should -Be $script:mockCredential.UserName
                    $currentState.UseEnglish | Should -BeTrue
                }
            }
        }
    }

    Context 'When the system is not in the desired state' {
        Context 'When the desired permission exist' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                        SourcePath          = 'C:\this\is\a\mocked\path\'
                        SourceCredential    = $script:mockCredential
                        Features            = @(
                            'SQL', 'SQLEngine', 'Replication', 'FullText', 'DQ', 'PolyBase',
                            'PolyBaseCore', 'PolyBaseJava', 'AdvancedAnalytics', 'SQL_INST_MR',
                            'SQL_INST_MPY', 'SQL_INST_JAVA', 'AS', 'RS', 'RS_SHP', 'RS_SHPWFE',
                            'DQC', 'IS', 'IS_Master', 'IS_Worker', 'MDS', 'SQL_SHARED_MPY',
                            'SQL_SHARED_MR', 'Tools', 'BC', 'Conn', 'DREPLAY_CTLR',
                            'DREPLAY_CLT', 'SNAC_SDK', 'SDK', 'LocalDB'
                        )
                        InstanceDir         = 'c:\mock'
                        InstanceID          = 'mock'
                        InstanceName        = 'mock'
                        UpdateEnabled       = $false
                        UpdateSource        = 'MU'
                        InstallSharedDir    = 'c:\mock'
                        InstallSharedWOWDir = 'c:\mock'
                        SQLSvcAccount       = $script:mockCredential
                        AgtSvcAccount       = $script:mockCredential
                        FTSvcAccount        = $script:mockCredential
                        RSSvcAccount        = $script:mockCredential
                        RSInstallMode       = 'DefaultNativeMode'
                        ASSvcAccount        = $script:mockCredential
                        ISSvcAccount        = $script:mockCredential
                        UseEnglish          = $true
                    }

                    <#
                        This mocks the method GetCurrentState().

                        Method Get() will call the base method Get() which will
                        call back to the derived class method GetCurrentState()
                        to get the result to return from the derived method Get().
                    #>
                    $script:mockSqlSetupPrepareFailoverClusterInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                Action                     = 'PrepareFailoverCluster'
                                SourcePath                 = 'c:\this\is\a\mocked\path\'
                                SourceCredential           = $script:mockCredential
                                InstanceName               = 'mock2'
                                RSInstallMode              = 'DefaultNativeMode'
                                FeatureFlag                = $null
                                FailoverClusterNetworkName = $null
                                Features                   = @(
                                    'SQL', 'SQLEngine', 'Replication', 'FullText', 'DQ', 'PolyBase',
                                    'PolyBaseCore', 'PolyBaseJava', 'AdvancedAnalytics', 'SQL_INST_MR',
                                    'SQL_INST_MPY', 'SQL_INST_JAVA', 'AS', 'RS', 'RS_SHP', 'RS_SHPWFE',
                                    'DQC', 'IS', 'IS_Master', 'IS_Worker', 'MDS', 'SQL_SHARED_MPY',
                                    'SQL_SHARED_MR', 'Tools', 'BC', 'Conn', 'DREPLAY_CTLR',
                                    'DREPLAY_CLT', 'SNAC_SDK', 'SDK', 'LocalDB'
                                )
                                InstanceID                 = 'mock2'
                                InstallSharedDir           = 'c:\mock'
                                InstallSharedWOWDir        = 'c:\mock'
                                InstanceDir                = 'c:\mock'
                                SQLSvcAccountUsername      = 'mockUser'
                                SqlSvcStartupType          = $null
                                AgtSvcAccountUsername      = 'mockUser'
                                AgtSvcStartupType          = $null
                                SQLCollation               = $null
                                SQLSysAdminAccounts        = $null
                                SecurityMode               = $null
                                InstallSQLDataDir          = $null
                                SQLUserDBDir               = $null
                                SQLUserDBLogDir            = $null
                                SQLTempDBDir               = $null
                                SQLTempDBLogDir            = $null
                                SqlTempdbFileCount         = $null
                                SqlTempdbFileSize          = $null
                                SqlTempdbFileGrowth        = $null
                                SqlTempdbLogFileSize       = $null
                                SqlTempdbLogFileGrowth     = $null
                                SQLBackupDir               = $null
                                FTSvcAccountUsername       = 'mockUser'
                                RSSvcAccountUsername       = 'mockUser'
                                RsSvcStartupType           = $null
                                ASSvcAccountUsername       = 'mockUser'
                                AsSvcStartupType           = $null
                                ASCollation                = $null
                                ASSysAdminAccounts         = $null
                                ASDataDir                  = $null
                                ASLogDir                   = $null
                                ASBackupDir                = $null
                                ASTempDir                  = $null
                                ASConfigDir                = $null
                                ASServerMode               = $null
                                ISSvcAccountUsername       = 'mockUser'
                                IsSvcStartupType           = $null
                                FailoverClusterGroupName   = $null
                                FailoverClusterIPAddress   = $null
                                UseEnglish                 = $true
                            }
                        }
                }
            }

            It 'Should return the correct values' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockSqlSetupPrepareFailoverClusterInstance.Get()

                    $currentState | ConvertTo-Json | Write-Verbose -Verbose

                    $currentState.SourcePath | Should -Be 'C:\this\is\a\mocked\path\'
                    $currentState.SourceCredential.UserName | Should -Be $script:mockCredential.UserName
                    ($currentState.Features | Sort-Object) | Should -Be (@(
                            'SQL', 'SQLEngine', 'Replication', 'FullText', 'DQ', 'PolyBase',
                            'PolyBaseCore', 'PolyBaseJava', 'AdvancedAnalytics', 'SQL_INST_MR',
                            'SQL_INST_MPY', 'SQL_INST_JAVA', 'AS', 'RS', 'RS_SHP', 'RS_SHPWFE',
                            'DQC', 'IS', 'IS_Master', 'IS_Worker', 'MDS', 'SQL_SHARED_MPY',
                            'SQL_SHARED_MR', 'Tools', 'BC', 'Conn', 'DREPLAY_CTLR',
                            'DREPLAY_CLT', 'SNAC_SDK', 'SDK', 'LocalDB'
                        ) | Sort-Object)
                    $currentState.InstanceDir | Should -Be 'c:\mock'
                    $currentState.InstanceID | Should -Be 'mock2'
                    $currentState.InstanceName | Should -Be 'mock2'
                    $currentState.UpdateEnabled | Should -BeFalse
                    $currentState.UpdateSource | Should -Be 'MU'
                    $currentState.InstallSharedDir | Should -Be 'c:\mock'
                    $currentState.InstallSharedWOWDir | Should -Be 'c:\mock'
                    $currentState.SQLSvcAccount.UserName | Should -Be $script:mockCredential.UserName
                    $currentState.AgtSvcAccount.UserName | Should -Be $script:mockCredential.UserName
                    $currentState.FTSvcAccount.UserName | Should -Be $script:mockCredential.UserName
                    $currentState.RSSvcAccount.UserName | Should -Be $script:mockCredential.UserName
                    $currentState.RSInstallMode | Should -Be 'DefaultNativeMode'
                    $currentState.ASSvcAccount.UserName | Should -Be $script:mockCredential.UserName
                    $currentState.ISSvcAccount.UserName | Should -Be $script:mockCredential.UserName
                    $currentState.UseEnglish | Should -BeTrue

                    $currentState.Reasons | Should -HaveCount 2
                }
            }
        }
    }
}
<#
Describe 'SqlSetupPrepareFailoverCluster\GetCurrentState()' -Tag 'GetCurrentState' {
    Context 'When there are no permission in the current state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                    Name         = 'MockUserName'
                    DatabaseName = 'MockDatabaseName'
                    InstanceName = 'NamedInstance'
                }
            }

            Mock -CommandName Connect-SqlDscDatabaseEngine -MockWith {
                return New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.Server'
            }

            Mock -CommandName Get-SqlDscDatabasePermission
        }

        It 'Should return empty collections for each state' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockSqlSetupPrepareFailoverClusterInstance.GetCurrentState(@{
                        Name         = 'MockUserName'
                        DatabaseName = 'MockDatabaseName'
                        InstanceName = 'NamedInstance'
                    })

                $currentState.Credential | Should -BeNullOrEmpty

                $currentState.Permission.GetType().FullName | Should -Be 'DatabasePermission[]'
                $currentState.Permission | Should -HaveCount 3

                $grantState = $currentState.Permission.Where({ $_.State -eq 'Grant' })

                $grantState | Should -Not -BeNullOrEmpty
                $grantState.State | Should -Be 'Grant'
                $grantState.Permission | Should -BeNullOrEmpty

                $grantWithGrantState = $currentState.Permission.Where({ $_.State -eq 'GrantWithGrant' })

                $grantWithGrantState | Should -Not -BeNullOrEmpty
                $grantWithGrantState.State | Should -Be 'GrantWithGrant'
                $grantWithGrantState.Permission | Should -BeNullOrEmpty

                $denyState = $currentState.Permission.Where({ $_.State -eq 'Deny' })

                $denyState | Should -Not -BeNullOrEmpty
                $denyState.State | Should -Be 'Deny'
                $denyState.Permission | Should -BeNullOrEmpty
            }
        }

        Context 'When using property Credential' {
            It 'Should return empty collections for each state' {
                InModuleScope -ScriptBlock {
                    $script:mockSqlSetupPrepareFailoverClusterInstance.Credential = [System.Management.Automation.PSCredential]::new(
                        'MyCredentialUserName',
                        [SecureString]::new()
                    )

                    $currentState = $script:mockSqlSetupPrepareFailoverClusterInstance.GetCurrentState(@{
                            Name         = 'MockUserName'
                            DatabaseName = 'MockDatabaseName'
                            InstanceName = 'NamedInstance'
                        })

                    $currentState.Credential | Should -BeOfType [System.Management.Automation.PSCredential]

                    $currentState.Credential.UserName | Should -Be 'MyCredentialUserName'

                    $currentState.Permission.GetType().FullName | Should -Be 'DatabasePermission[]'
                    $currentState.Permission | Should -HaveCount 3

                    $grantState = $currentState.Permission.Where({ $_.State -eq 'Grant' })

                    $grantState | Should -Not -BeNullOrEmpty
                    $grantState.State | Should -Be 'Grant'
                    $grantState.Permission | Should -BeNullOrEmpty

                    $grantWithGrantState = $currentState.Permission.Where({ $_.State -eq 'GrantWithGrant' })

                    $grantWithGrantState | Should -Not -BeNullOrEmpty
                    $grantWithGrantState.State | Should -Be 'GrantWithGrant'
                    $grantWithGrantState.Permission | Should -BeNullOrEmpty

                    $denyState = $currentState.Permission.Where({ $_.State -eq 'Deny' })

                    $denyState | Should -Not -BeNullOrEmpty
                    $denyState.State | Should -Be 'Deny'
                    $denyState.Permission | Should -BeNullOrEmpty
                }
            }
        }
    }

    Context 'When there are permissions for only state Grant' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                    Name         = 'MockUserName'
                    DatabaseName = 'MockDatabaseName'
                    InstanceName = 'NamedInstance'
                }
            }

            Mock -CommandName Connect-SqlDscDatabaseEngine -MockWith {
                return New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.Server'
            }

            Mock -CommandName Get-SqlDscDatabasePermission -MockWith {
                [Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo[]] $mockDatabasePermissionInfoCollection = @()

                $mockDatabasePermissionSet1 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionSet'
                $mockDatabasePermissionSet1.Connect = $true

                $mockDatabasePermissionInfo1 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo'
                $mockDatabasePermissionInfo1.PermissionState = 'Grant'
                $mockDatabasePermissionInfo1.PermissionType = $mockDatabasePermissionSet1

                $mockDatabasePermissionInfoCollection += $mockDatabasePermissionInfo1

                $mockDatabasePermissionSet2 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionSet'
                $mockDatabasePermissionSet2.Update = $true

                $mockDatabasePermissionInfo2 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo'
                $mockDatabasePermissionInfo2.PermissionState = 'Grant'
                $mockDatabasePermissionInfo2.PermissionType = $mockDatabasePermissionSet2

                $mockDatabasePermissionInfoCollection += $mockDatabasePermissionInfo2

                return $mockDatabasePermissionInfoCollection
            }
        }

        It 'Should return correct values for state Grant and empty collections for the two other states' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockSqlSetupPrepareFailoverClusterInstance.GetCurrentState(@{
                        Name         = 'MockUserName'
                        DatabaseName = 'MockDatabaseName'
                        InstanceName = 'NamedInstance'
                    })

                $currentState.Credential | Should -BeNullOrEmpty

                $currentState.Permission.GetType().FullName | Should -Be 'DatabasePermission[]'
                $currentState.Permission | Should -HaveCount 3

                $grantState = $currentState.Permission.Where({ $_.State -eq 'Grant' })

                $grantState | Should -Not -BeNullOrEmpty
                $grantState.State | Should -Be 'Grant'
                $grantState.Permission | Should -HaveCount 2
                $grantState.Permission | Should -Contain 'Connect'
                $grantState.Permission | Should -Contain 'Update'

                $grantWithGrantState = $currentState.Permission.Where({ $_.State -eq 'GrantWithGrant' })

                $grantWithGrantState | Should -Not -BeNullOrEmpty
                $grantWithGrantState.State | Should -Be 'GrantWithGrant'
                $grantWithGrantState.Permission | Should -BeNullOrEmpty

                $denyState = $currentState.Permission.Where({ $_.State -eq 'Deny' })

                $denyState | Should -Not -BeNullOrEmpty
                $denyState.State | Should -Be 'Deny'
                $denyState.Permission | Should -BeNullOrEmpty
            }
        }
    }

    Context 'When there are permissions for both state Grant and Deny' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                    Name         = 'MockUserName'
                    DatabaseName = 'MockDatabaseName'
                    InstanceName = 'NamedInstance'
                }
            }

            Mock -CommandName Connect-SqlDscDatabaseEngine -MockWith {
                return New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.Server'
            }

            Mock -CommandName Get-SqlDscDatabasePermission -MockWith {
                [Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo[]] $mockDatabasePermissionInfoCollection = @()

                $mockDatabasePermissionSet1 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionSet'
                $mockDatabasePermissionSet1.Connect = $true
                $mockDatabasePermissionSet1.Update = $true

                $mockDatabasePermissionInfo1 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo'
                $mockDatabasePermissionInfo1.PermissionState = 'Grant'
                $mockDatabasePermissionInfo1.PermissionType = $mockDatabasePermissionSet1

                $mockDatabasePermissionInfoCollection += $mockDatabasePermissionInfo1

                $mockDatabasePermissionSet2 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionSet'
                $mockDatabasePermissionSet2.Select = $true

                $mockDatabasePermissionInfo2 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo'
                $mockDatabasePermissionInfo2.PermissionState = 'Deny'
                $mockDatabasePermissionInfo2.PermissionType = $mockDatabasePermissionSet2

                $mockDatabasePermissionInfoCollection += $mockDatabasePermissionInfo2

                return $mockDatabasePermissionInfoCollection
            }
        }

        It 'Should return correct values for the states Grant and Deny and empty collections for the state GrantWithGrant' {
            InModuleScope -ScriptBlock {
                $currentState = $script:mockSqlSetupPrepareFailoverClusterInstance.GetCurrentState(@{
                        Name         = 'MockUserName'
                        DatabaseName = 'MockDatabaseName'
                        InstanceName = 'NamedInstance'
                    })

                $currentState.Credential | Should -BeNullOrEmpty

                $currentState.Permission.GetType().FullName | Should -Be 'DatabasePermission[]'
                $currentState.Permission | Should -HaveCount 3

                $grantState = $currentState.Permission.Where({ $_.State -eq 'Grant' })

                $grantState | Should -Not -BeNullOrEmpty
                $grantState.State | Should -Be 'Grant'
                $grantState.Permission | Should -Contain 'Connect'
                $grantState.Permission | Should -Contain 'Update'

                $grantWithGrantState = $currentState.Permission.Where({ $_.State -eq 'GrantWithGrant' })

                $grantWithGrantState | Should -Not -BeNullOrEmpty
                $grantWithGrantState.State | Should -Be 'GrantWithGrant'
                $grantWithGrantState.Permission | Should -BeNullOrEmpty

                $denyState = $currentState.Permission.Where({ $_.State -eq 'Deny' })

                $denyState | Should -Not -BeNullOrEmpty
                $denyState.State | Should -Be 'Deny'
                $denyState.Permission | Should -Contain 'Select'
            }
        }
    }

    Context 'When using parameter PermissionToInclude' {
        Context 'When the system is in the desired state' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                        Name                = 'MockUserName'
                        DatabaseName        = 'MockDatabaseName'
                        InstanceName        = 'NamedInstance'
                        PermissionToInclude = [DatabasePermission] @{
                            State      = 'Grant'
                            Permission = 'update'
                        }
                    }
                }

                Mock -CommandName Connect-SqlDscDatabaseEngine -MockWith {
                    return New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.Server'
                }

                Mock -CommandName Get-SqlDscDatabasePermission -MockWith {
                    [Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo[]] $mockDatabasePermissionInfoCollection = @()

                    $mockDatabasePermissionSet1 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionSet'
                    $mockDatabasePermissionSet1.Connect = $true
                    $mockDatabasePermissionSet1.Update = $true

                    $mockDatabasePermissionInfo1 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo'
                    $mockDatabasePermissionInfo1.PermissionState = 'Grant'
                    $mockDatabasePermissionInfo1.PermissionType = $mockDatabasePermissionSet1

                    $mockDatabasePermissionInfoCollection += $mockDatabasePermissionInfo1

                    $mockDatabasePermissionSet2 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionSet'
                    $mockDatabasePermissionSet2.Select = $true

                    $mockDatabasePermissionInfo2 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo'
                    $mockDatabasePermissionInfo2.PermissionState = 'Deny'
                    $mockDatabasePermissionInfo2.PermissionType = $mockDatabasePermissionSet2

                    $mockDatabasePermissionInfoCollection += $mockDatabasePermissionInfo2

                    return $mockDatabasePermissionInfoCollection
                }
            }

            It 'Should return correct values for the states Grant and Deny and empty collections for the state GrantWithGrant' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockSqlSetupPrepareFailoverClusterInstance.GetCurrentState(@{
                            Name         = 'MockUserName'
                            DatabaseName = 'MockDatabaseName'
                            InstanceName = 'NamedInstance'
                        })

                    $currentState.Credential | Should -BeNullOrEmpty

                    $currentState.Permission.GetType().FullName | Should -Be 'DatabasePermission[]'
                    $currentState.Permission | Should -HaveCount 3

                    $grantState = $currentState.Permission.Where({ $_.State -eq 'Grant' })

                    $grantState | Should -Not -BeNullOrEmpty
                    $grantState.State | Should -Be 'Grant'
                    $grantState.Permission | Should -Contain 'Connect'
                    $grantState.Permission | Should -Contain 'Update'

                    $grantWithGrantState = $currentState.Permission.Where({ $_.State -eq 'GrantWithGrant' })

                    $grantWithGrantState | Should -Not -BeNullOrEmpty
                    $grantWithGrantState.State | Should -Be 'GrantWithGrant'
                    $grantWithGrantState.Permission | Should -BeNullOrEmpty

                    $denyState = $currentState.Permission.Where({ $_.State -eq 'Deny' })

                    $denyState | Should -Not -BeNullOrEmpty
                    $denyState.State | Should -Be 'Deny'
                    $denyState.Permission | Should -Contain 'Select'

                    $currentState.PermissionToInclude | Should -HaveCount 1
                    $currentState.PermissionToInclude[0].State | Should -Be 'Grant'
                    $currentState.PermissionToInclude[0].Permission | Should -Be 'Update'
                }
            }
        }

        Context 'When the system is not in the desired state' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                        Name                = 'MockUserName'
                        DatabaseName        = 'MockDatabaseName'
                        InstanceName        = 'NamedInstance'
                        PermissionToInclude = [DatabasePermission] @{
                            State      = 'Grant'
                            Permission = 'alter'
                        }
                    }
                }

                Mock -CommandName Connect-SqlDscDatabaseEngine -MockWith {
                    return New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.Server'
                }

                Mock -CommandName Get-SqlDscDatabasePermission -MockWith {
                    [Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo[]] $mockDatabasePermissionInfoCollection = @()

                    $mockDatabasePermissionSet1 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionSet'
                    $mockDatabasePermissionSet1.Connect = $true
                    $mockDatabasePermissionSet1.Update = $true

                    $mockDatabasePermissionInfo1 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo'
                    $mockDatabasePermissionInfo1.PermissionState = 'Grant'
                    $mockDatabasePermissionInfo1.PermissionType = $mockDatabasePermissionSet1

                    $mockDatabasePermissionInfoCollection += $mockDatabasePermissionInfo1

                    $mockDatabasePermissionSet2 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionSet'
                    $mockDatabasePermissionSet2.Select = $true

                    $mockDatabasePermissionInfo2 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo'
                    $mockDatabasePermissionInfo2.PermissionState = 'Deny'
                    $mockDatabasePermissionInfo2.PermissionType = $mockDatabasePermissionSet2

                    $mockDatabasePermissionInfoCollection += $mockDatabasePermissionInfo2

                    return $mockDatabasePermissionInfoCollection
                }
            }

            It 'Should return correct values for the states Grant and Deny and empty collections for the state GrantWithGrant' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockSqlSetupPrepareFailoverClusterInstance.GetCurrentState(@{
                            Name         = 'MockUserName'
                            DatabaseName = 'MockDatabaseName'
                            InstanceName = 'NamedInstance'
                        })

                    $currentState.Credential | Should -BeNullOrEmpty

                    $currentState.Permission.GetType().FullName | Should -Be 'DatabasePermission[]'
                    $currentState.Permission | Should -HaveCount 3

                    $grantState = $currentState.Permission.Where({ $_.State -eq 'Grant' })

                    $grantState | Should -Not -BeNullOrEmpty
                    $grantState.State | Should -Be 'Grant'
                    $grantState.Permission | Should -Contain 'Connect'
                    $grantState.Permission | Should -Contain 'Update'

                    $grantWithGrantState = $currentState.Permission.Where({ $_.State -eq 'GrantWithGrant' })

                    $grantWithGrantState | Should -Not -BeNullOrEmpty
                    $grantWithGrantState.State | Should -Be 'GrantWithGrant'
                    $grantWithGrantState.Permission | Should -BeNullOrEmpty

                    $denyState = $currentState.Permission.Where({ $_.State -eq 'Deny' })

                    $denyState | Should -Not -BeNullOrEmpty
                    $denyState.State | Should -Be 'Deny'
                    $denyState.Permission | Should -Contain 'Select'

                    $currentState.PermissionToInclude | Should -HaveCount 1
                    $currentState.PermissionToInclude[0].State | Should -Be 'Grant'
                    $currentState.PermissionToInclude[0].Permission | Should -BeNullOrEmpty
                }
            }
        }
    }

    Context 'When using parameter PermissionToExclude' {
        Context 'When the system is in the desired state' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                        Name                = 'MockUserName'
                        DatabaseName        = 'MockDatabaseName'
                        InstanceName        = 'NamedInstance'
                        PermissionToExclude = [DatabasePermission] @{
                            State      = 'Grant'
                            Permission = 'alter'
                        }
                    }
                }

                Mock -CommandName Connect-SqlDscDatabaseEngine -MockWith {
                    return New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.Server'
                }

                Mock -CommandName Get-SqlDscDatabasePermission -MockWith {
                    [Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo[]] $mockDatabasePermissionInfoCollection = @()

                    $mockDatabasePermissionSet1 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionSet'
                    $mockDatabasePermissionSet1.Connect = $true
                    $mockDatabasePermissionSet1.Update = $true

                    $mockDatabasePermissionInfo1 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo'
                    $mockDatabasePermissionInfo1.PermissionState = 'Grant'
                    $mockDatabasePermissionInfo1.PermissionType = $mockDatabasePermissionSet1

                    $mockDatabasePermissionInfoCollection += $mockDatabasePermissionInfo1

                    $mockDatabasePermissionSet2 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionSet'
                    $mockDatabasePermissionSet2.Select = $true

                    $mockDatabasePermissionInfo2 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo'
                    $mockDatabasePermissionInfo2.PermissionState = 'Deny'
                    $mockDatabasePermissionInfo2.PermissionType = $mockDatabasePermissionSet2

                    $mockDatabasePermissionInfoCollection += $mockDatabasePermissionInfo2

                    return $mockDatabasePermissionInfoCollection
                }
            }

            It 'Should return correct values for the states Grant and Deny and empty collections for the state GrantWithGrant' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockSqlSetupPrepareFailoverClusterInstance.GetCurrentState(@{
                            Name         = 'MockUserName'
                            DatabaseName = 'MockDatabaseName'
                            InstanceName = 'NamedInstance'
                        })

                    $currentState.Credential | Should -BeNullOrEmpty

                    $currentState.Permission.GetType().FullName | Should -Be 'DatabasePermission[]'
                    $currentState.Permission | Should -HaveCount 3

                    $grantState = $currentState.Permission.Where({ $_.State -eq 'Grant' })

                    $grantState | Should -Not -BeNullOrEmpty
                    $grantState.State | Should -Be 'Grant'
                    $grantState.Permission | Should -Contain 'Connect'
                    $grantState.Permission | Should -Contain 'Update'

                    $grantWithGrantState = $currentState.Permission.Where({ $_.State -eq 'GrantWithGrant' })

                    $grantWithGrantState | Should -Not -BeNullOrEmpty
                    $grantWithGrantState.State | Should -Be 'GrantWithGrant'
                    $grantWithGrantState.Permission | Should -BeNullOrEmpty

                    $denyState = $currentState.Permission.Where({ $_.State -eq 'Deny' })

                    $denyState | Should -Not -BeNullOrEmpty
                    $denyState.State | Should -Be 'Deny'
                    $denyState.Permission | Should -Contain 'Select'

                    $currentState.PermissionToExclude | Should -HaveCount 1
                    $currentState.PermissionToExclude[0].State | Should -Be 'Grant'
                    $currentState.PermissionToExclude[0].Permission | Should -Be 'Alter'
                }
            }
        }

        Context 'When the system is not in the desired state' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                        Name                = 'MockUserName'
                        DatabaseName        = 'MockDatabaseName'
                        InstanceName        = 'NamedInstance'
                        PermissionToExclude = [DatabasePermission] @{
                            State      = 'Grant'
                            Permission = 'update'
                        }
                    }
                }

                Mock -CommandName Connect-SqlDscDatabaseEngine -MockWith {
                    return New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.Server'
                }

                Mock -CommandName Get-SqlDscDatabasePermission -MockWith {
                    [Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo[]] $mockDatabasePermissionInfoCollection = @()

                    $mockDatabasePermissionSet1 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionSet'
                    $mockDatabasePermissionSet1.Connect = $true
                    $mockDatabasePermissionSet1.Update = $true

                    $mockDatabasePermissionInfo1 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo'
                    $mockDatabasePermissionInfo1.PermissionState = 'Grant'
                    $mockDatabasePermissionInfo1.PermissionType = $mockDatabasePermissionSet1

                    $mockDatabasePermissionInfoCollection += $mockDatabasePermissionInfo1

                    $mockDatabasePermissionSet2 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionSet'
                    $mockDatabasePermissionSet2.Select = $true

                    $mockDatabasePermissionInfo2 = New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo'
                    $mockDatabasePermissionInfo2.PermissionState = 'Deny'
                    $mockDatabasePermissionInfo2.PermissionType = $mockDatabasePermissionSet2

                    $mockDatabasePermissionInfoCollection += $mockDatabasePermissionInfo2

                    return $mockDatabasePermissionInfoCollection
                }
            }

            It 'Should return correct values for the states Grant and Deny and empty collections for the state GrantWithGrant' {
                InModuleScope -ScriptBlock {
                    $currentState = $script:mockSqlSetupPrepareFailoverClusterInstance.GetCurrentState(@{
                            Name         = 'MockUserName'
                            DatabaseName = 'MockDatabaseName'
                            InstanceName = 'NamedInstance'
                        })

                    $currentState.Credential | Should -BeNullOrEmpty

                    $currentState.Permission.GetType().FullName | Should -Be 'DatabasePermission[]'
                    $currentState.Permission | Should -HaveCount 3

                    $grantState = $currentState.Permission.Where({ $_.State -eq 'Grant' })

                    $grantState | Should -Not -BeNullOrEmpty
                    $grantState.State | Should -Be 'Grant'
                    $grantState.Permission | Should -Contain 'Connect'
                    $grantState.Permission | Should -Contain 'Update'

                    $grantWithGrantState = $currentState.Permission.Where({ $_.State -eq 'GrantWithGrant' })

                    $grantWithGrantState | Should -Not -BeNullOrEmpty
                    $grantWithGrantState.State | Should -Be 'GrantWithGrant'
                    $grantWithGrantState.Permission | Should -BeNullOrEmpty

                    $denyState = $currentState.Permission.Where({ $_.State -eq 'Deny' })

                    $denyState | Should -Not -BeNullOrEmpty
                    $denyState.State | Should -Be 'Deny'
                    $denyState.Permission | Should -Contain 'Select'

                    $currentState.PermissionToExclude | Should -HaveCount 1
                    $currentState.PermissionToExclude[0].State | Should -Be 'Grant'
                    $currentState.PermissionToExclude[0].Permission | Should -BeNullOrEmpty
                }
            }
        }
    }
}

Describe 'SqlSetupPrepareFailoverCluster\Set()' -Tag 'Set' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                Name         = 'MockUserName'
                DatabaseName = 'MockDatabaseName'
                InstanceName = 'NamedInstance'
                Permission   = [DatabasePermission[]] @(
                    [DatabasePermission] @{
                        State      = 'Grant'
                        Permission = @('Connect')
                    }
                    [DatabasePermission] @{
                        State      = 'GrantWithGrant'
                        Permission = @()
                    }
                    [DatabasePermission] @{
                        State      = 'Deny'
                        Permission = @()
                    }
                )
            } |
                # Mock method Modify which is called by the base method Set().
                Add-Member -Force -MemberType 'ScriptMethod' -Name 'Modify' -Value {
                    $script:mockMethodModifyCallCount += 1
                } -PassThru
        }
    }

    BeforeEach {
        InModuleScope -ScriptBlock {
            $script:mockMethodModifyCallCount = 0
        }
    }

    Context 'When the system is in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlSetupPrepareFailoverClusterInstance |
                    # Mock method Compare() which is called by the base method Set()
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'Compare' -Value {
                        return $null
                    }
            }
        }

        It 'Should not call method Modify()' {
            InModuleScope -ScriptBlock {
                $script:mockSqlSetupPrepareFailoverClusterInstance.Set()

                $script:mockMethodModifyCallCount | Should -Be 0
            }
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlSetupPrepareFailoverClusterInstance |
                    # Mock method Compare() which is called by the base method Set()
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'Compare' -Value {
                        return @{
                            Property      = 'Permission'
                            ExpectedValue = [DatabasePermission[]] @(
                                [DatabasePermission] @{
                                    State      = 'Grant'
                                    Permission = @('Connect', 'Update')
                                }
                            )
                            ActualValue   = [DatabasePermission[]] @(
                                [DatabasePermission] @{
                                    State      = 'Grant'
                                    Permission = @('Connect')
                                }
                            )
                        }
                    }
            }
        }

        It 'Should not call method Modify()' {
            InModuleScope -ScriptBlock {
                $script:mockSqlSetupPrepareFailoverClusterInstance.Set()

                $script:mockMethodModifyCallCount | Should -Be 1
            }
        }
    }
}

Describe 'SqlSetupPrepareFailoverCluster\Test()' -Tag 'Test' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                Name         = 'MockUserName'
                DatabaseName = 'MockDatabaseName'
                InstanceName = 'NamedInstance'
                Permission   = [DatabasePermission[]] @(
                    [DatabasePermission] @{
                        State      = 'Grant'
                        Permission = @('Connect')
                    }
                    [DatabasePermission] @{
                        State      = 'GrantWithGrant'
                        Permission = @()
                    }
                    [DatabasePermission] @{
                        State      = 'Deny'
                        Permission = @()
                    }
                )
            }
        }
    }

    Context 'When the system is in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlSetupPrepareFailoverClusterInstance |
                    # Mock method Compare() which is called by the base method Set()
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'Compare' -Value {
                        return $null
                    }
            }
        }

        It 'Should return $true' {
            InModuleScope -ScriptBlock {
                $script:mockSqlSetupPrepareFailoverClusterInstance.Test() | Should -BeTrue
            }
        }
    }

    Context 'When the system is not in the desired state' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                $script:mockSqlSetupPrepareFailoverClusterInstance |
                    # Mock method Compare() which is called by the base method Set()
                    Add-Member -Force -MemberType 'ScriptMethod' -Name 'Compare' -Value {
                        return @{
                            Property      = 'Permission'
                            ExpectedValue = [DatabasePermission[]] @(
                                [DatabasePermission] @{
                                    State      = 'Grant'
                                    Permission = @('Connect', 'Update')
                                }
                            )
                            ActualValue   = [DatabasePermission[]] @(
                                [DatabasePermission] @{
                                    State      = 'Grant'
                                    Permission = @('Connect')
                                }
                            )
                        }
                    }
            }
        }

        It 'Should return $false' {
            InModuleScope -ScriptBlock {
                $script:mockSqlSetupPrepareFailoverClusterInstance.Test() | Should -BeFalse
            }
        }
    }
}

Describe 'SqlSetupPrepareFailoverCluster\Modify()' -Tag 'Modify' {
    Context 'When the database principal does not exist' {
        BeforeAll {
            InModuleScope -ScriptBlock {
                # This test does not set a desired state as it is not necessary for this test.
                $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                    Name         = 'MockUserName'
                    DatabaseName = 'MockDatabaseName'
                    InstanceName = 'NamedInstance'
                    # Credential is set to increase code coverage.
                    Credential   = [System.Management.Automation.PSCredential]::new(
                        'MyCredentialUserName',
                        [SecureString]::new()
                    )
                }
            }

            Mock -CommandName Connect-SqlDscDatabaseEngine -MockWith {
                return New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.Server'
            }

            Mock -CommandName Test-SqlDscIsDatabasePrincipal -MockWith {
                return $false
            }
        }

        It 'Should throw the correct error' {
            $mockErrorMessage = InModuleScope -ScriptBlock {
                $mockSqlSetupPrepareFailoverClusterInstance.localizedData.NameIsMissing
            }

            $mockErrorRecord = Get-InvalidOperationRecord -Message (
                $mockErrorMessage -f @(
                    'MockUserName'
                    'MockDatabaseName'
                    'NamedInstance'
                )
            )

            InModuleScope -ScriptBlock {
                {
                    # This test does not pass any properties to set as it is not necessary for this test.
                    $mockSqlSetupPrepareFailoverClusterInstance.Modify(@{
                            Permission = [DatabasePermission[]] @()
                        })
                } | Should -Throw -ExpectedMessage $mockErrorRecord
            }
        }
    }

    Context 'When property Permission is not in desired state' {
        Context 'When a desired permissions is missing from the current state' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                        Name         = 'MockUserName'
                        DatabaseName = 'MockDatabaseName'
                        InstanceName = 'NamedInstance'
                        Permission   = [DatabasePermission[]] @(
                            [DatabasePermission] @{
                                State      = 'Grant'
                                Permission = @('Connect')
                            }
                            [DatabasePermission] @{
                                State      = 'GrantWithGrant'
                                Permission = @('Update')
                            }
                            [DatabasePermission] @{
                                State      = 'Deny'
                                Permission = @()
                            }
                        )
                    }

                    # This mocks the method GetCurrentState().
                    $script:mockSqlSetupPrepareFailoverClusterInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                Permission = [DatabasePermission[]] @(
                                    [DatabasePermission] @{
                                        State      = 'Grant'
                                        Permission = @()
                                    }
                                    [DatabasePermission] @{
                                        State      = 'GrantWithGrant'
                                        Permission = @()
                                    }
                                    [DatabasePermission] @{
                                        State      = 'Deny'
                                        Permission = @()
                                    }
                                )
                            }
                        }
                }

                Mock -CommandName Connect-SqlDscDatabaseEngine -MockWith {
                    return New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.Server'
                }

                Mock -CommandName Test-SqlDscIsDatabasePrincipal -MockWith {
                    return $true
                }

                Mock -CommandName Set-SqlDscDatabasePermission
            }

            It 'Should call the correct mock with the correct parameter values' {
                InModuleScope -ScriptBlock {
                    {
                        $mockSqlSetupPrepareFailoverClusterInstance.Modify(@{
                                Permission = [DatabasePermission[]] @(
                                    [DatabasePermission] @{
                                        State      = 'Grant'
                                        Permission = @('Connect')
                                    }
                                    [DatabasePermission] @{
                                        State      = 'GrantWithGrant'
                                        Permission = @('Update')
                                    }
                                    [DatabasePermission] @{
                                        State      = 'Deny'
                                        Permission = @()
                                    }
                                )
                            })
                    } | Should -Not -Throw
                }

                # Grants
                Should -Invoke -CommandName Set-SqlDscDatabasePermission -ParameterFilter {
                    $State -eq 'Grant' -and $Permission.Connect -eq $true
                } -Exactly -Times 1 -Scope It

                # GrantWithGrants
                Should -Invoke -CommandName Set-SqlDscDatabasePermission -ParameterFilter {
                    $State -eq 'Grant' -and $Permission.Update -eq $true
                } -Exactly -Times 1 -Scope It
            }
        }

        Context 'When a desired permission is missing from the current state and there are four permissions that should not exist in the current state' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                        Name         = 'MockUserName'
                        DatabaseName = 'MockDatabaseName'
                        InstanceName = 'NamedInstance'
                        Permission   = [DatabasePermission[]] @(
                            [DatabasePermission] @{
                                State      = 'Grant'
                                Permission = @('Connect')
                            }
                            [DatabasePermission] @{
                                State      = 'GrantWithGrant'
                                Permission = @()
                            }
                            [DatabasePermission] @{
                                State      = 'Deny'
                                Permission = @()
                            }
                        )
                    }

                    # This mocks the method GetCurrentState().
                    $script:mockSqlSetupPrepareFailoverClusterInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                Permission = [DatabasePermission[]] @(
                                    [DatabasePermission] @{
                                        State      = 'Grant'
                                        Permission = @('Alter', 'Select')
                                    }
                                    [DatabasePermission] @{
                                        State      = 'GrantWithGrant'
                                        Permission = @('Delete')
                                    }
                                    [DatabasePermission] @{
                                        State      = 'Deny'
                                        Permission = @('CreateDatabase')
                                    }
                                )
                            }
                        }
                }

                Mock -CommandName Connect-SqlDscDatabaseEngine -MockWith {
                    return New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.Server'
                }

                Mock -CommandName Test-SqlDscIsDatabasePrincipal -MockWith {
                    return $true
                }

                Mock -CommandName Set-SqlDscDatabasePermission
            }

            It 'Should call the correct mock with the correct parameter values' {
                InModuleScope -ScriptBlock {
                    {
                        $mockSqlSetupPrepareFailoverClusterInstance.Modify(@{
                                Permission = [DatabasePermission[]] @(
                                    [DatabasePermission] @{
                                        State      = 'Grant'
                                        Permission = @('Connect')
                                    }
                                    [DatabasePermission] @{
                                        State      = 'GrantWithGrant'
                                        Permission = @()
                                    }
                                    [DatabasePermission] @{
                                        State      = 'Deny'
                                        Permission = @()
                                    }
                                )
                            })
                    } | Should -Not -Throw
                }

                # Revoking Grants
                Should -Invoke -CommandName Set-SqlDscDatabasePermission -ParameterFilter {
                    $State -eq 'Revoke' -and $Permission.Alter -eq $true -and $Permission.Select -eq $true
                } -Exactly -Times 1 -Scope It

                # Revoking GrantWithGrants
                Should -Invoke -CommandName Set-SqlDscDatabasePermission -ParameterFilter {
                    $State -eq 'Revoke' -and $Permission.Delete -eq $true
                } -Exactly -Times 1 -Scope It

                # Revoking Denies
                Should -Invoke -CommandName Set-SqlDscDatabasePermission -ParameterFilter {
                    $State -eq 'Revoke' -and $Permission.CreateDatabase -eq $true
                } -Exactly -Times 1 -Scope It

                # Adding new Grant
                Should -Invoke -CommandName Set-SqlDscDatabasePermission -ParameterFilter {
                    $State -eq 'Grant' -and $Permission.Connect -eq $true
                } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When property PermissionToInclude is not in desired state' {
        Context 'When a desired permissions is missing from the current state' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                        Name                = 'MockUserName'
                        DatabaseName        = 'MockDatabaseName'
                        InstanceName        = 'NamedInstance'
                        PermissionToInclude = [DatabasePermission[]] @(
                            [DatabasePermission] @{
                                State      = 'Grant'
                                Permission = @('Connect')
                            }
                            [DatabasePermission] @{
                                State      = 'GrantWithGrant'
                                Permission = @('Update')
                            }
                            [DatabasePermission] @{
                                State      = 'Deny'
                                Permission = @()
                            }
                        )
                    }

                    # This mocks the method GetCurrentState().
                    $script:mockSqlSetupPrepareFailoverClusterInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                Permission = [DatabasePermission[]] @(
                                    [DatabasePermission] @{
                                        State      = 'Grant'
                                        Permission = @()
                                    }
                                    [DatabasePermission] @{
                                        State      = 'GrantWithGrant'
                                        Permission = @()
                                    }
                                    [DatabasePermission] @{
                                        State      = 'Deny'
                                        Permission = @()
                                    }
                                )
                            }
                        }
                }

                Mock -CommandName Connect-SqlDscDatabaseEngine -MockWith {
                    return New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.Server'
                }

                Mock -CommandName Test-SqlDscIsDatabasePrincipal -MockWith {
                    return $true
                }

                Mock -CommandName Set-SqlDscDatabasePermission
            }

            It 'Should call the correct mock with the correct parameter values' {
                InModuleScope -ScriptBlock {
                    {
                        $mockSqlSetupPrepareFailoverClusterInstance.Modify(@{
                                PermissionToInclude = [DatabasePermission[]] @(
                                    [DatabasePermission] @{
                                        State      = 'Grant'
                                        Permission = @('Connect')
                                    }
                                    [DatabasePermission] @{
                                        State      = 'GrantWithGrant'
                                        Permission = @('Update')
                                    }
                                    [DatabasePermission] @{
                                        State      = 'Deny'
                                        Permission = @()
                                    }
                                )
                            })
                    } | Should -Not -Throw
                }

                # Grants
                Should -Invoke -CommandName Set-SqlDscDatabasePermission -ParameterFilter {
                    $State -eq 'Grant' -and $Permission.Connect -eq $true
                } -Exactly -Times 1 -Scope It

                # GrantWithGrants
                Should -Invoke -CommandName Set-SqlDscDatabasePermission -ParameterFilter {
                    $State -eq 'Grant' -and $Permission.Update -eq $true
                } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When property PermissionToExclude is not in desired state' {
        Context 'When a desired permissions is missing from the current state' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                        Name                = 'MockUserName'
                        DatabaseName        = 'MockDatabaseName'
                        InstanceName        = 'NamedInstance'
                        PermissionToExclude = [DatabasePermission[]] @(
                            [DatabasePermission] @{
                                State      = 'Grant'
                                Permission = @('Connect')
                            }
                            [DatabasePermission] @{
                                State      = 'GrantWithGrant'
                                Permission = @('Update')
                            }
                            [DatabasePermission] @{
                                State      = 'Deny'
                                Permission = @()
                            }
                        )
                    }

                    # This mocks the method GetCurrentState().
                    $script:mockSqlSetupPrepareFailoverClusterInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                Permission = [DatabasePermission[]] @(
                                    [DatabasePermission] @{
                                        State      = 'Grant'
                                        Permission = @('Connect')
                                    }
                                    [DatabasePermission] @{
                                        State      = 'GrantWithGrant'
                                        Permission = @('Update')
                                    }
                                    [DatabasePermission] @{
                                        State      = 'Deny'
                                        Permission = @()
                                    }
                                )
                            }
                        }
                }

                Mock -CommandName Connect-SqlDscDatabaseEngine -MockWith {
                    return New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.Server'
                }

                Mock -CommandName Test-SqlDscIsDatabasePrincipal -MockWith {
                    return $true
                }

                Mock -CommandName Set-SqlDscDatabasePermission
            }

            It 'Should call the correct mock with the correct parameter values' {
                InModuleScope -ScriptBlock {
                    {
                        $mockSqlSetupPrepareFailoverClusterInstance.Modify(@{
                                PermissionToExclude = [DatabasePermission[]] @(
                                    [DatabasePermission] @{
                                        State      = 'Grant'
                                        Permission = @('Connect')
                                    }
                                    [DatabasePermission] @{
                                        State      = 'GrantWithGrant'
                                        Permission = @('Update')
                                    }
                                    [DatabasePermission] @{
                                        State      = 'Deny'
                                        Permission = @()
                                    }
                                )
                            })
                    } | Should -Not -Throw
                }

                # Revoking Grants
                Should -Invoke -CommandName Set-SqlDscDatabasePermission -ParameterFilter {
                    $State -eq 'Revoke' -and $Permission.Connect -eq $true
                } -Exactly -Times 1 -Scope It

                # Revoking GrantWithGrants
                Should -Invoke -CommandName Set-SqlDscDatabasePermission -ParameterFilter {
                    $State -eq 'Revoke' -and $Permission.Update -eq $true
                } -Exactly -Times 1 -Scope It
            }
        }
    }

    Context 'When Set-SqlDscDatabasePermission fails to change permission' {
        Context 'When granting permissions' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                        Name         = 'MockUserName'
                        DatabaseName = 'MockDatabaseName'
                        InstanceName = 'NamedInstance'
                        Permission   = [DatabasePermission[]] @(
                            [DatabasePermission] @{
                                State      = 'Grant'
                                Permission = @('Connect')
                            }
                            [DatabasePermission] @{
                                State      = 'GrantWithGrant'
                                Permission = @()
                            }
                            [DatabasePermission] @{
                                State      = 'Deny'
                                Permission = @()
                            }
                        )
                    }

                    # This mocks the method GetCurrentState().
                    $script:mockSqlSetupPrepareFailoverClusterInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                Permission = [DatabasePermission[]] @(
                                    [DatabasePermission] @{
                                        State      = 'Grant'
                                        Permission = @()
                                    }
                                    [DatabasePermission] @{
                                        State      = 'GrantWithGrant'
                                        Permission = @()
                                    }
                                    [DatabasePermission] @{
                                        State      = 'Deny'
                                        Permission = @()
                                    }
                                )
                            }
                        }
                }

                Mock -CommandName Connect-SqlDscDatabaseEngine -MockWith {
                    return New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.Server'
                }

                Mock -CommandName Test-SqlDscIsDatabasePrincipal -MockWith {
                    return $true
                }

                Mock -CommandName Set-SqlDscDatabasePermission -MockWith {
                    throw 'Mocked error'
                }
            }

            It 'Should throw the correct error' {
                $mockErrorMessage = InModuleScope -ScriptBlock {
                    $mockSqlSetupPrepareFailoverClusterInstance.localizedData.FailedToSetPermission
                }

                $mockErrorRecord = Get-InvalidOperationRecord -Message (
                    $mockErrorMessage -f @(
                        'MockUserName'
                        'MockDatabaseName'
                    )
                )

                InModuleScope -ScriptBlock {
                    {
                        $mockSqlSetupPrepareFailoverClusterInstance.Modify(@{
                                Permission = [DatabasePermission[]] @(
                                    [DatabasePermission] @{
                                        State      = 'Grant'
                                        Permission = @('Connect')
                                    }
                                    [DatabasePermission] @{
                                        State      = 'GrantWithGrant'
                                        Permission = @()
                                    }
                                    [DatabasePermission] @{
                                        State      = 'Deny'
                                        Permission = @()
                                    }
                                )
                            })
                    } | Should -Throw -ExpectedMessage $mockErrorRecord
                }
            }
        }

        Context 'When revoking permissions' {
            BeforeAll {
                InModuleScope -ScriptBlock {
                    $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{
                        Name         = 'MockUserName'
                        DatabaseName = 'MockDatabaseName'
                        InstanceName = 'NamedInstance'
                        Permission   = [DatabasePermission[]] @(
                            [DatabasePermission] @{
                                State      = 'Grant'
                                Permission = @('Connect')
                            }
                            [DatabasePermission] @{
                                State      = 'GrantWithGrant'
                                Permission = @()
                            }
                            [DatabasePermission] @{
                                State      = 'Deny'
                                Permission = @()
                            }
                        )
                    }

                    # This mocks the method GetCurrentState().
                    $script:mockSqlSetupPrepareFailoverClusterInstance |
                        Add-Member -Force -MemberType 'ScriptMethod' -Name 'GetCurrentState' -Value {
                            return [System.Collections.Hashtable] @{
                                Permission = [DatabasePermission[]] @(
                                    [DatabasePermission] @{
                                        State      = 'Grant'
                                        Permission = @('Update')
                                    }
                                    [DatabasePermission] @{
                                        State      = 'GrantWithGrant'
                                        Permission = @()
                                    }
                                    [DatabasePermission] @{
                                        State      = 'Deny'
                                        Permission = @()
                                    }
                                )
                            }
                        }
                }

                Mock -CommandName Connect-SqlDscDatabaseEngine -MockWith {
                    return New-Object -TypeName 'Microsoft.SqlServer.Management.Smo.Server'
                }

                Mock -CommandName Test-SqlDscIsDatabasePrincipal -MockWith {
                    return $true
                }

                Mock -CommandName Set-SqlDscDatabasePermission -MockWith {
                    throw 'Mocked error'
                }
            }

            It 'Should throw the correct error' {
                $mockErrorMessage = InModuleScope -ScriptBlock {
                    $mockSqlSetupPrepareFailoverClusterInstance.localizedData.FailedToRevokePermissionFromCurrentState
                }

                $mockErrorRecord = Get-InvalidOperationRecord -Message (
                    $mockErrorMessage -f @(
                        'MockUserName'
                        'MockDatabaseName'
                    )
                )

                InModuleScope -ScriptBlock {
                    {
                        $mockSqlSetupPrepareFailoverClusterInstance.Modify(@{
                                Permission = [DatabasePermission[]] @(
                                    [DatabasePermission] @{
                                        State      = 'Grant'
                                        Permission = @('Connect')
                                    }
                                    [DatabasePermission] @{
                                        State      = 'GrantWithGrant'
                                        Permission = @()
                                    }
                                    [DatabasePermission] @{
                                        State      = 'Deny'
                                        Permission = @()
                                    }
                                )
                            })
                    } | Should -Throw -ExpectedMessage $mockErrorRecord
                }
            }
        }
    }
}
#>

<#
Describe 'SqlSetupPrepareFailoverCluster\AssertProperties()' -Tag 'AssertProperties' {
    BeforeAll {
        InModuleScope -ScriptBlock {
            $script:mockSqlSetupPrepareFailoverClusterInstance = [SqlSetupPrepareFailoverCluster] @{}
        }
    }

    #
        These tests just check for the string localized ID. Since the error is part
        of a command outside of SqlServerDscX, a small changes to the localized
        string should not fail these tests.
    #
    Context 'When passing mutually exclusive parameters' {
        Context 'When passing Permission and PermissionToInclude' {
            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    {
                        $mockSqlSetupPrepareFailoverClusterInstance.AssertProperties(@{
                                Permission          = [DatabasePermission[]] @([DatabasePermission] @{})
                                PermissionToInclude = [DatabasePermission[]] @([DatabasePermission] @{})
                            })
                    } | Should -Throw -ExpectedMessage '*DRC0010*'
                }
            }
        }

        Context 'When passing Permission and PermissionToExclude' {
            It 'Should throw the correct error' {
                InModuleScope -ScriptBlock {
                    {
                        $mockSqlSetupPrepareFailoverClusterInstance.AssertProperties(@{
                                Permission          = [DatabasePermission[]] @([DatabasePermission] @{})
                                PermissionToExclude = [DatabasePermission[]] @([DatabasePermission] @{})
                            })
                    } | Should -Throw -ExpectedMessage '*DRC0010*'
                }
            }
        }
    }

    Context 'When not passing any permission property' {
        It 'Should throw the correct error' {
            $mockErrorMessage = InModuleScope -ScriptBlock {
                $mockSqlSetupPrepareFailoverClusterInstance.localizedData.MustAssignOnePermissionProperty
            }

            InModuleScope -ScriptBlock {
                {
                    $mockSqlSetupPrepareFailoverClusterInstance.AssertProperties(@{})
                } | Should -Throw -ExpectedMessage $mockErrorMessage
            }
        }
    }

    Context 'When a permission Property contain the same State twice' {
        It 'Should throw the correct error for property <MockPropertyName>' -ForEach @(
            @{
                MockPropertyName = 'Permission'
            }
            @{
                MockPropertyName = 'PermissionToInclude'
            }
            @{
                MockPropertyName = 'PermissionToExclude'
            }
        ) {
            $mockErrorMessage = InModuleScope -ScriptBlock {
                $mockSqlSetupPrepareFailoverClusterInstance.localizedData.DuplicatePermissionState
            }

            InModuleScope -Parameters $_ -ScriptBlock {
                {
                    $mockSqlSetupPrepareFailoverClusterInstance.AssertProperties(@{
                            $MockPropertyName = [DatabasePermission[]] @(
                                [DatabasePermission] @{
                                    State = 'Grant'
                                }
                                [DatabasePermission] @{
                                    State = 'Grant'
                                }
                            )
                        })
                } | Should -Throw -ExpectedMessage $mockErrorMessage
            }
        }
    }

    Context 'When the property Permission is missing a state' {
        It 'Should throw the correct error' {
            $mockErrorMessage = InModuleScope -ScriptBlock {
                $mockSqlSetupPrepareFailoverClusterInstance.localizedData.MissingPermissionState
            }

            InModuleScope -Parameters $_ -ScriptBlock {
                {
                    $mockSqlSetupPrepareFailoverClusterInstance.AssertProperties(@{
                            Permission = [DatabasePermission[]] @(
                                # Missing state Deny.
                                [DatabasePermission] @{
                                    State = 'Grant'
                                }
                                [DatabasePermission] @{
                                    State = 'GrantWithGrant'
                                }
                            )
                        })
                } | Should -Throw -ExpectedMessage $mockErrorMessage
            }
        }
    }

    Context 'When a permission Property contain the same permission name twice' {
        It 'Should throw the correct error for property <MockPropertyName>' -ForEach @(
            @{
                MockPropertyName = 'Permission'
            }
            @{
                MockPropertyName = 'PermissionToInclude'
            }
            @{
                MockPropertyName = 'PermissionToExclude'
            }
        ) {
            $mockErrorMessage = InModuleScope -ScriptBlock {
                $mockSqlSetupPrepareFailoverClusterInstance.localizedData.DuplicatePermissionBetweenState
            }

            InModuleScope -Parameters $_ -ScriptBlock {
                {
                    $mockSqlSetupPrepareFailoverClusterInstance.AssertProperties(@{
                            $MockPropertyName = [DatabasePermission[]] @(
                                [DatabasePermission] @{
                                    State      = 'Grant'
                                    Permission = 'Select'
                                }
                                [DatabasePermission] @{
                                    State      = 'Deny'
                                    Permission = 'Select'
                                }
                            )
                        })
                } | Should -Throw -ExpectedMessage $mockErrorMessage
            }
        }
    }

    Context 'When a permission Property does not specify any permission name' {
        It 'Should throw the correct error for property <MockPropertyName>' -ForEach @(
            @{
                MockPropertyName = 'PermissionToInclude'
            }
            @{
                MockPropertyName = 'PermissionToExclude'
            }
        ) {
            $mockErrorMessage = InModuleScope -ScriptBlock {
                $mockSqlSetupPrepareFailoverClusterInstance.localizedData.MustHaveMinimumOnePermissionInState
            }

            InModuleScope -Parameters $_ -ScriptBlock {
                {
                    $mockSqlSetupPrepareFailoverClusterInstance.AssertProperties(@{
                            $MockPropertyName = [DatabasePermission[]] @(
                                [DatabasePermission] @{
                                    State      = 'Grant'
                                    #
                                        This should not be able to be $null since the property
                                        is mandatory but do allow empty collection. So no need
                                        to test using $null value.
                                    #
                                    Permission = @()
                                }
                                [DatabasePermission] @{
                                    State      = 'Deny'
                                    Permission = 'Select'
                                }
                            )
                        })
                } | Should -Throw -ExpectedMessage $mockErrorMessage
            }
        }
    }
}
#>
