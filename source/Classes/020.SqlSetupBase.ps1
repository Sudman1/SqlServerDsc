<#
    .SYNOPSIS
        A class with methods to manage the different SQL setup actions.

    .DESCRIPTION
        A class with methods to manage the different SQL setup actions.

    .NOTES
        This class should be able to be inherited by all SQL setup-related DSC
        resources. This class shall not contain any DSC properties, neither
        shall it contain anything specific to only a single resource.
#>

class SqlSetupBase : ResourceBase
{
    [DscProperty(Key)]
    [System.String]
    $Action

    [DscProperty()]
    [System.Boolean]
    $SuppressReboot

    [DscProperty()]
    [System.Boolean]
    $ForceReboot

    [DscProperty()]
    [System.UInt32]
    $SetupProcessTimeout = 7200

    <#
        After completing some actions, setup.exe does not (and cannot) start the SQL service, so we must
        skip attempts to connect to the service to avoid stopping errors.
    #>
    $actionsWithoutServerAccess = @('PrepareFailoverCluster')

    SqlSetupBase() : base ()
    {
    }

    [SqlSetupBase] Get()
    {
        # Call the base method to return the properties.
        return ([ResourceBase] $this).Get()
    }

    [System.Boolean] Test()
    {
        # Call the base method to test all of the properties that should be enforced.
        return ([ResourceBase] $this).Test()
    }

    [void] Set()
    {
        # Call the base method to enforce the properties.
        ([ResourceBase] $this).Set()
    }

    <#
        This method must be overridden by a resource. The parameter properties will
        contain the properties that should be enforced and that are not in desired
        state.
    #>
    hidden [void] Modify([System.Collections.Hashtable] $properties)
    {
        <#
            Fixing issue 448, setting FailoverClusterGroupName to default value
            if not specified in configuration.
        #>
        if ($null -eq $this.FailoverClusterGroupName)
        {
            $this.FailoverClusterGroupName = 'SQL Server ({0})' -f $this.InstanceName
        }

        # Force drive list update, to pick up any newly mounted volumes
        $null = Get-PSDrive

        $getTargetResourceParameters = @{
            Action                     = $this.Action
            SourcePath                 = $this.SourcePath
            SourceCredential           = $this.SourceCredential
            InstanceName               = $this.InstanceName
            FailoverClusterNetworkName = $this.FailoverClusterNetworkName
            FeatureFlag                = $this.FeatureFlag
        }

        $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters

        $this.InstanceName = $this.InstanceName.ToUpper()

        $parametersToEvaluateTrailingSlash = @(
            'InstanceDir',
            'InstallSharedDir',
            'InstallSharedWOWDir',
            'InstallSQLDataDir',
            'SQLUserDBDir',
            'SQLUserDBLogDir',
            'SQLTempDBDir',
            'SQLTempDBLogDir',
            'SQLBackupDir',
            'ASDataDir',
            'ASLogDir',
            'ASBackupDir',
            'ASTempDir',
            'ASConfigDir',
            'UpdateSource'
        )

        # Making sure paths are correct.
        foreach ($parameterName in $parametersToEvaluateTrailingSlash)
        {
            if ($this.$parameterName)
            {
                $parameterValue = $this.$parameterName
                $formattedPath = Format-Path -Path $parameterValue -TrailingSlash
                $this.$parameterName = $formattedPath
            }
        }

        $SourcePath = [Environment]::ExpandEnvironmentVariables($this.SourcePath)

        if ($this.SourceCredential)
        {
            $invokeInstallationMediaCopyParameters = @{
                SourcePath       = $this.SourcePath
                SourceCredential = $this.SourceCredential
                PassThru         = $true
            }

            $SourcePath = Invoke-InstallationMediaCopy @invokeInstallationMediaCopyParameters
        }

        $pathToSetupExecutable = Join-Path -Path $this.SourcePath -ChildPath 'setup.exe'

        Write-Verbose -Message ($script:localizedData.UsingPath -f $pathToSetupExecutable)

        $sqlVersion = $this.GetFilePathMajorVersion($pathToSetupExecutable)

        # Determine features to install
        $featuresToInstall = ''

        $featuresArray = $this.Features -split ','

        foreach ($feature in $featuresArray)
        {
            if (($sqlVersion -in ('13', '14', '15')) -and ($feature -in ('ADV_SSMS', 'SSMS')))
            {
                $errorMessage = $script:localizedData.FeatureNotSupported -f $feature
                New-InvalidOperationException -Message $errorMessage
            }

            $foundFeaturesArray = $getTargetResourceResult.Features -split ','

            if ($feature -notin $foundFeaturesArray)
            {
                # Must make sure the feature names are provided in upper-case.
                $featuresToInstall += '{0},' -f $feature.ToUpper()
            }
            else
            {
                Write-Verbose -Message ($script:localizedData.FeatureAlreadyInstalled -f $feature)
            }
        }

        $this.Features = $featuresToInstall.Trim(',')

        # If SQL shared components already installed, clear InstallShared*Dir variables
        switch ($sqlVersion)
        {
            { $_ -in ('10', '11', '12', '13', '14', '15') }
            {
                if ($this.InstallSharedDir -and (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\FEE2E540D20152D4597229B6CFBC0A69' -ErrorAction SilentlyContinue))
                {
                    $this.'InstallSharedDir' = ''
                }

                if ($this.'InstallSharedWOWDir' -and (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\A79497A344129F64CA7D69C56F5DD8B4' -ErrorAction SilentlyContinue))
                {
                    $this.'InstallSharedWOWDir' = ''
                }
            }
        }

        $setupArguments = @{}

        if ($this.SkipRule)
        {
            $setupArguments['SkipRules'] = @($this.SkipRule)
        }

        <#
            Set the failover cluster group name and failover cluster network name for this clustered instance
            if the action is either installing (InstallFailoverCluster) or completing (CompleteFailoverCluster) a cluster.
        #>
        if ($this.Action -in @('CompleteFailoverCluster', 'InstallFailoverCluster'))
        {
            $setupArguments['FailoverClusterNetworkName'] = $this.FailoverClusterNetworkName
            $setupArguments['FailoverClusterGroup'] = $this.FailoverClusterGroupName
        }

        # Perform disk mapping for specific cluster installation types
        if ($this.Action -in @('CompleteFailoverCluster', 'InstallFailoverCluster'))
        {
            $requiredDrive = @()

            # This is also used to evaluate which cluster shard disks should be used.
            $parametersToEvaluateShareDisk = @(
                'InstallSQLDataDir',
                'SQLUserDBDir',
                'SQLUserDBLogDir',
                'SQLTempDBDir',
                'SQLTempDBLogDir',
                'SQLBackupDir',
                'ASDataDir',
                'ASLogDir',
                'ASBackupDir',
                'ASTempDir',
                'ASConfigDir'
            )

            # Get a required listing of drives based on parameters assigned by user.
            foreach ($parameterName in $parametersToEvaluateShareDisk)
            {
                if ($this.$parameterName)
                {
                    $parameterValue = $this.$parameterName
                    if ($parameterValue)
                    {
                        Write-Verbose -Message ($script:localizedData.PathRequireClusterDriveFound -f $parameterName, $parameterValue)
                        $requiredDrive += $parameterValue
                    }
                }
            }

            # Only keep unique paths and add a member to keep track if the path is mapped to a disk.
            $requiredDrive = $requiredDrive | Sort-Object -Unique | Add-Member -MemberType NoteProperty -Name IsMapped -Value $false -PassThru

            # Get the disk resources that are available (not assigned to a cluster role)
            $availableStorage = Get-CimInstance -Namespace 'root/MSCluster' -ClassName 'MSCluster_ResourceGroup' -Filter "Name = 'Available Storage'" |
                Get-CimAssociatedInstance -Association MSCluster_ResourceGroupToResource -ResultClassName MSCluster_Resource |
                Add-Member -MemberType NoteProperty -Name 'IsPossibleOwner' -Value $false -PassThru

            # First map regular cluster volumes
            foreach ($diskResource in $availableStorage)
            {
                # Determine whether the current node is a possible owner of the disk resource
                $possibleOwners = $diskResource | Get-CimAssociatedInstance -Association 'MSCluster_ResourceToPossibleOwner' -KeyOnly | Select-Object -ExpandProperty Name

                if ($possibleOwners -icontains (Get-ComputerName))
                {
                    $diskResource.IsPossibleOwner = $true
                }
            }

            $failoverClusterDisks = @()

            foreach ($currentRequiredDrive in $requiredDrive)
            {
                foreach ($diskResource in ($availableStorage | Where-Object -FilterScript { $_.IsPossibleOwner -eq $true }))
                {
                    $partitions = $diskResource | Get-CimAssociatedInstance -ResultClassName 'MSCluster_DiskPartition' | Select-Object -ExpandProperty Path
                    foreach ($partition in $partitions)
                    {
                        if ($currentRequiredDrive -imatch $partition.Replace('\', '\\'))
                        {
                            $currentRequiredDrive.IsMapped = $true
                            $failoverClusterDisks += $diskResource.Name
                            break
                        }

                        if ($currentRequiredDrive.IsMapped)
                        {
                            break
                        }
                    }

                    if ($currentRequiredDrive.IsMapped)
                    {
                        break
                    }
                }
            }

            # Now we handle cluster shared volumes
            $clusterSharedVolumes = Get-CimInstance -ClassName 'MSCluster_ClusterSharedVolume' -Namespace 'root/MSCluster'

            foreach ($clusterSharedVolume in $clusterSharedVolumes)
            {
                foreach ($currentRequiredDrive in ($requiredDrive | Where-Object -FilterScript { $_.IsMapped -eq $false }))
                {
                    if ($currentRequiredDrive -imatch $clusterSharedVolume.Name.Replace('\', '\\'))
                    {
                        $diskName = Get-CimInstance -ClassName 'MSCluster_ClusterSharedVolumeToResource' -Namespace 'root/MSCluster' | `
                                Where-Object -FilterScript { $_.GroupComponent.Name -eq $clusterSharedVolume.Name } | `
                                Select-Object -ExpandProperty PartComponent | `
                                Select-Object -ExpandProperty Name
                        $failoverClusterDisks += $diskName
                        $currentRequiredDrive.IsMapped = $true
                    }
                }
            }

            # Ensure we have a unique listing of disks
            $failoverClusterDisks = $failoverClusterDisks | Sort-Object -Unique

            # Ensure we mapped all required drives
            $unMappedRequiredDrives = $requiredDrive | Where-Object -FilterScript { $_.IsMapped -eq $false } | Measure-Object
            if ($unMappedRequiredDrives.Count -gt 0)
            {
                $errorMessage = $script:localizedData.FailoverClusterDiskMappingError -f ($failoverClusterDisks -join '; ')
                New-InvalidResultException -Message $errorMessage
            }

            # Add the cluster disks as a setup argument
            $setupArguments['FailoverClusterDisks'] = ($failoverClusterDisks | Sort-Object)
        }

        # Determine network mapping for specific cluster installation types
        if ($this.Action -in @('CompleteFailoverCluster', 'InstallFailoverCluster'))
        {
            $clusterIPAddresses = @()

            # If no IP Address has been specified, use "DEFAULT"
            if ($this.FailoverClusterIPAddress.Count -eq 0)
            {
                $clusterIPAddresses += 'DEFAULT'
            }
            else
            {
                # Get the available client networks
                $availableNetworks = @(Get-CimInstance -Namespace root/MSCluster -ClassName MSCluster_Network -Filter 'Role >= 2')

                # Add supplied IP Addresses that are valid for available cluster networks
                foreach ($address in $this.FailoverClusterIPAddress)
                {
                    foreach ($network in $availableNetworks)
                    {
                        # Determine whether the IP address is valid for this network
                        if (TestIPAddress($address, $network.Address, $network.AddressMask))
                        {
                            # Add the formatted string to our array
                            $clusterIPAddresses += "IPv4;$address;$($network.Name);$($network.AddressMask)"
                        }
                    }
                }
            }

            # Ensure we mapped all required networks
            $suppliedNetworkCount = $this.FailoverClusterIPAddress.Count
            $mappedNetworkCount = $clusterIPAddresses.Count

            # Determine whether we have mapping issues for the IP Address(es)
            if ($mappedNetworkCount -lt $suppliedNetworkCount)
            {
                $errorMessage = $script:localizedData.FailoverClusterIPAddressNotValid
                New-InvalidResultException -Message $errorMessage
            }

            # Add the networks to the installation arguments
            $setupArguments['FailoverClusterIPAddresses'] = $clusterIPAddresses
        }

        # Add standard install arguments
        $setupArguments += @{
            Quiet                        = $true
            IAcceptSQLServerLicenseTerms = $true
            Action                       = $this.Action
        }

        $argumentVars = @(
            'InstanceName',
            'InstanceID',
            'UpdateEnabled',
            'UpdateSource',
            'ProductKey',
            'SQMReporting',
            'ErrorReporting'
        )

        if ($this.Action -in @('Install', 'Upgrade', 'InstallFailoverCluster', 'PrepareFailoverCluster', 'CompleteFailoverCluster'))
        {
            $argumentVars += @(
                'Features',
                'InstallSharedDir',
                'InstallSharedWOWDir',
                'InstanceDir'
            )
        }

        if ($this.BrowserSvcStartupType)
        {
            $argumentVars += 'BrowserSvcStartupType'
        }

        if ($this.Features.Contains('SQLENGINE'))
        {
            if ($this.SQLSvcAccount)
            {
                $setupArguments += GetServiceAccountParameters($this.SQLSvcAccount, 'SQL')
            }

            if ($this.AgtSvcAccount)
            {
                $setupArguments += GetServiceAccountParameters($this.AgtSvcAccount, 'AGT')
            }

            if ($this.SecurityMode -eq 'SQL')
            {
                $setupArguments['SAPwd'] = $this.SAPwd.GetNetworkCredential().Password
            }

            # Should not be passed when PrepareFailoverCluster is specified
            if ($this.Action -in @('Install', 'Upgrade', 'InstallFailoverCluster', 'CompleteFailoverCluster'))
            {
                if ($null -ne $PsDscContext.RunAsUser)
                {
                    <#
                        Add the credentials from the parameter PsDscRunAsCredential, as the first
                        system administrator. The username is stored in $PsDscContext.RunAsUser.
                    #>
                    Write-Verbose -Message ($script:localizedData.AddingFirstSystemAdministratorSqlServer -f $($PsDscContext.RunAsUser))

                    $setupArguments['SQLSysAdminAccounts'] = @($PsDscContext.RunAsUser)
                }

                if ($this.SQLSysAdminAccounts)
                {
                    $setupArguments['SQLSysAdminAccounts'] += $this.SQLSysAdminAccounts
                }

                if ($null -ne $this.NpEnabled)
                {
                    if ($this.NpEnabled)
                    {
                        $setupArguments['NPENABLED'] = 1
                    }
                    else
                    {
                        $setupArguments['NPENABLED'] = 0
                    }
                }

                if ($null -ne $this.TcpEnabled)
                {
                    if ($this.TcpEnabled)
                    {
                        $setupArguments['TCPENABLED'] = 1
                    }
                    else
                    {
                        $setupArguments['TCPENABLED'] = 0
                    }
                }

                $argumentVars += @(
                    'SecurityMode',
                    'SQLCollation',
                    'InstallSQLDataDir',
                    'SQLUserDBDir',
                    'SQLUserDBLogDir',
                    'SQLTempDBDir',
                    'SQLTempDBLogDir',
                    'SQLBackupDir'
                )
            }

            # tempdb : define SqlTempdbFileCount
            if ($null -ne $this.SqlTempdbFileCount)
            {
                $setupArguments['SqlTempdbFileCount'] = $this.SqlTempdbFileCount
            }

            # tempdb : define SqlTempdbFileSize
            if ($null -ne $this.SqlTempdbFileSize)
            {
                $setupArguments['SqlTempdbFileSize'] = $this.SqlTempdbFileSize
            }

            # tempdb : define SqlTempdbFileGrowth
            if ($null -ne $this.SqlTempdbFileGrowth)
            {
                $setupArguments['SqlTempdbFileGrowth'] = $this.SqlTempdbFileGrowth
            }

            # tempdb : define SqlTempdbLogFileSize
            if ($null -ne $this.SqlTempdbLogFileSize)
            {
                $setupArguments['SqlTempdbLogFileSize'] = $this.SqlTempdbLogFileSize
            }

            # tempdb : define SqlTempdbLogFileGrowth
            if ($null -ne $this.SqlTempdbLogFileGrowth)
            {
                $setupArguments['SqlTempdbLogFileGrowth'] = $this.SqlTempdbLogFileGrowth
            }

            if ($this.Action -in @('Install', 'Upgrade'))
            {
                if ($PSBoundParameters.ContainsKey('AgtSvcStartupType'))
                {
                    $setupArguments['AgtSvcStartupType'] = $this.AgtSvcStartupType
                }

                if ($PSBoundParameters.ContainsKey('SqlSvcStartupType'))
                {
                    $setupArguments['SqlSvcStartupType'] = $this.SqlSvcStartupType
                }
            }
        }

        if ($this.Features.Contains('FULLTEXT'))
        {
            if ($this.FTSvcAccount)
            {
                $setupArguments += GetServiceAccountParameters($this.FTSvcAccount, 'FT')
            }
        }

        if ($this.Features.Contains('RS'))
        {
            if ($PSBoundParameters.ContainsKey('RSSvcAccount'))
            {
                $setupArguments += GetServiceAccountParameters($this.RSSvcAccount, 'RS')
            }

            if ($this.RsSvcStartupType)
            {
                $setupArguments['RsSvcStartupType'] = $this.RsSvcStartupType
            }

            if ($this.RSInstallMode)
            {
                $setupArguments['RSINSTALLMODE'] = $this.RSInstallMode
            }
        }

        if ($this.Features.Contains('AS'))
        {
            $argumentVars += @(
                'ASCollation',
                'ASDataDir',
                'ASLogDir',
                'ASBackupDir',
                'ASTempDir',
                'ASConfigDir'
            )


            if ($this.ASServerMode)
            {
                $setupArguments['ASServerMode'] = $this.ASServerMode
            }

            if ($this.ASSvcAccount)
            {
                $setupArguments += GetServiceAccountParameters($this.ASSvcAccount, 'AS')
            }

            if ($this.Action -in ('Install', 'Upgrade', 'InstallFailoverCluster', 'CompleteFailoverCluster'))
            {
                if ($null -ne $PsDscContext.RunAsUser)
                {
                    <#
                    Add the credentials from the parameter PsDscRunAsCredential, as the first
                    system administrator. The username is stored in $PsDscContext.RunAsUser.
                #>
                    Write-Verbose -Message ($script:localizedData.AddingFirstSystemAdministratorAnalysisServices -f $($PsDscContext.RunAsUser))

                    $setupArguments['ASSysAdminAccounts'] = @($PsDscContext.RunAsUser)
                }

                if ($this.ASSysAdminAccounts)
                {
                    $setupArguments['ASSysAdminAccounts'] += $this.ASSysAdminAccounts
                }
            }

            if ($this.AsSvcStartupType)
            {
                $setupArguments['AsSvcStartupType'] = $this.AsSvcStartupType
            }
        }

        if ($this.Features.Contains('IS'))
        {
            if ($this.ISSvcAccount)
            {
                $setupArguments += Get-ServiceAccountParameters($this.ISSvcAccount, 'IS')
            }

            if ($this.IsSvcStartupType)
            {
                $setupArguments['IsSvcStartupType'] = $this.IsSvcStartupType
            }
        }

        # Automatically include any additional arguments
        foreach ($argument in $argumentVars)
        {
            if ($argument -eq 'ProductKey')
            {
                $setupArguments['PID'] = $this.$argument
            }
            else
            {
                # If the argument contains a value, then add the argument to the setup argument list
                if ($this.$argument)
                {
                    $setupArguments[$argument] = $this.$argument
                }
            }
        }

        # Build the argument string to be passed to setup
        $arguments = ''
        foreach ($currentSetupArgument in $setupArguments.GetEnumerator())
        {
            <#
                Using [System.String]::IsNullOrEmpty() instead if comparing against
                an empty string ('') because the numeric value zero (0) equals to an
                empty string. This is evaluated to $true: 0 -eq ''
            #>
            if (-not [System.String]::IsNullOrEmpty($currentSetupArgument.Value))
            {
                # Arrays are handled specially
                if ($currentSetupArgument.Value -is [System.Array])
                {
                    # Sort and format the array
                    $setupArgumentValue = (
                        $currentSetupArgument.Value |
                            Sort-Object |
                            ForEach-Object -Process {
                                '"{0}"' -f $_
                            }
                    ) -join ' '
                }
                elseif ($currentSetupArgument.Value -is [System.Boolean])
                {
                    $setupArgumentValue = @{
                        $true  = 'True'
                        $false = 'False'
                    }[$currentSetupArgument.Value]

                    $setupArgumentValue = '"{0}"' -f $setupArgumentValue
                }
                else
                {
                    # Features are comma-separated, no quotes
                    if ($currentSetupArgument.Key -eq 'Features')
                    {
                        $setupArgumentValue = $currentSetupArgument.Value
                    }
                    else
                    {
                        # Logic added as a fix for Issue#1254 SqlSetup:Fails when a root directory is specified
                        if ($currentSetupArgument.Value -match '^[a-zA-Z]:\\$')
                        {
                            $setupArgumentValue = $currentSetupArgument.Value
                        }
                        else
                        {
                            $setupArgumentValue = '"{0}"' -f $currentSetupArgument.Value
                        }
                    }
                }

                $arguments += "/$($currentSetupArgument.Key.ToUpper())=$($setupArgumentValue) "
            }
        }

        if ($this.UseEnglish)
        {
            $arguments += '/ENU'
        }

        # Replace sensitive values for verbose output
        $log = $arguments
        if ($this.SecurityMode -eq 'SQL')
        {
            $log = $log.Replace($this.SAPwd.GetNetworkCredential().Password, '********')
        }

        if ($this.ProductKey -ne '')
        {
            $log = $log.Replace($this.ProductKey, '*****-*****-*****-*****-*****')
        }

        $logVars = @('AgtSvcAccount', 'SQLSvcAccount', 'FTSvcAccount', 'RSSvcAccount', 'ASSvcAccount', 'ISSvcAccount')
        foreach ($logVar in $logVars)
        {
            if ($this.$logVar)
            {
                $log = $log.Replace($this.$logVar.GetNetworkCredential().Password, '********')
            }
        }

        $arguments = $arguments.Trim()

        try
        {
            Write-Verbose -Message ($script:localizedData.SetupArguments -f $log)

            <#
                This handles when PsDscRunAsCredential is set, or running as the SYSTEM account (when
                PsDscRunAsCredential is not set).
            #>

            $startProcessParameters = @{
                FilePath     = $pathToSetupExecutable
                ArgumentList = $arguments
                Timeout      = $this.SetupProcessTimeout
            }

            $setupEndedInError = $false

            $processExitCode = Start-SqlSetupProcess @startProcessParameters

            $setupExitMessage = ($script:localizedData.SetupExitMessage -f $processExitCode)

            if ($processExitCode -eq 3010 -and -not $this.SuppressReboot)
            {
                $setupExitMessageRebootRequired = ('{0} {1}' -f $setupExitMessage, ($script:localizedData.SetupSuccessfulRebootRequired))

                Write-Verbose -Message $setupExitMessageRebootRequired

                # Setup ended with error code 3010 which means reboot is required.
                $global:DSCMachineStatus = 1
            }
            elseif ($processExitCode -ne 0)
            {
                $setupExitMessageError = ('{0} {1}' -f $setupExitMessage, ($script:localizedData.SetupFailed))
                Write-Warning $setupExitMessageError

                $setupEndedInError = $true
            }
            else
            {
                $setupExitMessageSuccessful = ('{0} {1}' -f $setupExitMessage, ($script:localizedData.SetupSuccessful))

                Write-Verbose -Message $setupExitMessageSuccessful
            }

            if ($this.ForceReboot -or (Test-PendingRestart))
            {
                if (-not ($this.SuppressReboot))
                {
                    Write-Verbose -Message $script:localizedData.Reboot

                    # Rebooting, so no point in refreshing the session.
                    $forceReloadPowerShellModule = $false

                    $global:DSCMachineStatus = 1
                }
                else
                {
                    Write-Verbose -Message $script:localizedData.SuppressReboot
                    $forceReloadPowerShellModule = $true
                }
            }
            else
            {
                $forceReloadPowerShellModule = $true
            }

            if ((-not $setupEndedInError) -and $forceReloadPowerShellModule)
            {
                <#
                    Force reload of SQLPS module in case a newer version of
                    SQL Server was installed that contains a newer version
                    of the SQLPS module, although if SqlServer module exist
                    on the target node, that will be used regardless.
                    This is to make sure we use the latest SQLPS module that
                    matches the latest assemblies in GAC, mitigating for example
                    issue #1151.
                #>
                Import-SQLPSModule -Force
            }

            # Do not test the installation if preparing the failover cluster. The service will not be running to query.
            if ($this.Action -notin $this.actionsWithoutServerAccess)
            {
                Write-Verbose "$($this.Action) selected. Testing the setup"
                if (-not $this.Test())
                {
                    $errorMessage = $script:localizedData.TestFailedAfterSet
                    New-InvalidResultException -Message $errorMessage
                }
            }
            else
            {
                Write-Verbose "$($this.Action) selected. Not testing the setup"
            }
        }
        catch
        {
            throw $_
        }
    }

    <#
        This method must be overridden by a resource. The parameter properties will
        contain the key properties.
    #>
    hidden [System.Collections.Hashtable] GetCurrentState([System.Collections.Hashtable] $properties)
    {
        if ($this.FeatureFlag)
        {
            Write-Verbose -Message ($script:localizedData.FeatureFlag -f ($this.FeatureFlag -join ''','''))
        }

        $InstanceName = $this.InstanceName.ToUpper()

        $getTargetResourceReturnValue = @{
            Action                     = $this.Action
            SourcePath                 = $this.SourcePath
            SourceCredential           = $this.SourceCredential
            InstanceName               = $InstanceName
            RSInstallMode              = $this.RSInstallMode
            FeatureFlag                = $this.FeatureFlag
            FailoverClusterNetworkName = $null
            Features                   = $null
            InstanceID                 = $null
            InstallSharedDir           = $null
            InstallSharedWOWDir        = $null
            InstanceDir                = $null
            SQLSvcAccountUsername      = $null
            SqlSvcStartupType          = $null
            AgtSvcAccountUsername      = $null
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
            FTSvcAccountUsername       = $null
            RSSvcAccountUsername       = $null
            RsSvcStartupType           = $null
            ASSvcAccountUsername       = $null
            AsSvcStartupType           = $null
            ASCollation                = $null
            ASSysAdminAccounts         = $null
            ASDataDir                  = $null
            ASLogDir                   = $null
            ASBackupDir                = $null
            ASTempDir                  = $null
            ASConfigDir                = $null
            ASServerMode               = $null
            ISSvcAccountUsername       = $null
            IsSvcStartupType           = $null
            FailoverClusterGroupName   = $null
            FailoverClusterIPAddress   = $null
            UseEnglish                 = $this.UseEnglish
        }

        <#
            $sqlHostName is later used by helper function to connect to the instance
            for the Database Engine or the Analysis Services.
        #>
        if ($this.Action -in @('CompleteFailoverCluster', 'InstallFailoverCluster', 'Addnode'))
        {
            $sqlHostName = $this.FailoverClusterNetworkName
        }
        else
        {
            $sqlHostName = Get-ComputerName
        }

        # Force drive list update, to pick up any newly mounted volumes
        $null = Get-PSDrive

        $SourcePath = [Environment]::ExpandEnvironmentVariables($this.SourcePath)

        if ($this.SourceCredential)
        {
            Connect-UncPath -RemotePath $SourcePath -SourceCredential $this.SourceCredential
        }

        $pathToSetupExecutable = Join-Path -Path $SourcePath -ChildPath 'setup.exe'

        Write-Verbose -Message ($script:localizedData.UsingPath -f $pathToSetupExecutable)

        $sqlVersion = GetFilePathMajorVersion($pathToSetupExecutable)

        if ($this.SourceCredential)
        {
            Disconnect-UncPath -RemotePath $SourcePath
        }

        $serviceNames = GetServiceNamesForInstance($InstanceName, $sqlVersion)

        $this.Features = ''

        # Get the name of the relevant services that are actually installed.
        $currentServiceNames = (Get-Service -Name @(
                $serviceNames.DatabaseService
                $serviceNames.AgentService
                $serviceNames.FullTextService
                $serviceNames.ReportService
                $serviceNames.AnalysisService
                $serviceNames.IntegrationService
            ) -ErrorAction 'SilentlyContinue').Name

        Write-Verbose -Message $script:localizedData.EvaluateDatabaseEngineFeature

        if ($serviceNames.DatabaseService -in $currentServiceNames)
        {
            Write-Verbose -Message $script:localizedData.DatabaseEngineFeatureFound

            $this.Features += 'SQLENGINE,'

            # Get current properties for the feature SQLENGINE.
            if ($this.Action -notin $this.actionsWithoutServerAccess)
            {
                $currentSqlEngineProperties = GetSqlEngineProperties($sqlHostName, $InstanceName)

                $getTargetResourceReturnValue.SQLSvcAccountUsername = $currentSqlEngineProperties.SQLSvcAccountUsername
                $getTargetResourceReturnValue.AgtSvcAccountUsername = $currentSqlEngineProperties.AgtSvcAccountUsername
                $getTargetResourceReturnValue.SqlSvcStartupType = $currentSqlEngineProperties.SqlSvcStartupType
                $getTargetResourceReturnValue.AgtSvcStartupType = $currentSqlEngineProperties.AgtSvcStartupType
                $getTargetResourceReturnValue.SQLCollation = $currentSqlEngineProperties.SQLCollation
                $getTargetResourceReturnValue.InstallSQLDataDir = $currentSqlEngineProperties.InstallSQLDataDir
                $getTargetResourceReturnValue.SQLUserDBDir = $currentSqlEngineProperties.SQLUserDBDir
                $getTargetResourceReturnValue.SQLUserDBLogDir = $currentSqlEngineProperties.SQLUserDBLogDir
                $getTargetResourceReturnValue.SQLBackupDir = $currentSqlEngineProperties.SQLBackupDir
                $getTargetResourceReturnValue.IsClustered = $currentSqlEngineProperties.IsClustered
                $getTargetResourceReturnValue.SecurityMode = $currentSqlEngineProperties.SecurityMode
            }


            $fullInstanceId = $this.GetFullInstanceId($InstanceName)
            $replicationRegistryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$fullInstanceId\ConfigurationState"
            Write-Verbose -Message ($script:localizedData.EvaluateReplicationFeature -f $replicationRegistryPath)

            # Check if Replication sub component is configured for this instance
            $isReplicationInstalled = TestIsReplicationFeatureInstalled($InstanceName)

            if ($isReplicationInstalled)
            {
                Write-Verbose -Message $script:localizedData.ReplicationFeatureFound

                $this.Features += 'REPLICATION,'
            }
            else
            {
                Write-Verbose -Message $script:localizedData.ReplicationFeatureNotFound
            }

            # Check if the Data Quality Services sub component is configured.
            $isDQInstalled = TestIsDQComponentInstalled($InstanceName, $sqlVersion)

            if ($isDQInstalled)
            {
                Write-Verbose -Message $script:localizedData.DataQualityServicesFeatureFound

                $this.Features += 'DQ,'
            }
            else
            {
                Write-Verbose -Message $script:localizedData.DataQualityServicesFeatureNotFound
            }

            # Get the instance ID
            $fullInstanceId = $this.GetFullInstanceId($InstanceName)
            $getTargetResourceReturnValue.InstanceID = $fullInstanceId.Split('.')[1]

            # Get the instance program path.
            $getTargetResourceReturnValue.InstanceDir = GetInstanceProgramPath($InstanceName)

            if ($sqlVersion -ge 13 -and $this.Action -notin $this.actionsWithoutServerAccess)
            {
                # Retrieve information about Tempdb database and its files.
                $currentTempDbProperties = GetTempDbProperties($sqlHostName, $InstanceName)

                $getTargetResourceReturnValue.SQLTempDBDir = $currentTempDbProperties.SQLTempDBDir
                $getTargetResourceReturnValue.SqlTempdbFileCount = $currentTempDbProperties.SqlTempdbFileCount
                $getTargetResourceReturnValue.SqlTempdbFileSize = $currentTempDbProperties.SqlTempdbFileSize
                $getTargetResourceReturnValue.SqlTempdbFileGrowth = $currentTempDbProperties.SqlTempdbFileGrowth
                $getTargetResourceReturnValue.SqlTempdbLogFileSize = $currentTempDbProperties.SqlTempdbLogFileSize
                $getTargetResourceReturnValue.SqlTempdbLogFileGrowth = $currentTempDbProperties.SqlTempdbLogFileGrowth
            }

            # Get all members of the sysadmin role.
            if ($this.Action -notin $this.actionsWithoutServerAccess)
            {
                $sqlSystemAdminAccounts = GetSqlRoleMembers('sysadmin', $sqlHostName, $InstanceName)
                $getTargetResourceReturnValue.SQLSysAdminAccounts = $sqlSystemAdminAccounts
            }

            if ($getTargetResourceReturnValue.IsClustered)
            {
                Write-Verbose -Message $script:localizedData.ClusterInstanceFound

                $currentClusterProperties = GetSqlClusterProperties($InstanceName)

                $getTargetResourceReturnValue.FailoverClusterNetworkName = $currentClusterProperties.FailoverClusterNetworkName
                $getTargetResourceReturnValue.FailoverClusterGroupName = $currentClusterProperties.FailoverClusterGroupName
                $getTargetResourceReturnValue.FailoverClusterIPAddress = $currentClusterProperties.FailoverClusterIPAddress
            }
            else
            {
                Write-Verbose -Message $script:localizedData.ClusterInstanceNotFound
            }
        }
        else
        {
            Write-Verbose -Message $script:localizedData.DatabaseEngineFeatureNotFound
        }

        Write-Verbose -Message $script:localizedData.EvaluateFullTextFeature

        if ($serviceNames.FullTextService -in $currentServiceNames)
        {
            Write-Verbose -Message $script:localizedData.FullTextFeatureFound

            $this.Features += 'FULLTEXT,'

            $getTargetResourceReturnValue.FTSvcAccountUsername = (
                GetServiceProperties($serviceNames.FullTextService)
            ).UserName
        }
        else
        {
            Write-Verbose -Message $script:localizedData.FullTextFeatureNotFound
        }

        Write-Verbose -Message $script:localizedData.EvaluateReportingServicesFeature

        if ($serviceNames.ReportService -in $currentServiceNames)
        {
            Write-Verbose -Message $script:localizedData.ReportingServicesFeatureFound

            $this.Features += 'RS,'

            $serviceReportingService = GetServiceProperties($serviceNames.ReportService)

            $getTargetResourceReturnValue.RSSvcAccountUsername = $serviceReportingService.UserName
            $getTargetResourceReturnValue.RsSvcStartupType = $serviceReportingService.StartupType
        }
        else
        {
            Write-Verbose -Message $script:localizedData.ReportingServicesFeatureNotFound
        }

        Write-Verbose -Message $script:localizedData.EvaluateAnalysisServicesFeature

        if ($serviceNames.AnalysisService -in $currentServiceNames)
        {
            Write-Verbose -Message $script:localizedData.AnalysisServicesFeatureFound

            $this.Features += 'AS,'

            $serviceAnalysisService = GetServiceProperties($serviceNames.AnalysisService)

            $getTargetResourceReturnValue.ASSvcAccountUsername = $serviceAnalysisService.UserName
            $getTargetResourceReturnValue.AsSvcStartupType = $serviceAnalysisService.StartupType

            $analysisServer = Connect-SQLAnalysis -ServerName $sqlHostName -InstanceName $InstanceName -FeatureFlag $this.FeatureFlag

            $getTargetResourceReturnValue.ASCollation = $analysisServer.ServerProperties['CollationName'].Value
            $getTargetResourceReturnValue.ASDataDir = $analysisServer.ServerProperties['DataDir'].Value
            $getTargetResourceReturnValue.ASTempDir = $analysisServer.ServerProperties['TempDir'].Value
            $getTargetResourceReturnValue.ASLogDir = $analysisServer.ServerProperties['LogDir'].Value
            $getTargetResourceReturnValue.ASBackupDir = $analysisServer.ServerProperties['BackupDir'].Value

            <#
                The property $analysisServer.ServerMode.value__ contains the
                server mode (aka deployment mode) value 0, 1 or 2. See DeploymentMode
                here https://docs.microsoft.com/en-us/sql/analysis-services/server-properties/general-properties.

                The property $analysisServer.ServerMode contains the display name of
                the property value__. See more information here
                https://msdn.microsoft.com/en-us/library/microsoft.analysisservices.core.server.servermode.aspx.
            #>
            $getTargetResourceReturnValue.ASServerMode = $analysisServer.ServerMode.ToString().ToUpper()

            $getTargetResourceReturnValue.ASSysAdminAccounts = [System.String[]] $analysisServer.Roles['Administrators'].Members.Name

            $serviceAnalysisServiceImagePath = Get-RegistryPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($serviceNames.AnalysisService)" -Name 'ImagePath'
            $foundAnalysisServiceConfigPath = $serviceAnalysisServiceImagePath -match '-s\s*"(.*)"'

            if ($foundAnalysisServiceConfigPath)
            {
                $getTargetResourceReturnValue.ASConfigDir = $matches[1]
            }
        }
        else
        {
            Write-Verbose -Message $script:localizedData.AnalysisServicesFeatureNotFound
        }

        Write-Verbose -Message $script:localizedData.EvaluateIntegrationServicesFeature

        if ($serviceNames.IntegrationService -in $currentServiceNames)
        {
            Write-Verbose -Message $script:localizedData.IntegrationServicesFeatureFound

            $this.Features += 'IS,'

            $serviceIntegrationService = GetServiceProperties($serviceNames.IntegrationService)

            $getTargetResourceReturnValue.ISSvcAccountUsername = $serviceIntegrationService.UserName
            $getTargetResourceReturnValue.IsSvcStartupType = $serviceIntegrationService.StartupType
        }
        else
        {
            Write-Verbose -Message $script:localizedData.IntegrationServicesFeatureNotFound
        }

        $installedSharedFeatures = GetInstalledSharedFeatures($sqlVersion)
        $this.Features += '{0},' -f ($installedSharedFeatures -join ',')

        if (TestIsSsmsInstalled($sqlVersion))
        {
            $this.Features += 'SSMS,'
        }

        if (TestIsSsmsAdvancedInstalled($sqlVersion))
        {
            $this.Features += 'ADV_SSMS,'
        }

        $this.Features = $this.Features.Trim(',')

        if ($this.Features)
        {
            $currentSqlSharedPaths = GetSqlSharedPaths($sqlVersion)

            $getTargetResourceReturnValue.InstallSharedDir = $currentSqlSharedPaths.InstallSharedDir
            $getTargetResourceReturnValue.InstallSharedWOWDir = $currentSqlSharedPaths.InstallSharedWOWDir
        }

        <#
            If no features was found, this will be set to en empty string. The variable
            $features is initially set to an empty string.
        #>
        $getTargetResourceReturnValue.Features = $this.Features

        # Remove properties which do not apply to this object type.
        #(Different Action types take different properties)
        $applicableProperties = $this | Get-Member -MemberType Property | Select-Object -ExpandProperty Name

        foreach ($propertyName in $getTargetResourceReturnValue.Keys) {
            if ($propertyName -notin $applicableProperties) {
                $getTargetResourceReturnValue.Remove($propertyName)
            }
        }

        return $getTargetResourceReturnValue
    }

    <#
    .SYNOPSIS
        Returns the first item value in the registry location provided in the Path parameter.

    .PARAMETER Path
        String containing the path to the registry.

    .NOTES
        The property values that is returned from Get-Item can for example look like this:

        Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\FEE2E540D20152D4597229B6CFBC0A69'

        Name                           Property
        ----                           --------
        FEE2E540D20152D4597229B6CFBC0A DCB13571726C2A64F9E1C79C020E9EA4 : C:\Program Files\Microsoft SQL Server\
        69                             52A7B04BB8030564B8245E7101DC4D9D : C:\Program Files\Microsoft SQL Server\
                                       17195C960C1F3104DB7F109DB81562E3 : C:\Program Files\Microsoft SQL Server\
                                       F07EA859E694B45439E22B819F70A40F : C:\Program Files\Microsoft SQL Server\
                                       3F9A28055EEA9364B97A1C6916AB3713 : C:\Program Files\Microsoft SQL Server\
    #>
    hidden [System.String] GetFirstPathValueFromRegistryPath([System.String] $Path)
    {
        $registryPropertyValue = $null
        $registryProperty = Get-Item -Path $Path -ErrorAction 'SilentlyContinue'

        if ($registryProperty)
        {
            $registryProperty = $registryProperty | Select-Object -ExpandProperty Property | Select-Object -First 1

            if ($registryProperty)
            {
                $registryPropertyValue = (Get-ItemProperty -Path $Path -Name $registryProperty).$registryProperty.TrimEnd('\')
            }
        }

        return $registryPropertyValue
    }

    <#
    .SYNOPSIS
        Returns the decimal representation of an IP Addresses.

    .PARAMETER IPAddress
        The IP Address to be converted.
    #>
    hidden [System.UInt32] ConvertToDecimal([System.Net.IPAddress] $IpAddress)
    {
        $i = 3
        [System.UInt32] $decimalIpAddress = 0
        $IpAddress.GetAddressBytes() | ForEach-Object -Process
        {
            $decimalIpAddress += $_ * [Math]::Pow(256, $i)
            $i--
        }
        return [System.UInt32] $decimalIpAddress
    }

    <#
    .SYNOPSIS
        Determines whether an IP Address is valid for a given network / subnet.

    .PARAMETER IPAddress
        IP Address to be checked.

    .PARAMETER NetworkID
        IP Address of the network identifier.

    .PARAMETER SubnetMask
        Subnet mask of the network to be checked.
    #>
    hidden [System.Boolean] TestIPAddress([System.Net.IPAddress] $IPAddress, [System.Net.IPAddress] $NetworkID, [System.Net.IPAddress] $SubnetMask)
    {
        # Convert all values to decimal
        $IPAddressDecimal = this.ConvertToDecimal($IPAddress)
        $NetworkDecimal = this.ConvertToDecimal($NetworkID)
        $SubnetDecimal = this.ConvertToDecimal($SubnetMask)

        # Determine whether the IP Address is valid for this network / subnet
        return (($IPAddressDecimal -band $SubnetDecimal) -eq ($NetworkDecimal -band $SubnetDecimal))
    }

    <#
        .SYNOPSIS
            Builds service account parameters for setup.

        .PARAMETER ServiceAccount
            Credential for the service account.

        .PARAMETER ServiceType
            Type of service account.
    #>
    hidden [System.Collections.Hashtable] GetServiceAccountParameters([System.Management.Automation.PSCredential] $ServiceAccount, [System.String] $ServiceType)
    {
        # Get the service account properties
        $accountParameters = Get-ServiceAccount -ServiceAccount $ServiceAccount
        $parameters = @{}

        # Assign the service type the account
        $parameters = @{
            "$($ServiceType)SVCACCOUNT" = $accountParameters.UserName
        }

        # Check to see if password is null
        if (![string]::IsNullOrEmpty($accountParameters.Password))
        {
            # Add the password to the hashtable
            $parameters.Add("$($ServiceType)SVCPASSWORD", $accountParameters.Password)
        }

        return $parameters
    }

    <#
        .SYNOPSIS
            Converts the start mode property returned by a Win32_Service CIM object to the resource properties *StartupType equivalent

        .PARAMETER StartMode
            The StartMode to convert.
    #>
    hidden [System.String] ConvertToStartupType([System.String] $StartMode)
    {
        if ($StartMode -eq 'Auto')
        {
            $StartMode = 'Automatic'
        }

        return $StartMode
    }

    <#
    .SYNOPSIS
        Returns an array of installed shared features.

    .PARAMETER SqlServerMajorVersion
        Specifies the major version of SQL Server, e.g. 14 for SQL Server 2017.

#>
    hidden [System.String[]] GetInstalledSharedFeatures([System.Int32] $SqlServerMajorVersion)
    {
        $sharedFeatures = @()

        $configurationStateRegistryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($SqlServerMajorVersion)0\ConfigurationState"

        # Check if Data Quality Client sub component is configured
        Write-Verbose -Message ($script:localizedData.EvaluateDataQualityClientFeature -f $configurationStateRegistryPath)

        $isDQCInstalled = (Get-ItemProperty -Path $configurationStateRegistryPath -ErrorAction SilentlyContinue).SQL_DQ_CLIENT_Full
        if ($isDQCInstalled -eq 1)
        {
            Write-Verbose -Message $script:localizedData.DataQualityClientFeatureFound
            $sharedFeatures += 'DQC'
        }
        else
        {
            Write-Verbose -Message $script:localizedData.DataQualityClientFeatureNotFound
        }

        # Check if Documentation Components "BOL" is configured
        Write-Verbose -Message ($script:localizedData.EvaluateDocumentationComponentsFeature -f $configurationStateRegistryPath)

        $isBOLInstalled = (Get-ItemProperty -Path $configurationStateRegistryPath -ErrorAction SilentlyContinue).SQL_BOL_Components
        if ($isBOLInstalled -eq 1)
        {
            Write-Verbose -Message $script:localizedData.DocumentationComponentsFeatureFound
            $sharedFeatures += 'BOL'
        }
        else
        {
            Write-Verbose -Message $script:localizedData.DocumentationComponentsFeatureNotFound
        }

        # Check if Client Tools Connectivity (and SQL Client Connectivity SDK) "CONN" is configured
        Write-Verbose -Message ($script:localizedData.EvaluateDocumentationComponentsFeature -f $configurationStateRegistryPath)

        $isConnInstalled = (Get-ItemProperty -Path $configurationStateRegistryPath -ErrorAction SilentlyContinue).Connectivity_Full
        if ($isConnInstalled -eq 1)
        {
            Write-Verbose -Message $script:localizedData.ClientConnectivityToolsFeatureFound
            $sharedFeatures += 'CONN'
        }
        else
        {
            Write-Verbose -Message $script:localizedData.ClientConnectivityToolsFeatureNotFound
        }

        # Check if Client Tools Backwards Compatibility "BC" is configured
        Write-Verbose -Message ($script:localizedData.EvaluateDocumentationComponentsFeature -f $configurationStateRegistryPath)

        $isBcInstalled = (Get-ItemProperty -Path $configurationStateRegistryPath -ErrorAction SilentlyContinue).Tools_Legacy_Full
        if ($isBcInstalled -eq 1)
        {
            Write-Verbose -Message $script:localizedData.ClientConnectivityBackwardsCompatibilityToolsFeatureFound
            $sharedFeatures += 'BC'
        }
        else
        {
            Write-Verbose -Message $script:localizedData.ClientConnectivityBackwardsCompatibilityToolsFeatureNotFound
        }

        # Check if Client Tools SDK "SDK" is configured
        Write-Verbose -Message ($script:localizedData.EvaluateDocumentationComponentsFeature -f $configurationStateRegistryPath)

        $isSdkInstalled = (Get-ItemProperty -Path $configurationStateRegistryPath -ErrorAction SilentlyContinue).SDK_Full
        if ($isSdkInstalled -eq 1)
        {
            Write-Verbose -Message $script:localizedData.ClientToolsSdkFeatureFound
            $sharedFeatures += 'SDK'
        }
        else
        {
            Write-Verbose -Message $script:localizedData.ClientToolsSdkFeatureNotFound
        }

        # Check if MDS sub component is configured for this server
        Write-Verbose -Message ($script:localizedData.EvaluateMasterDataServicesFeature -f $configurationStateRegistryPath)

        $isMDSInstalled = (Get-ItemProperty -Path $configurationStateRegistryPath -ErrorAction SilentlyContinue).MDSCoreFeature
        if ($isMDSInstalled -eq 1)
        {
            Write-Verbose -Message $script:localizedData.MasterDataServicesFeatureFound
            $sharedFeatures += 'MDS'
        }
        else
        {
            Write-Verbose -Message $script:localizedData.MasterDataServicesFeatureNotFound
        }

        return $sharedFeatures
    }

    <#
    .SYNOPSIS
        Get current properties for the feature SQLENGINE.

    .PARAMETER ServerName
        Specifies the server name where the database engine instance is located.

    .PARAMETER InstanceName
        Specifies the instance name. Use 'MSSQLSERVER' for the default instance.

    .PARAMETER DatabaseServiceName
        Specifies the name of the SQL Server Database Engine service.

    .PARAMETER AgentServiceName
        Specifies the name of the  SQL Server Agent service.

    .OUTPUTS
        An hashtable with properties.
#>
    hidden [System.Collections.Hashtable] GetSqlEngineProperties([System.String] $ServerName, [System.String] $InstanceName)
    {
        $serviceNames = GetServiceNamesForInstance($InstanceName)

        $databaseEngineService = GetServiceProperties($serviceNames.DatabaseService)
        $sqlAgentService = GetServiceProperties($serviceNames.AgentService)

        $sqlCollation = $null
        $isClustered = $null
        $installSQLDataDirectory = $null
        $sqlUserDatabaseDirectory = $null
        $sqlUserDatabaseLogDirectory = $null
        $sqlBackupDirectory = $null
        $securityMode = $null

        if ($this.Action -notin $this.actionsWithoutServerAccess)
        {
            $sqlServerObject = Connect-SQL -ServerName $ServerName -InstanceName $InstanceName

            $sqlCollation = $sqlServerObject.Collation
            $isClustered = $sqlServerObject.IsClustered
            $installSQLDataDirectory = $sqlServerObject.InstallDataDirectory
            $sqlUserDatabaseDirectory = $sqlServerObject.DefaultFile
            $sqlUserDatabaseLogDirectory = $sqlServerObject.DefaultLog
            $sqlBackupDirectory = $sqlServerObject.BackupDirectory

            if ($sqlServerObject.LoginMode -eq 'Mixed')
            {
                $securityMode = 'SQL'
            }
            else
            {
                $securityMode = 'Windows'
            }
        }

        return @{
            SQLSvcAccountUsername = $databaseEngineService.UserName
            AgtSvcAccountUsername = $sqlAgentService.UserName
            SqlSvcStartupType     = $databaseEngineService.StartupType
            AgtSvcStartupType     = $sqlAgentService.StartupType
            SQLCollation          = $sqlCollation
            IsClustered           = $isClustered
            InstallSQLDataDir     = $installSQLDataDirectory
            SQLUserDBDir          = $sqlUserDatabaseDirectory
            SQLUserDBLogDir       = $sqlUserDatabaseLogDirectory
            SQLBackupDir          = $sqlBackupDirectory
            SecurityMode          = $securityMode
        }
    }

    <#
        .SYNOPSIS
            Returns the SQL Server full instance ID.

        .PARAMETER InstanceName
            Specifies the instance name. Use 'MSSQLSERVER' for the default instance.

        .OUTPUTS
            A string containing the full instance ID, e.g. 'MSSQL12.INSTANCE'.
    #>
    hidden [System.String] GetFullInstanceId([System.String] $InstanceName)
    {

        $getRegistryPropertyValueParameters = @{
            Path = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
            Name = $InstanceName
        }

        return (Get-RegistryPropertyValue @getRegistryPropertyValueParameters)
    }

    <#
    .SYNOPSIS
        Evaluates if the feature Replication is installed.

    .PARAMETER InstanceName
        Specifies the instance name. Use 'MSSQLSERVER' for the default instance.

    .OUTPUTS
        A boolean value. $true if it is installed, $false if is it not.
#>
    hidden [System.Boolean] TestIsReplicationFeatureInstalled([System.String] $InstanceName)
    {
        $isReplicationInstalled = $false

        $fullInstanceId = $this.GetFullInstanceId($InstanceName)

        # Check if Replication sub component is configured for this instance
        $replicationRegistryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$fullInstanceId\ConfigurationState"

        $replicationInstallValue = Get-RegistryPropertyValue -Path $replicationRegistryPath -Name 'SQL_Replication_Core_Inst'

        if ($replicationInstallValue -eq 1)
        {
            $isReplicationInstalled = $true
        }

        return $isReplicationInstalled
    }

    <#
    .SYNOPSIS
        Evaluates if the Data Quality Services sub component is installed.

    .PARAMETER InstanceName
        Specifies the instance name. Use 'MSSQLSERVER' for the default instance.

    .PARAMETER SqlServerMajorVersion
        Specifies the major version of SQL Server, e.g. 14 for SQL Server 2017.

    .OUTPUTS
        A boolean value. $true if it is installed, $false if is it not.
#>
    hidden [System.Boolean] TestIsDQComponentInstalled([System.String] $InstanceName, [System.Int32] $SqlServerMajorVersion)
    {
        $isDQInstalled = $false

        $dataQualityServicesRegistryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($SqlServerMajorVersion)0\DQ\*"

        Write-Verbose -Message ($script:localizedData.EvaluateDataQualityServicesFeature -f $dataQualityServicesRegistryPath)

        # If the path exist then we assume the feature is installed.
        $dataQualityServiceRegistryValues = Get-ItemProperty -Path $dataQualityServicesRegistryPath -ErrorAction 'SilentlyContinue'

        if ($dataQualityServiceRegistryValues)
        {
            $isDQInstalled = $true
        }

        return $isDQInstalled
    }

    <#
        .SYNOPSIS
            Returns the SQL Server instance program path.

        .PARAMETER InstanceName
            Specifies the instance name. Use 'MSSQLSERVER' for the default instance.

        .OUTPUTS
            A string containing the path to the instance program folder, e.g.
            'C:\Program Files\Microsoft SQL Server'.
    #>
    hidden [System.String] GetInstanceProgramPath([System.String] $InstanceName)
    {
        $fullInstanceId = $this.GetFullInstanceId($InstanceName)

        # Check if Replication sub component is configured for this instance
        $registryPath = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\{0}\Setup' -f $fullInstanceId

        $instanceDirectory = Get-RegistryPropertyValue -Path $registryPath -Name 'SqlProgramDir'

        return $instanceDirectory.Trim('\')
    }

    <#
        .SYNOPSIS
            Get current properties for the TempDB in the database engine.

        .PARAMETER ServerName
            Specifies the server name where the database engine instance is located.

        .PARAMETER InstanceName
            Specifies the instance name. Use 'MSSQLSERVER' for the default instance.

        .OUTPUTS
            An hashtable with properties.
    #>
    hidden [System.Collections.Hashtable] GetTempDbProperties([System.String] $ServerName, [System.String] $InstanceName)
    {
        $sqlServerObject = Connect-SQL -ServerName $ServerName -InstanceName $InstanceName

        $databaseTempDb = $sqlServerObject.Databases['tempdb']

        # Tempdb data primary path.
        $sqlTempDBPrimaryFilePath = $databaseTempDb.PrimaryFilePath

        $primaryFileGroup = $databaseTempDb.FileGroups['PRIMARY']

        # Tempdb data files count.
        $sqlTempdbFileCount = $primaryFileGroup.Files.Count

        # Tempdb data files size.
        $sqlTempdbFileSize = (
            $primaryFileGroup.Files.Size |
                Measure-Object -Average
        ).Average / 1KB

        # Tempdb data files average growth in KB.
        $sqlTempdbAverageFileGrowthKB = (
            $primaryFileGroup.Files |
                Where-Object -FilterScript {
                    $_.GrowthType -eq 'KB'
                } | Select-Object -ExpandProperty 'Growth' | Measure-Object -Average
        ).Average

        # Tempdb data files average growth in Percent.
        $sqlTempdbFileGrowthPercent = (
            $primaryFileGroup.Files |
                Where-Object -FilterScript { $_.GrowthType -eq 'Percent' } |
                Select-Object -ExpandProperty 'Growth' |
                Measure-Object -Average
        ).Average

        $sqlTempdbFileGrowthMB = 0

        # Convert the KB value into MB.
        if ($sqlTempdbAverageFileGrowthKB)
        {
            $sqlTempdbFileGrowthMB = $sqlTempdbAverageFileGrowthKB / 1KB
        }

        $sqlTempdbFileGrowth = $sqlTempdbFileGrowthMB + $sqlTempdbFileGrowthPercent

        $tempdbLogFiles = $databaseTempDb.LogFiles

        # Tempdb log file size.
        $sqlTempdbLogFileSize = ($tempdbLogFiles.Size | Measure-Object -Average).Average / 1KB

        # Tempdb log file average growth in KB.
        $sqlTempdbAverageLogFileGrowthKB = (
            $tempdbLogFiles |
                Where-Object -FilterScript { $_.GrowthType -eq 'KB' } |
                Select-Object -ExpandProperty 'Growth' |
                Measure-Object -Average
        ).Average

        # Tempdb log file average growth in Percent.
        $sqlTempdbLogFileGrowthPercent = (
            $tempdbLogFiles |
                Where-Object -FilterScript { $_.GrowthType -eq 'Percent' } |
                Select-Object -ExpandProperty 'Growth' |
                Measure-Object -Average
        ).Average

        # Convert the KB value into MB.
        if ($sqlTempdbAverageLogFileGrowthKB)
        {
            $sqlTempdbLogFileGrowthMB = $sqlTempdbAverageLogFileGrowthKB / 1KB
        }
        else
        {
            $sqlTempdbLogFileGrowthMB = 0
        }

        # The sum of the average growth in KB and average growth in Percent.
        $sqlTempdbLogFileGrowth = $sqlTempdbLogFileGrowthMB + $sqlTempdbLogFileGrowthPercent

        return @{
            SQLTempDBDir           = $sqlTempDBPrimaryFilePath
            SqlTempdbFileCount     = $sqlTempdbFileCount
            SqlTempdbFileSize      = $sqlTempdbFileSize
            SqlTempdbFileGrowth    = $sqlTempdbFileGrowth
            SqlTempdbLogFileSize   = $sqlTempdbLogFileSize
            SqlTempdbLogFileGrowth = $sqlTempdbLogFileGrowth
        }
    }

    <#
        .SYNOPSIS
            Get the correct service named based on the instance name.

        .PARAMETER InstanceName
            Specifies the instance name. Use 'MSSQLSERVER' for the default instance.

        .PARAMETER SqlServerMajorVersion
            Specifies the major version of SQL Server, e.g. 14 for SQL Server 2017.
            If this is not passed the service name for Integration Services cannot
            be determined and will return $null.

        .OUTPUTS
            An hashtable with the service names.
    #>
    hidden [System.Collections.Hashtable] GetServiceNamesForInstance([System.String] $InstanceName, [System.Int32] $SqlServerMajorVersion)
    {
        $serviceNames = @{}

        if ($InstanceName -eq 'MSSQLSERVER')
        {
            $serviceNames.DatabaseService = 'MSSQLSERVER'
            $serviceNames.AgentService = 'SQLSERVERAGENT'
            $serviceNames.FullTextService = 'MSSQLFDLauncher'
            $serviceNames.ReportService = 'ReportServer'
            $serviceNames.AnalysisService = 'MSSQLServerOLAPService'
        }
        else
        {
            $serviceNames.DatabaseService = 'MSSQL${0}' -f $InstanceName
            $serviceNames.AgentService = 'SQLAgent${0}' -f $InstanceName
            $serviceNames.FullTextService = 'MSSQLFDLauncher${0}' -f $InstanceName
            $serviceNames.ReportService = 'ReportServer${0}' -f $InstanceName
            $serviceNames.AnalysisService = 'MSOLAP${0}' -f $InstanceName
        }

        if ($PSBoundParameters.ContainsKey('SqlServerMajorVersion'))
        {
            $serviceNames.IntegrationService = 'MsDtsServer{0}0' -f $SqlServerMajorVersion
        }
        else
        {
            $serviceNames.IntegrationService = $null
        }

        return $serviceNames
    }

    <#
    .SYNOPSIS
        Get members that are part of a SQL system role.

    .PARAMETER ServerName
        Specifies the server name where the database engine instance is located.

    .PARAMETER InstanceName
        Specifies the instance name. Use 'MSSQLSERVER' for the default instance.

    .PARAMETER RoleName
        Specifies the name of the role to get the members for.

    .OUTPUTS
        An hashtable with properties containing the current cluster values.
#>
    hidden [System.Object[]] GetSqlRoleMembers([System.String] $ServerName, [System.String] $InstanceName, [System.String] $RoleName)
    {
        $sqlServerObject = Connect-SQL -ServerName $ServerName -InstanceName $InstanceName

        $membersOfSysAdminRole = @($sqlServerObject.Roles[$RoleName].EnumMemberNames())

        # Make sure to alway return an array of object even if there is only one value.
        return , $membersOfSysAdminRole
    }

    <#
    .SYNOPSIS
        Get current SQL Server cluster properties.

    .PARAMETER InstanceName
        Specifies the instance name. Use 'MSSQLSERVER' for the default instance.

    .OUTPUTS
        An hashtable with properties.
#>
    hidden [System.Collections.Hashtable] GetSqlClusterProperties([System.String] $InstanceName)
    {
        $getCimInstanceParameters = @{
            Namespace = 'root/MSCluster'
            ClassName = 'MSCluster_Resource'
            Filter    = "Type = 'SQL Server'"
        }

        $clusteredSqlInstance = Get-CimInstance @getCimInstanceParameters |
            Where-Object -FilterScript {
                $_.PrivateProperties.InstanceName -eq $InstanceName
            }

        if (-not $clusteredSqlInstance)
        {
            $errorMessage = $script:localizedData.FailoverClusterResourceNotFound -f $InstanceName
            New-ObjectNotFoundException -Message $errorMessage
        }

        Write-Verbose -Message $script:localizedData.FailoverClusterResourceFound

        $clusteredSqlGroup = $clusteredSqlInstance |
            Get-CimAssociatedInstance -ResultClassName 'MSCluster_ResourceGroup'

        $clusteredSqlNetworkName = $clusteredSqlGroup |
            Get-CimAssociatedInstance -ResultClassName 'MSCluster_Resource' |
            Where-Object -FilterScript {
                $_.Type -eq 'Network Name'
            }

        $clusteredSqlIPAddress = $clusteredSqlNetworkName |
            Get-CimAssociatedInstance -ResultClassName 'MSCluster_Resource' |
            Where-Object -FilterScript {
                $_.Type -eq 'IP Address'
            }

        return @{
            FailoverClusterNetworkName = $clusteredSqlNetworkName.PrivateProperties.DnsName
            FailoverClusterGroupName   = $clusteredSqlGroup.Name
            FailoverClusterIPAddress   = $clusteredSqlIPAddress.PrivateProperties.Address
        }
    }

    <#
    .SYNOPSIS
        Get current properties for a service. Returns the user name that starts
        the service, and the startup type.

    .PARAMETER ServiceName
        Specifies the service name.

    .OUTPUTS
        An hashtable with properties.
    #>
    hidden [System.Collections.Hashtable] GetServiceProperties([System.String] $ServiceName)
    {
        $cimInstance = Get-CimInstance -ClassName 'Win32_Service' -Filter ("Name = '{0}'" -f $ServiceName)

        return @{
            UserName    = $cimInstance.StartName
            StartupType = ConvertToStartupType($cimInstance.StartMode)
        }
    }

    <#
    .SYNOPSIS
        Evaluates if the SQL Server Management Studio for the specified SQL Server
        major version is installed.

    .PARAMETER SqlServerMajorVersion
        Specifies the major version of SQL Server, e.g. 14 for SQL Server 2017.

    .OUTPUTS
        A boolean value. $true if it is installed, $false if is it not.
#>
    hidden [System.Boolean] TestIsSsmsInstalled([System.Int32] $SqlServerMajorVersion)
    {
        $isInstalled = $false
        $productIdentifyingNumber = $null

        switch ($SqlServerMajorVersion)
        {
            10
            {
                <#
                Verify if SQL Server Management Studio 2008 or SQL Server Management
                Studio 2008 R2 (major version 10) is installed.
            #>
                $productIdentifyingNumber = '{72AB7E6F-BC24-481E-8C45-1AB5B3DD795D}'
            }

            11
            {
                # Verify if SQL Server Management Studio 2012 (major version 11) is installed.
                $productIdentifyingNumber = '{A7037EB2-F953-4B12-B843-195F4D988DA1}'
            }

            12
            {
                # Verify if SQL Server Management Studio 2012 (major version 11) is installed.
                $productIdentifyingNumber = '{75A54138-3B98-4705-92E4-F619825B121F}'
            }

            default
            {
                # If an unsupported version was passed, make sure the function returns $false.
                $productIdentifyingNumber = $null
            }
        }

        if ($productIdentifyingNumber)
        {
            $registryUninstallPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall'

            $registryObject = Get-ItemProperty -Path (
                Join-Path -Path $registryUninstallPath -ChildPath $productIdentifyingNumber
            ) -ErrorAction 'SilentlyContinue'

            if ($registryObject)
            {
                $isInstalled = $true
            }
        }

        return $isInstalled
    }

    <#
    .SYNOPSIS
        Evaluates if the SQL Server Management Studio Advanced for the specified
        SQL Server major version is installed.

    .PARAMETER SqlServerMajorVersion
        Specifies the major version of SQL Server, e.g. 14 for SQL Server 2017.

    .OUTPUTS
        A boolean value. $true if it is installed, $false if is it not.
    #>
    hidden [System.Boolean] TestIsSsmsAdvancedInstalled([System.Int32] $SqlServerMajorVersion)
    {
        $isInstalled = $false
        $productIdentifyingNumber = $null

        switch ($SqlServerMajorVersion)
        {
            10
            {
                <#
                    Evaluating if SQL Server Management Studio Advanced 2008 or
                    SQL Server Management Studio Advanced 2008 R2 (major version 10)
                    is installed.
                #>
                $productIdentifyingNumber = '{B5FE23CC-0151-4595-84C3-F1DE6F44FE9B}'
            }

            11
            {
                <#
                    Evaluating if SQL Server Management Studio Advanced 2012 (major
                    version 11) is installed.
                #>
                $productIdentifyingNumber = '{7842C220-6E9A-4D5A-AE70-0E138271F883}'
            }

            12
            {
                <#
                    Evaluating if SQL Server Management Studio Advanced 2014 (major
                    version 12) is installed.
                #>
                $productIdentifyingNumber = '{B5ECFA5C-AC4F-45A4-A12E-A76ABDD9CCBA}'
            }

            default
            {
                <#
                    If an unsupported version was passed, make sure the function
                    returns $false.
                #>
                $productIdentifyingNumber = $null
            }
        }

        if ($productIdentifyingNumber)
        {
            $registryUninstallPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall'

            $registryObject = Get-ItemProperty -Path (
                Join-Path -Path $registryUninstallPath -ChildPath $productIdentifyingNumber
            ) -ErrorAction 'SilentlyContinue'

            if ($registryObject)
            {
                $isInstalled = $true
            }
        }

        return $isInstalled
    }

    <#
    .SYNOPSIS
        Get current SQL Server shared paths for the instances.

    .OUTPUTS
        An hashtable with properties.
    #>
    hidden [System.Collections.Hashtable] GetSqlSharedPaths([System.Int32] $SqlServerMajorVersion)
    {

        $installSharedDir = $null
        $installSharedWOWDir = $null
        $registryKeySharedDir = $null
        $registryKeySharedWOWDir = $null

        $registryInstallerComponentsPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components'

        switch ($SqlServerMajorVersion)
        {
            { $_ -in ('10', '11', '12', '13', '14', '15') }
            {
                $registryKeySharedDir = 'FEE2E540D20152D4597229B6CFBC0A69'
                $registryKeySharedWOWDir = 'A79497A344129F64CA7D69C56F5DD8B4'
            }
        }

        if ($registryKeySharedDir)
        {
            $installSharedDir = this.GetFirstPathValueFromRegistryPath((Join-Path -Path $registryInstallerComponentsPath -ChildPath $registryKeySharedDir))
        }

        if ($registryKeySharedWOWDir)
        {
            $installSharedWOWDir = this.GetFirstPathValueFromRegistryPath((Join-Path -Path $registryInstallerComponentsPath -ChildPath $registryKeySharedWOWDir))
        }

        return @{
            InstallSharedDir    = $installSharedDir
            InstallSharedWOWDir = $installSharedWOWDir
        }
    }
}
