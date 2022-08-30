Function Write-Log
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $LogMessage,
        [Parameter(Mandatory=$False)]
        [switch]
        $LogToFile,
        [Parameter(Mandatory=$False)]
        [string]
        $LogPath,
        [Parameter(Mandatory=$False)]
        [string]
        $LogLevel
    )

    if ($LogToFile)
    {
        Add-Content -Path $LogPath -Value "$((Get-Date).ToString("yyyy/MM/dd-hh:mm:ss")) - $LogMessage"
    }
    else
    {
        Write-Verbose "$((Get-Date).ToString("yyyy/MM/dd-hh:mm:ss")) - $LogMessage"
    }
}

Function Check-ConcurrentSessions
{
    while ((get-process powershell).count -gt $MaxConcurrentSessions)
    {
        if ($Waiting % 10 -eq 0)
        {
            write-verbose "Waiting for other processes to complete"
        }
        $Waiting++
        start-sleep 1
    }
}

Function ConvertFrom-FixedWidthTable
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string[]]
        $Table
    )

    $pTable = @()
    $Headers = @()

    #Find the first line that looks like the table headers
    #We'll see how it goes
    $HeaderLine = 0
    foreach ($Line in $Table)
    {
        if ($Line -match "\w{1,}\s{2,}\w{1,}")
        {
            $Headers = $Line -split "\s{2,}"
            break
        }
        $HeaderLine++
    }

    $Columns = @{}

    foreach ($Header in $Headers)
    {
        $Columns += @{$Header = $Table[$HeaderLine].indexof($Header)}
    }

    $tofs = $ofs
    $ofs = ""       

    foreach ($Entry in $Table[2..($Table.count - 1)])
    {
        $Row = new-object PSCustomObject

        for ($x = 0; $x -lt $Headers.count; $x++)
        {
            $Header = $Headers[$x]

            if ($x -eq ($Headers.count - 1))
            {
                $Next = $Entry.length - 1
            }
            else {
                $Next = ([int]$Columns[$Headers[$x + 1]] - 1)
            }

            if ($Entry.length -gt $Columns[$Header])
            {
                #$Columns[$Header]
                $Value = "$($Entry[$Columns[$Header]..$Next])"
            }
            else 
            {
                $Value = $null    
            }

            $Row | add-member -type NoteProperty -name $Header -value $Value -force
        }

        $pTable += $Row
    }

    $ofs = $tofs

    return $pTable
}

Function Check-ModuleDependencies
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string[]]
        $Modules
    )

    $ModulesExist = $True

    foreach ($Module in $Modules)
    {
        $ModulesExist = $ModulesExist -and ((Get-Module $Module) -ne $null)
    }

    return $ModulesExist
}


## Everything below this line is going to be replaced with a significantly better C# module eventually

Function Get-NetworkRange
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $Network,
        [Parameter(Mandatory=$true)]
        [string]
        $Mask
    )
    $tofs = $ofs
    $ofs = ""

    $Ranges = @{}

    for ($Octet = 0; $Octet -le 3; $Octet++)
    {
        $OctStart = $Octet * 8
        $OctEnd   = (($Octet + 1) * 8) - 1

        $StartBin = "$($Network[$OctStart..$OctEnd])"
        $EndBin   = "$(for ($x = $OctStart; $x -le $OctEnd; $x++)

        {
            if ($Mask[$x] -eq "0")
            {
                "1"
            }
            else {
                $Network[$x]
            }
        })"
        Write-Debug "StartBin - $StartBin"
        Write-Debug "EndBin - $EndBin"
        $Ranges += @{$Octet = @([convert]::toInt32($StartBin,2), [convert]::toInt32($EndBin,2))}
    }
    $ofs = $tofs
    return $Ranges
}


function Get-DNSHostname
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    return (nslookup $ComputerName | where {$_ -match "name:\s*\S*"} | %{$_ -replace "name:\s*(\S*)",'$1'})
}

function Test-HostStatus
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        [Parameter(Mandatory=$false)]
        [string]$Timeout = "100",
        [Parameter(Mandatory=$false)]
        [string]$PingCount = "2"
    )

    $ping = invoke-expression "ping -w $Timeout -n $PingCount $ComputerName"

    return ($ping -match "bytes=")
}

function New-HostDetailsObject
{
    $HostDetails = [PSCustomObject]@{
    "Name" = $null
    "DNSHostname" = $null
    "Active" = $null
    "Services" = $null}
    return $HostDetails
}

function Get-HostDetails
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        [switch]$BasicServices
    )

    $HostDetails = New-HostDetailsObject
    $HostDetails.Name = $ComputerName
    $HostDetails.DNSHostname = Get-DNSHostname $ComputerName
    $HostDetails.Active = Test-HostStatus $ComputerName 

    if ($HostDetails.Active)
    {
        if ($BasicServices)
        {
            $Services = @()
            foreach ($Service in $BasicServicePorts)
            {
                $ServiceStatus = new-object PSCustomObject
                $ServiceStatus | add-member -type NoteProperty -name Port -value $Service
                $ServiceStatus | add-member -type NoteProperty -name Status -value (Test-NetConnection -ComputerName $ComputerName -Port $Service -Verbose:$False)
                $Services += $ServiceStatus
            }
        }

        $HostDetails.Services = $Services
    }
    else {
        
    }
    return $HostDetails
}


Function Search-Network
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $Network,
        [switch]
        $StandardGateways
    )

    if ($Network -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}")
    {
        $tofs = $ofs
        $ofs = ""
        write-verbose "scanning $Network"
        $ScanInstance = [guid]::NewGuid()

        $NetworkSplit = ($Network -split "/")
        
        $NetworkBase = $NetworkSplit[0] -split "\."
        $NetworkMask = $NetworkSplit[1]

        $BinaryBase = "$($NetworkBase | %{("{0,8}" -f [convert]::ToString([int32]$_,2)) -replace " ","0"})"
        $BinaryMask = "$("1"*$NetworkMask)$("0"*(32-$NetworkMask))"
        Write-Debug "Binary Base - $BinaryBase"
        Write-Debug "Binary Mask - $BinaryMask"
        for ($x = 0; $x -lt 32; $x++)
        {
            if (($BinaryMask[$x] -eq "0") -and ($BinaryBase[$x] -eq "1"))
            {
                throw "invalid network provided"
            }
        }

        $hosts = @()

        $ScanRange = Get-NetworkRange $BinaryBase $BinaryMask
        $Octets = @($ScanRange[0][0],$ScanRange[1][0],$ScanRange[2][0],$ScanRange[3][0])
        Write-Debug "ScanRange Start- $($ScanRange[0][0]).$($ScanRange[1][0]).$($ScanRange[2][0]).$($ScanRange[3][0])"
        Write-Debug "ScanRange Start- $($ScanRange[0][1]).$($ScanRange[1][1]).$($ScanRange[2][1]).$($ScanRange[3][1])"
        $ScanJobs = @()
        for ($Octets[0] = $ScanRange[0][0]; $Octets[0] -le $ScanRange[0][1]; $Octets[0]++)
        {

            for ($Octets[1] = $ScanRange[1][0]; $Octets[1] -le $ScanRange[1][1]; $Octets[1]++)
            {
                for ($Octets[2] = $ScanRange[2][0]; $Octets[2] -le $ScanRange[2][1]; $Octets[2]++)
                {
                    $StandardGateway = "$($Octets[0]).$($Octets[1]).$($Octets[2]).254"
                    if (($StandardGateways -and (Test-HostStatus $StandardGateway)) -or (-not $StandardGateways))
                    {
                        for ($Octets[3] = $ScanRange[3][0]; $Octets[3] -le $ScanRange[3][1]; $Octets[3]++)
                        {
                            #Check-ConcurrentSessions
                            $ComputerName = "$($Octets[0]).$($Octets[1]).$($Octets[2]).$($Octets[3])"
                            $OutputFile = "C:\Temp\NetworkTools\$($ScanInstance)_ping_$ComputerName.txt"
                            Write-Debug "$ComputerName"
                            $ScanJobs += $OutputFile
                            start-process "C:\windows\system32\cmd.exe" -argumentlist "/C ping $ComputerName" -RedirectStandardOutput $OutputFile -NoNewWindow
                            #start-job -name "$ScanInstance_ping_$JobInstance" -scriptblock {Test-HostStatus $args[0]} -ArgumentList $ComputerName
                        }                        
                    }
                    else {
                        Write-Verbose "$StandardGateway does not appear to be active, skipping network"
                    }
                }
            }
        }

        $ScannedHosts = 0

        while ((gci C:\Temp\NetworkTools | where {{$_.FullName -match "$($ScanInstance)_ping"} -and $_.length -eq 0}).count -lt $ScanJobs.count)
        {
            if ($Waiting % 10 -eq 0)
            {
                write-verbose "Waiting for the ping jobs to complete"
            }
            $Waiting++
            start-sleep 1           
        }

        foreach ($ScanJob in $ScanJobs)
        {   
            Write-Debug "JobFile - $ScanJob"
            $JobDeets = get-content $ScanJob
            Write-Debug "JobResults - $JobDeets"
            $ignore = $JobDeets | %{$_ -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"}
            Write-Debug "Matches - $ignore"
            Write-Debug "IP Addresses - $($Matches[0])"
            $ComputerName = $Matches[0]
            Write-Debug "Bytes Fields = $($JobDeets  | %{$_ -match "bytes="})"
            if ($JobDeets  | %{$_ -match "bytes="})
            {
                Write-Verbose "$ComputerName is online"
                Write-Verbose "Starting job to scan $ComputerName"
                $JobInstance = [guid]::NewGuid()
                $ignore = start-job -name "$($ScanInstance)_check_$JobInstance" -scriptblock {Get-HostDetails $args[0] -BasicServices} -ArgumentList $ComputerName
            }     
        }

        $ofs = $tofs
        $Waiting = 0
        while ((Get-Job) | where {$_.state -eq "Running" -and $_.name -match $ScanInstance})
        {   
            if ($Waiting % 10 -eq 0)
            {
                write-verbose "Waiting for the scan jobs to complete"
            }
            $Waiting++
            start-sleep 1
        }

        $hosts += (Get-Job) | where {$_.name -match "$($ScanInstance)_check" } | receive-job

    }
    else 
    {
        Write-Error "Invalid Error provided"
    }

    return $hosts
}

Function Invoke-VariableJSONSave
{
    Param
    (
        $ModuleName,
        $SavePath,
        $Variables
    )

    Write-Verbose "Encrypting all senstitive information"

    $OutVars = @()

    foreach ($Variable in $Variables)
    {
        Write-Debug $Variable.name
        if ($Variable.value -ne $null)
        {
            Write-Debug "$($Variable.value.GetType().tostring())"
            if ($Variable.value.GetType().ToString() -eq "System.Management.Automation.PSCredential")
            {
                Write-Debug "Credential - $($Variable.name) - found, encrypting"
                $NewCredObject = [PSCustomObject]@{
                    "Name" = $Variable.name
                    "Description" = $Variable.Description
                    "Value" = [PSCustomObject]@{
                        "username" = $Variable.value.username
                        "SecurePass" = ($Variable.value.password | ConvertFrom-SecureString)
                    }
                    "Visibility" = $Variable.Visibility
                    "Module" = $Variable.Module
                    "ModuleName" = $Variable.ModuleName
                    "Options" = $Variable.Options
                    "Attributes" = $Variable.Attributes
                }
                $OutVars += $NewCredObject
                Write-Debug $OutVars.count
            }
            elseif ($Variable.name -match "Token")
            {
                if ($Variable.value -ne "")
                {
                    Write-Debug "API Token - $($Variable.name) - found, encrypting"
                    $NewTokenObject = [PSCustomObject]@{
                        "Name" = "SecureToken-$($_.name)"
                        "Description" = $Variable.Description
                        "Value" = (ConvertTo-SecureString -AsPlainText $Variable.Value -Force | ConvertFrom-SecureString)
                        "Visibility" = $Variable.Visibility
                        "Module" = $Variable.Module
                        "ModuleName" = $Variable.ModuleName
                        "Options" = $Variable.Options
                        "Attributes" = $Variable.Attributes
                    }
                    $OutVars += $NewTokenObject
                    Write-Debug $OutVars.count
                }
            }
            elseif ($Variable.name -match "APIKey")
            {
                if ($Variable.value -ne $null)
                {
                    Write-Debug "API Token - $($Variable.name) - found, encrypting"
                    $NewTokenObject = [PSCustomObject]@{
                        "Name" = $Variable.name
                        "Description" = $Variable.Description
                        "Value" = [PSCustomObject]@{
                            "ID" = $Variable.value.id
                            "SecureKey" = (ConvertTo-SecureString -AsPlainText $Variable.Value.key -Force | ConvertFrom-SecureString)
                        }
                        "Visibility" = $Variable.Visibility
                        "Module" = $Variable.Module
                        "ModuleName" = $Variable.ModuleName
                        "Options" = $Variable.Options
                        "Attributes" = $Variable.Attributes
                    }
                    $OutVars += @($NewTokenObject)
                    Write-Debug $OutVars.count
                }
            }
            else {
                $OutVars += @($Variable)

                Write-Debug $OutVars.count
            }

        }
    }

    Write-Verbose "Saving variables to $SavePath"

    $OutVars | ConvertTo-Json -depth 10 | Set-Content $SavePath
}

Function Invoke-VariableJSONLoad
{
    Param
    (
        $LoadPath
    )

    Write-Verbose "Loading all variables from $LoadPath"
    $JsonContent = get-content $LoadPath
    if ($JsonContent -ne "")
    {
        $JsonContent | Write-Debug 
        $Variables = $JsonContent | convertfrom-json 
    }

    foreach ($Variable in $Variables)
    {
        if ($Variable.Name -match "SecureToken")
        {
            $TokenSecure = (ConvertTo-SecureString $Variable.value)

            $Variable.value = (New-Object System.Management.Automation.PsCredential("SecureToken", $TokenSecure)).GetNetworkCredential().Password

            $Variable = $Variable | select @{Name="Name";Expression={$_.name -replace "SecureToken-",""}},Value
        }
        elseif (($Variable.value | gm).name -contains "SecurePass")
        {
            $Variable.value = (New-Object System.Management.Automation.PsCredential($Variable.value.username, (ConvertTo-SecureString ($Variable.value.SecurePass))))
        }
        elseif ($Variable.name -match "APIKey")
        {

            $SecureKey = ConvertTo-SecureString $Variable.Value.SecureKey

            Write-Debug $SecureKey

            $APIKey = [PSCustomObject]@{
                "ID" = $Variable.value.id
                "Key" = (New-Object System.Management.Automation.PsCredential("SecureToken",$SecureKey)).GetNetworkCredential().Password
            }

            $Variable.value = $APIKey
        }
    }

    return $Variables
}