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