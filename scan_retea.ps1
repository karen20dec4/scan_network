<# 
Network Scanner pentru Windows
Port PowerShell dupa scan_retea.sh, cu config JSON si fallback fara Nmap.

Utilizare:
  .\scan_retea.ps1
  .\scan_retea.ps1 -Scan
  .\scan_retea.ps1 -Interactive
  .\scan_retea.ps1 -Config
  .\scan_retea.ps1 -History
  .\scan_retea.ps1 -FlushArp
  .\scan_retea.ps1 -Repair
#>

[CmdletBinding()]
param(
    [switch]$Scan,
    [switch]$Interactive,
    [switch]$Config,
    [switch]$History,
    [switch]$FlushArp,
    [switch]$Repair,
    [switch]$InstallNmap,
    [string]$Subnet,
    [switch]$NoColor
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$Script:ScriptDir = Split-Path -Parent $PSCommandPath
$Script:ConfigFile = Join-Path $Script:ScriptDir "retea_config.windows.json"
$Script:LegacyConfigFile = Join-Path $Script:ScriptDir "retea_config.conf"
$Script:LogFile = Join-Path $Script:ScriptDir "status_retea_windows.log"
$Script:HistoryFile = Join-Path $Script:ScriptDir "retea_history.windows.jsonl"
$Script:ScanCache = @{
    Time = [datetime]::MinValue
    MacToIP = @{}
}

$Script:State = @{
    Subnet = "192.168.1.0/24"
    Calculatoare = @{}
    Ignora = @{}
}

function Test-CommandExists {
    param([Parameter(Mandatory)][string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-NmapInstallHint {
    if (Test-CommandExists "winget") {
        return "winget install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements"
    }
    if (Test-CommandExists "choco") {
        return "choco install nmap -y"
    }
    if (Test-CommandExists "scoop") {
        return "scoop install nmap"
    }
    return "Instaleaza Nmap de la https://nmap.org/download.html sau instaleaza winget/Chocolatey/Scoop."
}

function Update-ProcessPath {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $paths = New-Object System.Collections.Generic.List[string]

    foreach ($pathValue in @($machinePath, $userPath, $env:Path)) {
        if ([string]::IsNullOrWhiteSpace($pathValue)) {
            continue
        }

        foreach ($entry in ($pathValue -split ";")) {
            $clean = $entry.Trim()
            if ($clean -and -not $paths.Contains($clean)) {
                $paths.Add($clean)
            }
        }
    }

    foreach ($candidate in @(
        "$env:ProgramFiles\Nmap",
        "${env:ProgramFiles(x86)}\Nmap"
    )) {
        if ($candidate -and (Test-Path (Join-Path $candidate "nmap.exe")) -and -not $paths.Contains($candidate)) {
            $paths.Add($candidate)
        }
    }

    $env:Path = ($paths -join ";")
}

function Install-Nmap {
    Write-Header "INSTALARE NMAP"
    Update-ProcessPath

    if (Test-CommandExists "nmap") {
        Write-Color "[OK] Nmap este deja instalat." Green
        try {
            & nmap --version | Select-Object -First 1 | ForEach-Object { Write-Host $_ }
        } catch {
            # Versiunea nu este critica.
        }
        Write-Separator
        return $true
    }

    $commandText = Get-NmapInstallHint
    Write-Color "Nmap ajuta la detectie mai buna: vendor MAC, hosturi active si porturi comune." Cyan
    Write-Host "Comanda propusa:"
    Write-Color "  $commandText" White
    Write-Host ""

    if ($commandText -match "^Instaleaza") {
        Write-Color "[WARN] Nu am gasit winget, Chocolatey sau Scoop pe sistem." Yellow
        Write-Host $commandText
        Write-Separator
        return $false
    }

    $confirm = Read-Host "Instalez Nmap acum? [y/N]"
    if ($confirm -notmatch "^[Yy]") {
        Write-Color "[INFO] Instalare anulata. Scriptul va folosi fallback ping + ARP." Yellow
        Write-Separator
        return $false
    }

    try {
        if ($commandText.StartsWith("winget ")) {
            & winget install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements
        } elseif ($commandText.StartsWith("choco ")) {
            & choco install nmap -y
        } elseif ($commandText.StartsWith("scoop ")) {
            & scoop install nmap
        }

        Update-ProcessPath

        if (Test-CommandExists "nmap") {
            Write-Color "[OK] Nmap instalat si detectat." Green
            Write-Separator
            return $true
        }

        Write-Color "[WARN] Instalarea pare terminata, dar nmap nu este in PATH nici dupa reincarcare." Yellow
        Write-Color "Verifica instalarea sau redeschide PowerShell, apoi ruleaza din nou scriptul." Yellow
        Write-Separator
        return $false
    } catch {
        Write-Color "[ERR] Instalarea a esuat: $($_.Exception.Message)" Red
        Write-Separator
        return $false
    }
}

function Write-Color {
    param(
        [Parameter(Mandatory)][string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::Gray,
        [switch]$NoNewline
    )

    if ($NoColor) {
        if ($NoNewline) { Write-Host $Text -NoNewline } else { Write-Host $Text }
        return
    }

    if ($NoNewline) {
        Write-Host $Text -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $Text -ForegroundColor $Color
    }
}

function Write-Header {
    param([Parameter(Mandatory)][string]$Title)

    $line = "=" * 70
    Write-Color $line Cyan
    Write-Color ("{0,-70}" -f $Title) White
    Write-Color ("{0,-70}" -f (Get-Date -Format "dd-MM-yyyy HH:mm:ss")) DarkGray
    Write-Color $line Cyan
}

function Write-Separator {
    Write-Color ("-" * 70) DarkGray
}

function ConvertTo-Hashtable {
    param($InputObject)

    $table = @{}
    if ($null -eq $InputObject) {
        return $table
    }

    if ($InputObject -is [hashtable]) {
        foreach ($key in $InputObject.Keys) {
            $table[$key] = $InputObject[$key]
        }
        return $table
    }

    foreach ($property in $InputObject.PSObject.Properties) {
        $table[$property.Name] = $property.Value
    }
    return $table
}

function Normalize-Mac {
    param([AllowNull()][string]$Mac)

    if ([string]::IsNullOrWhiteSpace($Mac)) {
        return ""
    }

    $hex = ($Mac -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
    if ($hex.Length -eq 12) {
        $parts = for ($i = 0; $i -lt 12; $i += 2) { $hex.Substring($i, 2) }
        return ($parts -join ":")
    }

    return (($Mac.Trim() -replace "-", ":") -replace "\s+", "").ToUpperInvariant()
}

function ConvertTo-UInt32Ip {
    param([Parameter(Mandatory)][string]$IpAddress)

    $bytes = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
    return [uint32](
        ([uint32]$bytes[0] -shl 24) -bor
        ([uint32]$bytes[1] -shl 16) -bor
        ([uint32]$bytes[2] -shl 8) -bor
        [uint32]$bytes[3]
    )
}

function ConvertFrom-UInt32Ip {
    param([Parameter(Mandatory)][uint32]$Value)

    $bytes = [byte[]](
        (($Value -shr 24) -band 255),
        (($Value -shr 16) -band 255),
        (($Value -shr 8) -band 255),
        ($Value -band 255)
    )
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-SubnetMaskUInt32 {
    param([Parameter(Mandatory)][ValidateRange(0, 32)][int]$PrefixLength)

    $mask = [uint32]0
    for ($i = 0; $i -lt $PrefixLength; $i++) {
        $mask = $mask -bor [uint32]([math]::Pow(2, 31 - $i))
    }
    return $mask
}

function Get-NetworkAddress {
    param(
        [Parameter(Mandatory)][string]$IpAddress,
        [Parameter(Mandatory)][int]$PrefixLength
    )

    $ip = ConvertTo-UInt32Ip $IpAddress
    if ($PrefixLength -le 0) {
        return "0.0.0.0"
    }

    $mask = Get-SubnetMaskUInt32 -PrefixLength $PrefixLength
    return ConvertFrom-UInt32Ip ([uint32]($ip -band $mask))
}

function Get-DefaultSubnet {
    try {
        $config = Get-NetIPConfiguration |
            Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address } |
            Select-Object -First 1

        if ($config) {
            $ip = $config.IPv4Address[0].IPAddress
            $prefix = [int]$config.IPv4Address[0].PrefixLength
            $network = Get-NetworkAddress -IpAddress $ip -PrefixLength $prefix
            return "$network/$prefix"
        }
    } catch {
        # Fallback mai jos.
    }

    return "192.168.1.0/24"
}

function Get-SubnetHosts {
    param([Parameter(Mandatory)][string]$Cidr)

    if ($Cidr -notmatch "^([0-9]{1,3}(\.[0-9]{1,3}){3})/([0-9]|[12][0-9]|3[0-2])$") {
        throw "Subnet invalid: $Cidr. Exemplu valid: 192.168.1.0/24"
    }

    $networkIp = $Matches[1]
    $prefix = [int]$Matches[3]
    $hostCount = [math]::Pow(2, 32 - $prefix)

    if ($hostCount -gt 1024) {
        throw "Subnetul $Cidr este prea mare pentru fallback-ul fara Nmap. Instaleaza Nmap sau foloseste un subnet /22 - /30."
    }

    $network = ConvertTo-UInt32Ip $networkIp
    $first = if ($prefix -ge 31) { $network } else { $network + 1 }
    $last = if ($prefix -ge 31) { $network + [uint32]$hostCount - 1 } else { $network + [uint32]$hostCount - 2 }

    for ($i = $first; $i -le $last; $i++) {
        ConvertFrom-UInt32Ip ([uint32]$i)
    }
}

function Test-IpInSubnet {
    param(
        [Parameter(Mandatory)][string]$IpAddress,
        [Parameter(Mandatory)][string]$Cidr
    )

    if ($Cidr -notmatch "^([0-9]{1,3}(\.[0-9]{1,3}){3})/([0-9]|[12][0-9]|3[0-2])$") {
        return $false
    }

    try {
        $networkIp = $Matches[1]
        $prefix = [int]$Matches[3]
        $ip = ConvertTo-UInt32Ip $IpAddress
        $network = ConvertTo-UInt32Ip $networkIp
        $mask = Get-SubnetMaskUInt32 -PrefixLength $prefix
        return (($ip -band $mask) -eq ($network -band $mask))
    } catch {
        return $false
    }
}

function Import-LegacyConfig {
    if (-not (Test-Path $Script:LegacyConfigFile)) {
        return $false
    }

    $section = ""
    foreach ($line in Get-Content -LiteralPath $Script:LegacyConfigFile -ErrorAction SilentlyContinue) {
        if ($line -match "^\s*CALCULATOARE=\(") {
            $section = "Calculatoare"
            continue
        }
        if ($line -match "^\s*IGNORA=\(") {
            $section = "Ignora"
            continue
        }
        if ($line -match "^\s*\)") {
            $section = ""
            continue
        }
        if ($section -and $line -match '\["([^"]+)"\]\s*=\s*"([^"]*)"') {
            $mac = Normalize-Mac $Matches[1]
            $name = $Matches[2]
            if ($mac) {
                $Script:State[$section][$mac] = $name
            }
        }
    }

    return ($Script:State.Calculatoare.Count -gt 0 -or $Script:State.Ignora.Count -gt 0)
}

function Save-Config {
    $payload = [ordered]@{
        version = 1
        generatedAt = (Get-Date).ToString("o")
        subnet = $Script:State.Subnet
        calculatoare = $Script:State.Calculatoare
        ignora = $Script:State.Ignora
    }

    $tempFile = "$Script:ConfigFile.tmp"
    $json = $payload | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $tempFile -Value $json -Encoding UTF8

    try {
        $null = Get-Content -LiteralPath $tempFile -Raw | ConvertFrom-Json
        Move-Item -LiteralPath $tempFile -Destination $Script:ConfigFile -Force
    } catch {
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        throw "Config generat invalid: $($_.Exception.Message)"
    }
}

function Backup-Config {
    if (-not (Test-Path $Script:ConfigFile)) {
        return
    }

    $backup = "$Script:ConfigFile.bak.$(Get-Date -Format yyyyMMdd)"
    if (-not (Test-Path $backup)) {
        Copy-Item -LiteralPath $Script:ConfigFile -Destination $backup -Force
    }

    Get-ChildItem -LiteralPath $Script:ScriptDir -Filter "retea_config.windows.json.bak.*" |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

function Load-Config {
    $Script:State.Calculatoare = @{}
    $Script:State.Ignora = @{}

    if ($Subnet) {
        $Script:State.Subnet = $Subnet
    } else {
        $Script:State.Subnet = Get-DefaultSubnet
    }

    if (Test-Path $Script:ConfigFile) {
        try {
            $config = Get-Content -LiteralPath $Script:ConfigFile -Raw | ConvertFrom-Json
            if ($config.subnet) {
                $Script:State.Subnet = [string]$config.subnet
            }
            if ($Subnet) {
                $Script:State.Subnet = $Subnet
            }
            $Script:State.Calculatoare = ConvertTo-Hashtable $config.calculatoare
            $Script:State.Ignora = ConvertTo-Hashtable $config.ignora
            return
        } catch {
            $bad = "$Script:ConfigFile.corrupt.$(Get-Date -Format yyyyMMdd_HHmmss)"
            Copy-Item -LiteralPath $Script:ConfigFile -Destination $bad -Force
            Write-Color "[WARN] Config JSON corupt. L-am salvat ca $(Split-Path -Leaf $bad) si pornesc cu o configuratie goala." Yellow
        }
    }

    if (Import-LegacyConfig) {
        Write-Color "[OK] Am importat configuratia veche din retea_config.conf in format Windows JSON." Green
    } else {
        Write-Color "[INFO] Nu exista configuratie Windows. Creez una noua." Yellow
    }

    Save-Config
}

function Resolve-DeviceHostname {
    param([Parameter(Mandatory)][string]$IpAddress)

    try {
        $dns = Resolve-DnsName -Name $IpAddress -QuickTimeout -ErrorAction Stop |
            Where-Object { $_.NameHost } |
            Select-Object -First 1
        if ($dns.NameHost) {
            return $dns.NameHost.TrimEnd(".")
        }
    } catch {
        # Fara hostname rapid.
    }

    return ""
}

function Get-LocalMacMap {
    $map = @{}
    try {
        $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.MacAddress }
        foreach ($adapter in $adapters) {
            $mac = Normalize-Mac $adapter.MacAddress
            if ($mac) {
                $map[$mac] = $adapter
            }
        }
    } catch {
        # Nu toate editiile Windows au modulele NetTCPIP/NetAdapter incarcate.
    }
    return $map
}

function Get-LocalIpToMac {
    $map = @{}
    try {
        $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.MacAddress }
        foreach ($adapter in $adapters) {
            $mac = Normalize-Mac $adapter.MacAddress
            $ips = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            foreach ($ip in $ips) {
                if ($ip.IPAddress -and -not $ip.IPAddress.StartsWith("169.254.")) {
                    $map[$ip.IPAddress] = $mac
                }
            }
        }
    } catch {
        # Fallback indisponibil.
    }
    return $map
}

function Get-ConnectionType {
    param(
        [Parameter(Mandatory)][string]$Mac,
        [string]$Vendor = ""
    )

    $localMap = Get-LocalMacMap
    if ($localMap.ContainsKey($Mac)) {
        $adapter = $localMap[$Mac]
        $text = "$($adapter.Name) / $($adapter.InterfaceDescription)"
        if ($text -match "Wi-?Fi|Wireless|WLAN|802\.11") {
            return "WiFi local"
        }
        if ($text -match "Ethernet|Realtek|Intel|LAN|GbE|2\.5G|10G") {
            return "Ethernet local"
        }
        return "Local: $($adapter.Name)"
    }

    if ($Vendor -match "Wireless|Qualcomm|Broadcom|Atheros|Ralink|MediaTek") {
        return "WiFi probabil"
    }
    if ($Vendor -match "Intel|Realtek|Dell|HP|Hewlett|Lenovo|ASUS|Gigabyte|MSI") {
        return "Ethernet probabil"
    }

    return "LAN remote"
}

function Invoke-NmapPingScan {
    param([Parameter(Mandatory)][string]$Cidr)

    $devices = New-Object System.Collections.Generic.List[object]
    $output = & nmap -sn $Cidr 2>$null
    $currentIp = ""
    $currentHost = ""

    foreach ($line in $output) {
        if ($line -match "^Nmap scan report for\s+(.+)$") {
            $target = $Matches[1].Trim()
            $currentIp = ""
            $currentHost = ""

            if ($target -match "\(([0-9]{1,3}(\.[0-9]{1,3}){3})\)") {
                $currentIp = $Matches[1]
                $currentHost = ($target -replace "\s*\([^)]+\)\s*$", "")
            } elseif ($target -match "([0-9]{1,3}(\.[0-9]{1,3}){3})") {
                $currentIp = $Matches[1]
            }
            continue
        }

        if ($currentIp -and $line -match "MAC Address:\s+(([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s*(?:\((.+)\))?") {
            $mac = Normalize-Mac $Matches[1]
            $vendor = if ($Matches.Count -ge 4) { [string]$Matches[3] } else { "Unknown" }
            $devices.Add([pscustomobject]@{
                IP = $currentIp
                MAC = $mac
                Vendor = $(if ($vendor) { $vendor } else { "Unknown" })
                Hostname = $currentHost
            })
            $currentIp = ""
            $currentHost = ""
        }
    }

    $localIpToMac = Get-LocalIpToMac
    foreach ($ip in $localIpToMac.Keys) {
        if ((Test-IpInSubnet -IpAddress $ip -Cidr $Cidr) -and -not ($devices | Where-Object { $_.IP -eq $ip })) {
            $devices.Add([pscustomobject]@{
                IP = $ip
                MAC = $localIpToMac[$ip]
                Vendor = "Local Machine"
                Hostname = $env:COMPUTERNAME
            })
        }
    }

    return $devices
}

function Invoke-FallbackPingScan {
    param([Parameter(Mandatory)][string]$Cidr)

    $hosts = @(Get-SubnetHosts $Cidr)
    Write-Color "[INFO] Nmap nu este instalat. Folosesc fallback ping + ARP pentru $($hosts.Count) hosturi." Yellow
    Write-Color "[INFO] Pentru rezultate mai bune: .\scan_retea.ps1 -InstallNmap" DarkGray

    Invoke-PingSweep -Hosts $hosts -TimeoutMs 800 -BatchSize 128

    $devices = New-Object System.Collections.Generic.List[object]

    try {
        $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -and
                (Test-IpInSubnet -IpAddress $_.IPAddress -Cidr $Cidr) -and
                $_.LinkLayerAddress -and
                $_.LinkLayerAddress -notmatch "^(00-00-00-00-00-00|ff-ff-ff-ff-ff-ff)$"
            }

        foreach ($neighbor in $neighbors) {
            $mac = Normalize-Mac $neighbor.LinkLayerAddress
            if ($mac) {
                $devices.Add([pscustomobject]@{
                    IP = $neighbor.IPAddress
                    MAC = $mac
                    Vendor = "Unknown"
                    Hostname = ""
                })
            }
        }
    } catch {
        $arp = & arp -a 2>$null
        foreach ($line in $arp) {
            if ($line -match "^\s*([0-9]{1,3}(\.[0-9]{1,3}){3})\s+([0-9A-Fa-f-]{17})\s+") {
                if (-not (Test-IpInSubnet -IpAddress $Matches[1] -Cidr $Cidr)) {
                    continue
                }
                $devices.Add([pscustomobject]@{
                    IP = $Matches[1]
                    MAC = (Normalize-Mac $Matches[3])
                    Vendor = "Unknown"
                    Hostname = ""
                })
            }
        }
    }

    $localIpToMac = Get-LocalIpToMac
    foreach ($ip in $localIpToMac.Keys) {
        if ((Test-IpInSubnet -IpAddress $ip -Cidr $Cidr) -and -not ($devices | Where-Object { $_.IP -eq $ip })) {
            $devices.Add([pscustomobject]@{
                IP = $ip
                MAC = $localIpToMac[$ip]
                Vendor = "Local Machine"
                Hostname = $env:COMPUTERNAME
            })
        }
    }

    return $devices | Sort-Object IP -Unique
}

function Invoke-PingSweep {
    param(
        [Parameter(Mandatory)][string[]]$Hosts,
        [int]$TimeoutMs = 800,
        [int]$BatchSize = 128
    )

    for ($start = 0; $start -lt $Hosts.Count; $start += $BatchSize) {
        $end = [Math]::Min($start + $BatchSize - 1, $Hosts.Count - 1)
        $items = @()

        foreach ($hostIp in $Hosts[$start..$end]) {
            $ping = New-Object System.Net.NetworkInformation.Ping
            try {
                $items += [pscustomobject]@{
                    Ping = $ping
                    Task = $ping.SendPingAsync($hostIp, $TimeoutMs)
                }
            } catch {
                $ping.Dispose()
            }
        }

        if ($items.Count -gt 0) {
            [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]($items.Task), $TimeoutMs + 2000) | Out-Null
            foreach ($item in $items) {
                $item.Ping.Dispose()
            }
        }
    }
}

function Get-NetworkDevices {
    param([Parameter(Mandatory)][string]$Cidr)

    if (Test-CommandExists "nmap") {
        return Invoke-NmapPingScan -Cidr $Cidr
    }

    return Invoke-FallbackPingScan -Cidr $Cidr
}

function Test-PingHost {
    param(
        [Parameter(Mandatory)][string]$IpAddress,
        [int]$TimeoutMs = 1000
    )

    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        $reply = $ping.Send($IpAddress, $TimeoutMs)
        return ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
    } catch {
        return $false
    } finally {
        $ping.Dispose()
    }
}

function Test-HostOnline {
    param([Parameter(Mandatory)][string]$IpAddress)

    return Test-PingHost -IpAddress $IpAddress -TimeoutMs 1000
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory)][string]$IpAddress,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 400
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($IpAddress, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Test-PotentialComputer {
    param([Parameter(Mandatory)][string]$IpAddress)

    if (Test-CommandExists "nmap") {
        try {
            $ports = & nmap -p 22,445,3389,5900 --host-timeout 800ms $IpAddress 2>$null
            return [bool]($ports | Where-Object { $_ -match "\bopen\b" })
        } catch {
            return $false
        }
    }

    $clients = @()
    try {
        foreach ($port in 22, 445, 3389, 5900) {
            $client = New-Object System.Net.Sockets.TcpClient
            $async = $client.BeginConnect($IpAddress, $port, $null, $null)
            $clients += [pscustomobject]@{
                Client = $client
                Async = $async
            }
        }

        $deadline = (Get-Date).AddMilliseconds(350)
        while ((Get-Date) -lt $deadline) {
            foreach ($item in $clients) {
                if ($item.Client.Connected) {
                    return $true
                }
            }
            Start-Sleep -Milliseconds 25
        }
        return $false
    } catch {
        return $false
    } finally {
        foreach ($item in $clients) {
            $item.Client.Close()
        }
    }

}

function Add-DeviceInteractive {
    param(
        [Parameter(Mandatory)][string]$Mac,
        [Parameter(Mandatory)][string]$IpAddress,
        [string]$Vendor = "Unknown",
        [bool]$IsComputer
    )

    Write-Host ""
    Write-Color "[NEW] Dispozitiv nou detectat" Yellow
    Write-Host ("  MAC:    {0}" -f $Mac)
    Write-Host ("  IP:     {0}" -f $IpAddress)
    Write-Host ("  Vendor: {0}" -f $Vendor)
    Write-Host ("  Tip:    {0}" -f $(if ($IsComputer) { "Calculator/Server posibil" } else { "Alt dispozitiv" }))
    Write-Host ""
    Write-Color "Cum vrei sa-l clasifici?" Cyan
    Write-Host "  1 - Adauga la calculatoare monitorizate"
    Write-Host "  2 - Adauga la ignorate"
    Write-Host "  3 - Ignora doar acum"

    $choice = Read-Host "Alege optiunea [1-3]"
    switch ($choice) {
        "1" {
            $name = Read-Host "Nume identificare"
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                $Script:State.Calculatoare[$Mac] = $name.Trim()
                Backup-Config
                Save-Config
                Write-Color "[OK] Adaugat la calculatoare: $name" Green
            } else {
                Write-Color "[ERR] Nume invalid." Red
            }
        }
        "2" {
            $name = Read-Host "Nume dispozitiv"
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                $Script:State.Ignora[$Mac] = $name.Trim()
                Backup-Config
                Save-Config
                Write-Color "[OK] Adaugat la ignorate: $name" Green
            } else {
                Write-Color "[ERR] Nume invalid." Red
            }
        }
        "3" {
            Write-Color "[INFO] Ignorat temporar." DarkGray
        }
        default {
            Write-Color "[ERR] Optiune invalida: $choice" Red
        }
    }
}

function Save-HistoryEntry {
    param(
        [Parameter(Mandatory)][string]$Mac,
        [Parameter(Mandatory)][string]$IpAddress,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Status
    )

    $entry = [ordered]@{
        timestamp = (Get-Date).ToString("o")
        mac = $Mac
        ip = $IpAddress
        name = $Name
        status = $Status
    }

    Add-Content -LiteralPath $Script:HistoryFile -Value ($entry | ConvertTo-Json -Compress) -Encoding UTF8
}

function Update-ScanCache {
    $age = (Get-Date) - [datetime]$Script:ScanCache.Time
    if ($age.TotalSeconds -lt 180) {
        return
    }

    $Script:ScanCache.MacToIP = @{}
    foreach ($device in Get-NetworkDevices -Cidr $Script:State.Subnet) {
        $mac = Normalize-Mac $device.MAC
        if ($mac -and -not $Script:ScanCache.MacToIP.ContainsKey($mac)) {
            $Script:ScanCache.MacToIP[$mac] = $device.IP
        }
    }
    $Script:ScanCache.Time = Get-Date
}

function Show-MonitoredDashboard {
    if ($Script:State.Calculatoare.Count -eq 0) {
        return
    }

    Update-ScanCache

    Write-Host ""
    Write-Color ("=" * 70) Cyan
    Write-Color ("{0,-70}" -f "Calculatoare monitorizate") White
    Write-Color ("=" * 70) Cyan

    foreach ($mac in $Script:State.Calculatoare.Keys) {
        $name = [string]$Script:State.Calculatoare[$mac]
        $ip = $Script:ScanCache.MacToIP[$mac]
        if ($ip) {
            $status = if (Test-HostOnline $ip) { "ONLINE" } else { "PING?" }
            $color = if ($status -eq "ONLINE") { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow }
            Write-Color ("{0,-15} -> {1,-38} {2,-8}" -f $ip, $name.Substring(0, [Math]::Min(38, $name.Length)), $status) $color
        } else {
            Write-Color ("{0,-15} -> {1,-38} {2,-8}" -f "N/A", $name.Substring(0, [Math]::Min(38, $name.Length)), "OFFLINE") Red
        }
    }

    $cacheAge = [int](((Get-Date) - [datetime]$Script:ScanCache.Time).TotalSeconds)
    Write-Color ("cache: {0}s" -f $cacheAge) DarkGray
}

function Invoke-NetworkScan {
    param([bool]$InteractiveMode)

    Write-Header "SCANARE RETEA LOCALA"
    Write-Color "[INFO] Scanez subnet: $($Script:State.Subnet)" Cyan
    Write-Color "Te rog asteapta..." DarkGray
    Write-Host ""

    $devices = @(Get-NetworkDevices -Cidr $Script:State.Subnet)
    $seen = @{}
    $totalFound = 0
    $knownComputers = 0
    $newDevices = 0
    $ignoredDevices = 0
    $duplicates = 0
    $nmapAvailable = Test-CommandExists "nmap"

    Write-Separator
    Write-Color ("{0,-8} | {1,-31} | {2,-15} | {3}" -f "STATUS", "NUME DISPOZITIV", "IP ADDRESS", "MAC ADDRESS") White
    Write-Separator

    foreach ($device in $devices) {
        $ip = [string]$device.IP
        $mac = Normalize-Mac ([string]$device.MAC)
        if (-not $mac) {
            continue
        }

        if ($seen.ContainsKey($mac)) {
            $duplicates++
            Write-Color ("SKIP     | Duplicat MAC                 | {0,-15} | {1}" -f $ip, $mac) DarkGray
            continue
        }

        $seen[$mac] = $ip
        $totalFound++
        $vendor = if ($device.Vendor) { [string]$device.Vendor } else { "Unknown" }
        $hostname = if ($device.Hostname) {
            [string]$device.Hostname
        } elseif ($nmapAvailable) {
            Resolve-DeviceHostname $ip
        } else {
            ""
        }
        $connection = Get-ConnectionType -Mac $mac -Vendor $vendor

        if ($Script:State.Calculatoare.ContainsKey($mac)) {
            $knownComputers++
            $name = [string]$Script:State.Calculatoare[$mac]
            Write-Color ("OK       | {0,-31} | {1,-15} | {2}" -f $name.Substring(0, [Math]::Min(31, $name.Length)), $ip, $mac) Green
            Write-Color ("         | conexiune: {0}" -f $connection) DarkGray
            Save-HistoryEntry -Mac $mac -IpAddress $ip -Name $name -Status "online"
            continue
        }

        if ($Script:State.Ignora.ContainsKey($mac)) {
            $ignoredDevices++
            continue
        }

        $newDevices++
        $isComputer = Test-PotentialComputer $ip
        $label = if ($isComputer) { "PC NOU" } else { "NOU" }
        $displayName = if ($hostname) { "$vendor / $hostname" } else { $vendor }
        $displayShort = $displayName.Substring(0, [Math]::Min(31, $displayName.Length))
        $color = if ($isComputer) { [ConsoleColor]::Red } else { [ConsoleColor]::Yellow }

        Write-Color ("{0,-8} | {1,-31} | {2,-15} | {3}" -f $label, $displayShort, $ip, $mac) $color
        Write-Color ("         | conexiune: {0}" -f $connection) DarkGray
        Add-Content -LiteralPath $Script:LogFile -Value ("[{0}] NEW: {1} | {2} | {3} | {4}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $mac, $ip, $displayName, $connection) -Encoding UTF8
        Save-HistoryEntry -Mac $mac -IpAddress $ip -Name $displayShort -Status "new"

        if ($InteractiveMode) {
            Add-DeviceInteractive -Mac $mac -IpAddress $ip -Vendor $displayName -IsComputer:$isComputer
        }
    }

    Write-Separator
    Write-Color "STATISTICI:" White
    Write-Host ("  Calculatoare online:  {0}" -f $knownComputers)
    Write-Host ("  Dispozitive noi:      {0}" -f $newDevices)
    Write-Host ("  Dispozitive ignorate: {0}" -f $ignoredDevices)
    Write-Host ("  Total unic gasite:    {0}" -f $totalFound)
    if ($duplicates -gt 0) {
        Write-Host ("  Duplicate ignorate:   {0}" -f $duplicates)
    }
    Write-Separator
}

function Show-Config {
    Write-Header "CONFIGURATIE CURENTA"
    Write-Host ("Subnet: {0}" -f $Script:State.Subnet)
    Write-Host ""

    Write-Color ("Calculatoare monitorizate ({0}):" -f $Script:State.Calculatoare.Count) Green
    if ($Script:State.Calculatoare.Count -eq 0) {
        Write-Color "  (niciun dispozitiv)" DarkGray
    } else {
        foreach ($mac in $Script:State.Calculatoare.Keys) {
            Write-Host ("  {0} -> {1}" -f $mac, $Script:State.Calculatoare[$mac])
        }
    }

    Write-Host ""
    Write-Color ("Dispozitive ignorate ({0}):" -f $Script:State.Ignora.Count) Yellow
    if ($Script:State.Ignora.Count -eq 0) {
        Write-Color "  (niciun dispozitiv)" DarkGray
    } else {
        foreach ($mac in $Script:State.Ignora.Keys) {
            Write-Host ("  {0} -> {1}" -f $mac, $Script:State.Ignora[$mac])
        }
    }
    Write-Separator
}

function Show-History {
    Write-Header "ISTORIC (ultimele 20 intrari)"
    if (-not (Test-Path $Script:HistoryFile)) {
        Write-Color "[INFO] Nu exista istoric." Yellow
        Write-Separator
        return
    }

    Write-Color ("{0,-8} | {1,-16} | {2,-24} | {3}" -f "STATUS", "DATA/ORA", "DISPOZITIV", "IP ADDRESS") White
    Write-Separator

    Get-Content -LiteralPath $Script:HistoryFile -Tail 20 | ForEach-Object {
        try {
            $entry = $_ | ConvertFrom-Json
            $dt = [datetime]::Parse($entry.timestamp)
            $name = [string]$entry.name
            $short = $name.Substring(0, [Math]::Min(24, $name.Length))
            $status = [string]$entry.status
            $color = if ($status -eq "online") { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow }
            Write-Color ("{0,-8} | {1,-16} | {2,-24} | {3}" -f $status, $dt.ToString("dd-MM HH:mm"), $short, $entry.ip) $color
        } catch {
            Write-Color "[WARN] Linie istoric invalida ignorata." Yellow
        }
    }
    Write-Separator
}

function Clear-ArpCache {
    Write-Header "CURATARE CACHE ARP"
    if (-not (Test-IsAdmin)) {
        Write-Color "[WARN] Pentru curatare completa ARP, ruleaza PowerShell ca Administrator." Yellow
    }

    try {
        & netsh interface ip delete arpcache | Out-Null
        Write-Color "[OK] Cache ARP curatat." Green
    } catch {
        Write-Color "[ERR] Nu am putut curata cache-ul ARP: $($_.Exception.Message)" Red
    }
    Write-Separator
}

function Repair-Config {
    Write-Header "VERIFICARE SI REPARARE CONFIGURATIE"
    $issues = 0

    if (-not (Test-Path $Script:ConfigFile)) {
        Write-Color "[WARN] Config lipsa. Creez fisier nou." Yellow
        Save-Config
        Write-Separator
        return
    }

    try {
        $config = Get-Content -LiteralPath $Script:ConfigFile -Raw | ConvertFrom-Json
        Write-Color "[OK] JSON valid." Green
    } catch {
        $issues++
        Write-Color "[ERR] JSON invalid: $($_.Exception.Message)" Red
        $bad = "$Script:ConfigFile.corrupt.$(Get-Date -Format yyyyMMdd_HHmmss)"
        Copy-Item -LiteralPath $Script:ConfigFile -Destination $bad -Force
        Write-Color "[INFO] Copie salvata: $(Split-Path -Leaf $bad)" Yellow
        Save-Config
        Write-Color "[OK] Am regenerat o configuratie goala." Green
        Write-Separator
        return
    }

    $fixedComputers = @{}
    foreach ($property in $config.calculatoare.PSObject.Properties) {
        $mac = Normalize-Mac $property.Name
        if ($mac -ne $property.Name) { $issues++ }
        if ($mac) { $fixedComputers[$mac] = $property.Value }
    }

    $fixedIgnored = @{}
    foreach ($property in $config.ignora.PSObject.Properties) {
        $mac = Normalize-Mac $property.Name
        if ($mac -ne $property.Name) { $issues++ }
        if ($mac) { $fixedIgnored[$mac] = $property.Value }
    }

    if ($issues -gt 0) {
        Backup-Config
        $Script:State.Subnet = if ($config.subnet) { [string]$config.subnet } else { Get-DefaultSubnet }
        $Script:State.Calculatoare = $fixedComputers
        $Script:State.Ignora = $fixedIgnored
        Save-Config
        Write-Color "[OK] Am reparat $issues probleme si am normalizat adresele MAC." Green
    } else {
        Write-Color "[OK] Nicio problema gasita." Green
    }

    Write-Separator
}

function Edit-Config {
    if (-not (Test-Path $Script:ConfigFile)) {
        Save-Config
    }

    $editor = $env:EDITOR
    if ([string]::IsNullOrWhiteSpace($editor)) {
        $editor = "notepad.exe"
    }

    Start-Process -FilePath $editor -ArgumentList "`"$Script:ConfigFile`"" -Wait
    Load-Config
    Write-Color "[OK] Configuratie reincarcata." Green
    Start-Sleep -Seconds 1
}

function Show-Menu {
    Clear-Host
    Write-Header "NETWORK SCANNER WINDOWS v1.0"
    Show-MonitoredDashboard
    Write-Host ""
    Write-Color "Selecteaza o optiune:" Cyan
    Write-Host ""
    Write-Host "  1 - Scanare rapida (fara interactiune)"
    Write-Host "  2 - Scanare interactiva (adauga dispozitive noi)"
    Write-Host "  3 - Afisare configuratie"
    Write-Host "  4 - Afisare istoric"
    Write-Host "  5 - Editare configuratie manuala"
    Write-Host "  6 - Curatare cache ARP"
    Write-Host "  7 - Reimprospatare status calculatoare"
    Write-Host "  8 - Verificare si reparare configuratie"
    if (-not (Test-CommandExists "nmap")) {
        Write-Host "  9 - Instaleaza Nmap (recomandat)"
    }
    Write-Host "  0 - Iesire"
    Write-Separator
}

Load-Config

if ($Scan) {
    Invoke-NetworkScan -InteractiveMode:$false
    return
}
if ($Interactive) {
    Invoke-NetworkScan -InteractiveMode:$true
    return
}
if ($Config) {
    Show-Config
    return
}
if ($History) {
    Show-History
    return
}
if ($FlushArp) {
    Clear-ArpCache
    return
}
if ($Repair) {
    Repair-Config
    return
}
if ($InstallNmap) {
    Install-Nmap | Out-Null
    return
}

:MainMenu while ($true) {
    Load-Config
    Show-Menu
    $option = Read-Host "Optiunea ta"

    switch ($option) {
        "1" {
            Clear-Host
            Invoke-NetworkScan -InteractiveMode:$false
            Read-Host "Apasa Enter pentru a continua" | Out-Null
        }
        "2" {
            Clear-Host
            Invoke-NetworkScan -InteractiveMode:$true
            Read-Host "Apasa Enter pentru a continua" | Out-Null
        }
        "3" {
            Clear-Host
            Show-Config
            Read-Host "Apasa Enter pentru a continua" | Out-Null
        }
        "4" {
            Clear-Host
            Show-History
            Read-Host "Apasa Enter pentru a continua" | Out-Null
        }
        "5" {
            Edit-Config
        }
        "6" {
            Clear-Host
            Clear-ArpCache
            Read-Host "Apasa Enter pentru a continua" | Out-Null
        }
        "7" {
            $Script:ScanCache.Time = [datetime]::MinValue
            Write-Color "[INFO] Cache sters. Statusul se va recalcula." Cyan
            Start-Sleep -Seconds 1
        }
        "8" {
            Clear-Host
            Repair-Config
            Read-Host "Apasa Enter pentru a continua" | Out-Null
        }
        "9" {
            Clear-Host
            if (Test-CommandExists "nmap") {
                Write-Color "[OK] Nmap este deja instalat." Green
            } else {
                Install-Nmap | Out-Null
            }
            Read-Host "Apasa Enter pentru a continua" | Out-Null
        }
        "0" {
            Write-Color "[OK] La revedere!" Green
            break MainMenu
        }
        default {
            Write-Color "[ERR] Optiune invalida." Red
            Start-Sleep -Seconds 1
        }
    }
}
