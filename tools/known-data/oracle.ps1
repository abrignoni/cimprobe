param([Parameter(Mandatory=$true)][string]$Label)
# Export the live WMI view that cimprobe must reproduce: every instance of every class
# in root\subscription and root\default (shallow, per exact class), each property's
# name, CIM type, flags and value; plus the namespace tree and a class count per namespace.
$ErrorActionPreference = 'Stop'
$dest = "C:\cimprobe-test\$Label"
New-Item -ItemType Directory -Force $dest | Out-Null

function Convert-Value($v) {
    if ($null -eq $v) { return $null }
    if ($v -is [datetime]) { return @{ datetime = $v.ToString('o') } }
    if ($v -is [Microsoft.Management.Infrastructure.CimInstance]) {
        return @{ embedded = $v.CimClass.CimClassName; props = @($v.CimInstanceProperties | ForEach-Object { @{ Name = $_.Name; Value = (Convert-Value $_.Value) } }) }
    }
    if ($v -is [array]) { return @($v | ForEach-Object { Convert-Value $_ }) }
    if ($v -is [timespan]) { return @{ interval = $v.ToString() } }
    return $v
}

$started = [DateTime]::UtcNow.ToString('o')
$out = @{}
foreach ($ns in 'root\subscription', 'root\default') {
    $classes = @(Get-CimClass -Namespace $ns)
    $rows = @()
    foreach ($c in $classes) {
        $quals = @($c.CimClassQualifiers | ForEach-Object { $_.Name })
        $insts = @()
        try { $insts = @(Get-CimInstance -Namespace $ns -ClassName $c.CimClassName -Shallow -ErrorAction Stop) } catch { $insts = @(); $err = $_.Exception.Message }
        foreach ($i in $insts) {
            $rows += [pscustomobject]@{
                ClassName = $c.CimClassName
                ClassQualifiers = $quals
                Properties = @($i.CimInstanceProperties | ForEach-Object {
                    [pscustomobject]@{ Name = $_.Name; CimType = $_.CimType.ToString(); Flags = $_.Flags.ToString(); Value = (Convert-Value $_.Value) }
                })
            }
        }
    }
    $out[$ns] = @{ class_count = $classes.Count; class_names = @($classes | ForEach-Object { $_.CimClassName } | Sort-Object); instances = $rows }
}

function Walk($ns) {
    $kids = @(Get-CimInstance -Namespace $ns -ClassName __Namespace -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $res = @([pscustomobject]@{ Namespace = $ns; ClassCount = @(Get-CimClass -Namespace $ns -ErrorAction SilentlyContinue).Count; Children = $kids })
    foreach ($k in $kids) { $res += Walk "$ns\$k" }
    return $res
}
$tree = Walk 'root'
[pscustomobject]@{
    label = $Label
    started_utc = $started
    finished_utc = [DateTime]::UtcNow.ToString('o')
    namespaces = $out
    namespace_tree = $tree
} | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 (Join-Path $dest 'oracle.json')
"oracle written: " + (Get-Item (Join-Path $dest 'oracle.json')).Length
