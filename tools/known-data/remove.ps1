# Remove every cimprobe known-data object (bindings first) and show what is left.
$ErrorActionPreference = 'Stop'
$before = [DateTime]::UtcNow.ToString('o')
foreach ($ns in 'root/subscription', 'root/default') {
    Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding | Where-Object { $_.Filter.Name -like 'cimprobe_kd_*' -or $_.Consumer.Name -like 'cimprobe_kd_*' } | Remove-CimInstance
    Get-CimInstance -Namespace $ns -ClassName __EventConsumer | Where-Object { $_.Name -like 'cimprobe_kd_*' } | Remove-CimInstance
    Get-CimInstance -Namespace $ns -ClassName __EventFilter | Where-Object { $_.Name -like 'cimprobe_kd_*' } | Remove-CimInstance
}
$after = [DateTime]::UtcNow.ToString('o')
$left = foreach ($ns in 'root/subscription', 'root/default') {
    foreach ($c in '__EventFilter', '__EventConsumer', '__FilterToConsumerBinding') {
        [pscustomobject]@{ Namespace = $ns; Class = $c; Count = @(Get-CimInstance -Namespace $ns -ClassName $c).Count
            cimprobe_left = @(Get-CimInstance -Namespace $ns -ClassName $c | Where-Object { "$($_.Name) $($_.Filter) $($_.Consumer)" -like '*cimprobe_kd_*' }).Count }
    }
}
[pscustomobject]@{ before_utc = $before; after_utc = $after; remaining = $left } | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 'C:\cimprobe-test\remove-log.json'
Get-Content 'C:\cimprobe-test\remove-log.json'
