# Change one property of the CommandLineEventConsumer, so the instance timestamps can be
# compared before and after a known modification time.
$ErrorActionPreference = 'Stop'
$jp = [string][char]0x65E5 + [char]0x672C
$before = [DateTime]::UtcNow.ToString('o')
$c = Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Filter "Name='cimprobe_kd_consumer_cmd'"
Set-CimInstance -InputObject $c -Property @{ CommandLineTemplate = "cmd.exe /c echo cimprobe modified $jp > C:\cimprobe-test\fired_cmd.txt" }
$after = [DateTime]::UtcNow.ToString('o')
[pscustomobject]@{ modified = 'cimprobe_kd_consumer_cmd'; before_utc = $before; after_utc = $after } | ConvertTo-Json | Set-Content -Encoding UTF8 'C:\cimprobe-test\modify-log.json'
Get-Content 'C:\cimprobe-test\modify-log.json'
