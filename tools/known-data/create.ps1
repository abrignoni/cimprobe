# Create the cimprobe known-data WMI subscriptions. Harmless: the filters watch for a
# process name that never runs, and the actions only echo or log to C:\cimprobe-test.
# Non-ASCII characters are built from code points so the file's own encoding cannot change them.
$ErrorActionPreference = 'Stop'
$log = @()
function Stamp($what) { $script:log += [pscustomobject]@{ step = $what; utc = [DateTime]::UtcNow.ToString('o') } }

$e = [string][char]0x00E9                       # e acute (Latin-1 range)
$jp = [string][char]0x65E5 + [char]0x672C        # two CJK characters (outside Latin-1)
$sub = 'root/subscription'
$def = 'root/default'
$never = "SELECT * FROM __InstanceCreationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'cimprobe-never-runs.exe'"

Stamp 'start'
# 1. filter with non-ASCII in its Name, explicit EventNamespace
$f1 = New-CimInstance -Namespace $sub -ClassName __EventFilter -Property @{
    Name = "cimprobe_kd_filter_cmd_$e$jp"; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'; Query = $never }
Stamp 'filter_cmd'
# 2. CommandLineEventConsumer: some properties set, the rest left at the class default
$c1 = New-CimInstance -Namespace $sub -ClassName CommandLineEventConsumer -Property @{
    Name = 'cimprobe_kd_consumer_cmd'
    CommandLineTemplate = "cmd.exe /c echo cimprobe $e $jp > C:\cimprobe-test\fired_cmd.txt"
    WorkingDirectory = 'C:\cimprobe-test'
    KillTimeout = [uint32]30
    RunInteractively = $false }
Stamp 'consumer_cmd'
$b1 = New-CimInstance -Namespace $sub -ClassName __FilterToConsumerBinding -Property @{ Filter = [ref]$f1; Consumer = [ref]$c1 }
Stamp 'binding_cmd'

# 3. ActiveScriptEventConsumer whose ScriptText is larger than one 8 KiB page
$lines = 1..400 | ForEach-Object { "' cimprobe padding line {0:D4} of 0400" -f $_ }
$script = ($lines -join "`r`n") + "`r`nDim x : x = 1`r`n"
$f2 = New-CimInstance -Namespace $sub -ClassName __EventFilter -Property @{
    Name = 'cimprobe_kd_filter_script'; QueryLanguage = 'WQL'; Query = $never; EventNamespace = 'root\cimv2' }
Stamp 'filter_script'
$c2 = New-CimInstance -Namespace $sub -ClassName ActiveScriptEventConsumer -Property @{
    Name = 'cimprobe_kd_consumer_script'; ScriptingEngine = 'VBScript'; ScriptText = $script }
Stamp 'consumer_script'
$b2 = New-CimInstance -Namespace $sub -ClassName __FilterToConsumerBinding -Property @{ Filter = [ref]$f2; Consumer = [ref]$c2; DeliverSynchronously = $false }
Stamp 'binding_script'

# 4. root\default: filter + LogFileEventConsumer + binding
$f3 = New-CimInstance -Namespace $def -ClassName __EventFilter -Property @{
    Name = 'cimprobe_kd_filter_default'; QueryLanguage = 'WQL'; Query = $never; EventNamespace = 'root\cimv2' }
Stamp 'filter_default'
$c3 = New-CimInstance -Namespace $def -ClassName LogFileEventConsumer -Property @{
    Name = 'cimprobe_kd_consumer_log'; Filename = 'C:\cimprobe-test\fired_log.txt'; Text = "cimprobe log $e"; MaximumFileSize = [uint64]65536 }
Stamp 'consumer_log'
$b3 = New-CimInstance -Namespace $def -ClassName __FilterToConsumerBinding -Property @{ Filter = [ref]$f3; Consumer = [ref]$c3 }
Stamp 'binding_default'

[pscustomobject]@{ script_text_chars = $script.Length; steps = $log } | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 'C:\cimprobe-test\create-log.json'
Get-Content 'C:\cimprobe-test\create-log.json'
