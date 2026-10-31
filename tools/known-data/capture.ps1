param([Parameter(Mandatory=$true)][string]$Label)
# Copy the live WMI repository out of a fresh VSS shadow copy of C:, hash it, and
# delete the shadow. Output: C:\cimprobe-test\<Label>\Repository\* and capture.json.
$ErrorActionPreference = 'Stop'
$dest = "C:\cimprobe-test\$Label"
$repoDest = Join-Path $dest 'Repository'
New-Item -ItemType Directory -Force $repoDest | Out-Null
$before = [DateTime]::UtcNow.ToString('o')
$r = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{Volume='C:\'; Context='ClientAccessible'}
if ($r.ReturnValue -ne 0) { throw "Win32_ShadowCopy.Create returned $($r.ReturnValue)" }
$sc = Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $r.ShadowID }
$link = Join-Path $dest 'shadowlink'
cmd /c "mklink /d `"$link`" `"$($sc.DeviceObject)\`"" | Out-Null
try {
    $src = Join-Path $link 'Windows\System32\wbem\Repository'
    $listing = Get-ChildItem -Force -Recurse $src | Select-Object FullName, Length, LastWriteTimeUtc
    Copy-Item -Path (Join-Path $src '*') -Destination $repoDest -Recurse -Force
} finally {
    cmd /c "rmdir `"$link`"" | Out-Null
    Remove-CimInstance -InputObject $sc
}
$after = [DateTime]::UtcNow.ToString('o')
$hashes = Get-ChildItem -File -Recurse $repoDest | ForEach-Object {
    [pscustomobject]@{ Name = $_.FullName.Substring($repoDest.Length + 1); Length = $_.Length; SHA256 = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash }
}
$remaining = @(Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $r.ShadowID }).Count
[pscustomobject]@{
    label = $Label
    started_utc = $before
    shadow_install_date = $sc.InstallDate.ToUniversalTime().ToString('o')
    finished_utc = $after
    shadow_left_behind = $remaining
    source_listing = $listing | ForEach-Object { [pscustomobject]@{ Name = $_.FullName.Substring($src.Length); Length = $_.Length; LastWriteTimeUtc = $_.LastWriteTimeUtc.ToString('o') } }
    files = $hashes
} | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 (Join-Path $dest 'capture.json')
Get-Content (Join-Path $dest 'capture.json')
