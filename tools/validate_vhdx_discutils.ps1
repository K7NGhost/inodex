param(
    [string]$FixtureDirectory = 'target/format-expansion',
    [string]$LibraryDirectory = 'target/format-expansion/discutils'
)
$ErrorActionPreference = 'Stop'
foreach ($assemblyName in @('DiscUtils.Streams.dll', 'DiscUtils.Core.dll', 'DiscUtils.Vhdx.dll')) {
    Add-Type -Path (Join-Path $LibraryDirectory $assemblyName)
}
$fixtureRoot = (Resolve-Path -LiteralPath $FixtureDirectory).Path
foreach ($fixtureName in @('ext2', 'fat-parent', 'fat-differential', 'ntfs-fixed', 'ntfs-dynamic', 'ntfs-parent', 'ntfs-differential')) {
    $layers = [System.Collections.Generic.List[DiscUtils.Vhdx.DiskImageFile]]::new()
    $child = [DiscUtils.Vhdx.DiskImageFile]::new((Join-Path $fixtureRoot ($fixtureName + '.vhdx')), [System.IO.FileAccess]::Read)
    $layers.Add($child)
    if ($fixtureName.EndsWith('-differential')) {
        $parentName = $fixtureName.Replace('-differential', '-parent') + '.vhdx'
        $parent = [DiscUtils.Vhdx.DiskImageFile]::new((Join-Path $fixtureRoot $parentName), [System.IO.FileAccess]::Read)
        if ($child.ParentUniqueId -ne $parent.UniqueId) { throw 'Independent parent linkage mismatch' }
        $layers.Add($parent)
    }
    $disk = [DiscUtils.Vhdx.Disk]::new($layers, [DiscUtils.Streams.Ownership]::Dispose)
    $outputPath = Join-Path $fixtureRoot ($fixtureName + '-discutils.raw')
    $outputStream = [System.IO.File]::Create($outputPath)
    try { $disk.Content.CopyTo($outputStream) }
    finally { $outputStream.Dispose(); $disk.Dispose() }
    $digest = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Output ($fixtureName + ' ' + $digest)
}
