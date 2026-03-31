Set-StrictMode -Version Latest

function Resolve-GhidraReSkillRoot {
    param(
        [string]$SkillRoot
    )

    $candidates = @()

    if ($SkillRoot) {
        $candidates += $SkillRoot
    }

    if ($env:GHIDRA_RE_ROOT) {
        $candidates += $env:GHIDRA_RE_ROOT
    }

    if ($PSScriptRoot) {
        $candidates += (Join-Path $PSScriptRoot "..")
    }

    $codexHome = if ($env:CODEX_HOME) {
        $env:CODEX_HOME
    } else {
        Join-Path $HOME ".codex"
    }
    $candidates += (Join-Path $codexHome "skills\ghidra-re")

    foreach ($candidate in $candidates) {
        if (-not $candidate) {
            continue
        }
        try {
            $resolved = (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).Path
        } catch {
            continue
        }
        if (Test-Path (Join-Path $resolved "scripts\common.sh")) {
            return $resolved
        }
    }

    throw "Unable to locate the ghidra-re skill root. Pass -SkillRoot or set GHIDRA_RE_ROOT."
}

function Find-GhidraReBash {
    $candidates = @(
        (Get-Command bash.exe -ErrorAction SilentlyContinue | ForEach-Object { $_.Source }),
        "C:\Program Files\Git\bin\bash.exe",
        "C:\Program Files\Git\usr\bin\bash.exe"
    ) | Where-Object { $_ -and (Test-Path $_) }

    return ($candidates | Select-Object -First 1)
}

function Find-GhidraReCygpath {
    param(
        [string]$BashPath
    )

    if (-not $BashPath) {
        return $null
    }

    $gitRoot = Split-Path (Split-Path $BashPath -Parent) -Parent
    $candidate = Join-Path $gitRoot "usr\bin\cygpath.exe"
    if (Test-Path $candidate) {
        return $candidate
    }
    return $null
}

function ConvertTo-GhidraReBashPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string]$CygpathPath
    )

    if ($CygpathPath -and (Test-Path $CygpathPath)) {
        return (& $CygpathPath -u $Path).Trim()
    }

    $normalized = $Path -replace '\\', '/'
    if ($normalized -match '^[A-Za-z]:/') {
        $drive = $normalized.Substring(0, 1).ToLowerInvariant()
        return "/$drive/$($normalized.Substring(3))"
    }
    return $normalized
}

function Test-GhidraReWindowsPath {
    param(
        [string]$Value
    )

    return ($Value -match '^[A-Za-z]:[\\/]') -or ($Value -match '^\\\\')
}

function ConvertTo-GhidraReArgument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Argument,
        [string]$CygpathPath
    )

    if ($Argument -match '^(?<key>[^=]+)=(?<value>.*)$') {
        $key = $Matches["key"]
        $value = $Matches["value"]
        if ($value -and -not ($value -like 'source:*') -and -not ($value -like 'json:*') -and (Test-GhidraReWindowsPath $value)) {
            return "$key=$(ConvertTo-GhidraReBashPath -Path $value -CygpathPath $CygpathPath)"
        }
        return $Argument
    }

    if (Test-GhidraReWindowsPath $Argument) {
        return (ConvertTo-GhidraReBashPath -Path $Argument -CygpathPath $CygpathPath)
    }

    return $Argument
}

function Get-GhidraReEnvironment {
    param(
        [string]$SkillRoot
    )

    $resolvedRoot = Resolve-GhidraReSkillRoot -SkillRoot $SkillRoot
    $bashPath = Find-GhidraReBash
    if (-not $bashPath) {
        throw "Git Bash was not found. Install Git for Windows or run the desktop installer bundle."
    }

    $cygpathPath = Find-GhidraReCygpath -BashPath $bashPath

    [pscustomobject]@{
        SkillRoot   = $resolvedRoot
        ScriptsRoot = Join-Path $resolvedRoot "scripts"
        BashPath    = $bashPath
        CygpathPath = $cygpathPath
    }
}

function Resolve-GhidraReScriptPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,
        [Parameter(Mandatory = $true)]
        [string]$SkillRoot
    )

    $resolved = if ([System.IO.Path]::IsPathRooted($ScriptName)) {
        $ScriptName
    } else {
        Join-Path (Join-Path $SkillRoot "scripts") $ScriptName
    }

    if (-not (Test-Path $resolved)) {
        throw "ghidra-re script not found: $resolved"
    }

    return (Resolve-Path -LiteralPath $resolved).Path
}

function Join-GhidraReOutput {
    param(
        [object[]]$Lines
    )

    if (-not $Lines) {
        return ""
    }

    return (($Lines | ForEach-Object { "$_" }) -join "`n").Trim()
}

function ConvertFrom-GhidraReJsonIfPossible {
    param(
        [string]$Output
    )

    if (-not $Output) {
        return $null
    }

    $trimmed = $Output.Trim()
    if (($trimmed.StartsWith("{")) -or ($trimmed.StartsWith("["))) {
        return ($trimmed | ConvertFrom-Json)
    }

    return $trimmed
}

function Invoke-GhidraReScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,
        [string[]]$Arguments = @(),
        [string]$SkillRoot,
        [switch]$RawOutput
    )

    $envInfo = Get-GhidraReEnvironment -SkillRoot $SkillRoot
    $scriptPath = Resolve-GhidraReScriptPath -ScriptName $ScriptName -SkillRoot $envInfo.SkillRoot
    $bashScriptPath = ConvertTo-GhidraReBashPath -Path $scriptPath -CygpathPath $envInfo.CygpathPath
    $convertedArgs = @($Arguments | ForEach-Object { ConvertTo-GhidraReArgument -Argument "$_" -CygpathPath $envInfo.CygpathPath })

    $output = & $envInfo.BashPath $bashScriptPath @convertedArgs 2>&1
    $exitCode = $LASTEXITCODE
    $joined = Join-GhidraReOutput -Lines $output

    if ($exitCode -ne 0) {
        if ($joined) {
            throw $joined
        }
        throw "ghidra-re script failed: $ScriptName"
    }

    if ($RawOutput) {
        return $joined
    }

    return (ConvertFrom-GhidraReJsonIfPossible -Output $joined)
}
