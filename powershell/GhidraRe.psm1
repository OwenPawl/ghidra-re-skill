. "$PSScriptRoot/GhidraRe.Common.ps1"

function Initialize-GhidraRe {
    [CmdletBinding()]
    param(
        [switch]$SkipSmokeTest,
        [string]$SkillRoot
    )

    $args = @()
    if ($SkipSmokeTest) {
        $args += "--skip-smoke-test"
    }
    Invoke-GhidraReScript -ScriptName "bootstrap" -Arguments $args -SkillRoot $SkillRoot -RawOutput
}

function Invoke-GhidraReDoctor {
    [CmdletBinding()]
    param(
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "doctor" -SkillRoot $SkillRoot -RawOutput
}

function Add-GhidraReSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [string]$Platform = "macos-image",
        [ValidateSet("cache", "direct")]
        [string]$Copy = "cache",
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_source_add" -Arguments @(
        $Name,
        "root=$Root",
        "platform=$Platform",
        "copy=$Copy"
    ) -SkillRoot $SkillRoot | Out-Null

    Get-GhidraReSources -SkillRoot $SkillRoot
}

function Get-GhidraReSources {
    [CmdletBinding()]
    param(
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_source_list" -SkillRoot $SkillRoot
}

function Resolve-GhidraReSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$ImagePath,
        [ValidateSet("cache", "direct")]
        [string]$Copy = "cache",
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_source_resolve" -Arguments @(
        $Name,
        $ImagePath,
        "copy=$Copy"
    ) -SkillRoot $SkillRoot -RawOutput
}

function Import-GhidraReBinary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Binary,
        [string]$ProjectName,
        [string]$SkillRoot
    )

    $args = @($Binary)
    if ($ProjectName) {
        $args += $ProjectName
    }
    Invoke-GhidraReScript -ScriptName "ghidra_import_analyze" -Arguments $args -SkillRoot $SkillRoot -RawOutput
}

function Export-GhidraReAppleBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectName,
        [Parameter(Mandatory = $true)]
        [string]$ProgramName,
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_export_apple_bundle" -Arguments @(
        $ProjectName,
        $ProgramName
    ) -SkillRoot $SkillRoot -RawOutput
}

function Get-GhidraReBridgeSessions {
    [CmdletBinding()]
    param(
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_sessions" -SkillRoot $SkillRoot
}

function Select-GhidraReBridgeSession {
    [CmdletBinding(DefaultParameterSetName = "Session")]
    param(
        [Parameter(ParameterSetName = "Session", Mandatory = $true)]
        [string]$Session,
        [Parameter(ParameterSetName = "Project", Mandatory = $true)]
        [string]$Project,
        [Parameter(ParameterSetName = "Program", Mandatory = $true)]
        [string]$Program,
        [string]$ProjectProgram,
        [string]$SkillRoot
    )

    $args = @()
    switch ($PSCmdlet.ParameterSetName) {
        "Session" { $args += "session=$Session" }
        "Project" {
            $args += "project=$Project"
            if ($ProjectProgram) {
                $args += "program=$ProjectProgram"
            }
        }
        "Program" { $args += "program=$Program" }
    }

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_select" -Arguments $args -SkillRoot $SkillRoot
}

function Open-GhidraReBridge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectName,
        [string]$ProgramName,
        [string]$SkillRoot
    )

    $args = @($ProjectName)
    if ($ProgramName) {
        $args += $ProgramName
    }
    Invoke-GhidraReScript -ScriptName "ghidra_bridge_open" -Arguments $args -SkillRoot $SkillRoot -RawOutput | Out-Null
    if ($ProgramName) {
        return (Select-GhidraReBridgeSession -Project $ProjectName -ProjectProgram $ProgramName -SkillRoot $SkillRoot)
    }
    return (Select-GhidraReBridgeSession -Project $ProjectName -SkillRoot $SkillRoot)
}

function Close-GhidraReBridge {
    [CmdletBinding(DefaultParameterSetName = "Current")]
    param(
        [Parameter(ParameterSetName = "Session", Mandatory = $true)]
        [string]$Session,
        [Parameter(ParameterSetName = "Project", Mandatory = $true)]
        [string]$Project,
        [Parameter(ParameterSetName = "Program", Mandatory = $true)]
        [string]$Program,
        [string]$ProjectProgram,
        [string]$SkillRoot
    )

    $args = @()
    switch ($PSCmdlet.ParameterSetName) {
        "Session" { $args += "session=$Session" }
        "Project" {
            $args += "project=$Project"
            if ($ProjectProgram) {
                $args += "program=$ProjectProgram"
            }
        }
        "Program" { $args += "program=$Program" }
        default { }
    }

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_close" -Arguments $args -SkillRoot $SkillRoot -RawOutput
}

function Get-GhidraReCurrentContext {
    [CmdletBinding()]
    param(
        [string]$Session,
        [string]$Project,
        [string]$Program,
        [string]$SkillRoot
    )

    $args = @()
    if ($Session) { $args += "session=$Session" }
    if ($Project) { $args += "project=$Project" }
    if ($Program) { $args += "program=$Program" }

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_current_context" -Arguments $args -SkillRoot $SkillRoot
}

function Search-GhidraReFunctions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,
        [int]$Limit = 10,
        [string]$Session,
        [string]$Project,
        [string]$Program,
        [string]$SkillRoot
    )

    $args = @($Query, "limit=$Limit")
    if ($Session) { $args += "session=$Session" }
    if ($Project) { $args += "project=$Project" }
    if ($Program) { $args += "program=$Program" }

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_functions_search" -Arguments $args -SkillRoot $SkillRoot
}

function Invoke-GhidraReAnalyzeTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,
        [int]$Limit = 5,
        [switch]$Navigate,
        [string]$Session,
        [string]$Project,
        [string]$Program,
        [string]$SkillRoot
    )

    $args = @($Query, "limit=$Limit", "navigate=$($Navigate.IsPresent.ToString().ToLowerInvariant())")
    if ($Session) { $args += "session=$Session" }
    if ($Project) { $args += "project=$Project" }
    if ($Program) { $args += "program=$Program" }

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_analyze_target" -Arguments $args -SkillRoot $SkillRoot
}

function Trace-GhidraReSelector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Selector,
        [int]$Limit = 5,
        [string]$Session,
        [string]$Project,
        [string]$Program,
        [string]$SkillRoot
    )

    $args = @($Selector, "limit=$Limit")
    if ($Session) { $args += "session=$Session" }
    if ($Project) { $args += "project=$Project" }
    if ($Program) { $args += "program=$Program" }

    Invoke-GhidraReScript -ScriptName "ghidra_bridge_selector_trace" -Arguments $args -SkillRoot $SkillRoot
}

function Start-GhidraReMission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Goal,
        [Parameter(Mandatory = $true)]
        [string[]]$Target,
        [string[]]$Seed = @(),
        [string]$Mode = "trace",
        [string]$SkillRoot
    )

    $args = @($Name, "goal=$Goal", "mode=$Mode")
    foreach ($item in $Target) {
        $args += "target=$item"
    }
    foreach ($item in $Seed) {
        $args += "seed=$item"
    }

    Invoke-GhidraReScript -ScriptName "ghidra_mission_start" -Arguments $args -SkillRoot $SkillRoot -RawOutput | Out-Null
    Get-GhidraReMissionStatus -Name $Name -SkillRoot $SkillRoot
}

function Get-GhidraReMissionStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$SkillRoot
    )

    Invoke-GhidraReScript -ScriptName "ghidra_mission_status" -Arguments @($Name) -SkillRoot $SkillRoot
}

function Trace-GhidraReMission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Seed,
        [string[]]$Target = @(),
        [int]$LimitTargets = 3,
        [int]$TraceLimit = 5,
        [string]$SkillRoot
    )

    $args = @($Name, "seed=$Seed", "limit_targets=$LimitTargets", "trace_limit=$TraceLimit")
    foreach ($item in $Target) {
        $args += "target=$item"
    }

    Invoke-GhidraReScript -ScriptName "ghidra_mission_trace" -Arguments $args -SkillRoot $SkillRoot -RawOutput | Out-Null
    Get-GhidraReMissionStatus -Name $Name -SkillRoot $SkillRoot
}

function Get-GhidraReMissionReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [ValidateSet("markdown", "json", "path")]
        [string]$Format = "markdown",
        [string]$SkillRoot
    )

    $result = Invoke-GhidraReScript -ScriptName "ghidra_mission_report" -Arguments @($Name, "format=$Format") -SkillRoot $SkillRoot -RawOutput
    if ($Format -eq "json") {
        return (ConvertFrom-GhidraReJsonIfPossible -Output $result)
    }
    return $result
}

Export-ModuleMember -Function @(
    "Initialize-GhidraRe",
    "Invoke-GhidraReDoctor",
    "Add-GhidraReSource",
    "Get-GhidraReSources",
    "Resolve-GhidraReSource",
    "Import-GhidraReBinary",
    "Export-GhidraReAppleBundle",
    "Get-GhidraReBridgeSessions",
    "Select-GhidraReBridgeSession",
    "Open-GhidraReBridge",
    "Close-GhidraReBridge",
    "Get-GhidraReCurrentContext",
    "Search-GhidraReFunctions",
    "Invoke-GhidraReAnalyzeTarget",
    "Trace-GhidraReSelector",
    "Start-GhidraReMission",
    "Get-GhidraReMissionStatus",
    "Trace-GhidraReMission",
    "Get-GhidraReMissionReport"
)
