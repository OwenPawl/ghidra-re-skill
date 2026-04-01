@{
    RootModule = 'GhidraRe.psm1'
    ModuleVersion = '0.1.0'
    GUID = '6f1b682c-e6a7-4e46-a5dd-b1b57e5583f0'
    Author = 'OpenAI Codex'
    CompanyName = 'OpenAI'
    Copyright = '(c) OpenAI'
    Description = 'Native PowerShell wrappers for the ghidra-re Codex skill.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Initialize-GhidraRe',
        'Invoke-GhidraReDoctor',
        'Add-GhidraReSource',
        'Get-GhidraReSources',
        'Resolve-GhidraReSource',
        'Import-GhidraReBinary',
        'Export-GhidraReAppleBundle',
        'Get-GhidraReBridgeSessions',
        'Select-GhidraReBridgeSession',
        'Open-GhidraReBridge',
        'Close-GhidraReBridge',
        'Close-GhidraReAllBridges',
        'Get-GhidraReCurrentContext',
        'Get-GhidraReBridgeSnapshot',
        'Search-GhidraReFunctions',
        'Invoke-GhidraReAnalyzeTarget',
        'Trace-GhidraReSelector',
        'Start-GhidraReMission',
        'Get-GhidraReMissionStatus',
        'Trace-GhidraReMission',
        'Get-GhidraReMissionReport',
        'Complete-GhidraReMission',
        'Start-GhidraReAutopilot',
        'Get-GhidraReNotesStatus',
        'Add-GhidraReNote',
        'Sync-GhidraReNotes',
        'Receive-GhidraReNotes',
        'Set-GhidraReNoteStatus',
        'Open-GhidraReSharedNotes'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('ghidra', 'reverse-engineering', 'codex', 'ghidra-re')
            ProjectUri = 'https://github.com/OwenPawl/ghidra-re-skill'
        }
    }
}
