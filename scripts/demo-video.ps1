[CmdletBinding()]
param(
    [int]$IntroPauseMs = 350,
    [int]$CommandPauseMs = 250,
    [int]$SectionPauseMs = 700,
    [int]$FinalPauseMs = 1800
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$demoRoot = Join-Path $repoRoot "out\video-demo"
$profileId = "github-level-1"

function Write-SceneTitle {
    param(
        [string]$Text,
        [string]$Color = "White"
    )

    Write-Host ""
    Write-Host $Text -ForegroundColor $Color
}

function Get-StatusText {
    param([object]$Summary)

    $orderedKeys = @("fail", "pass", "self-attested", "manual-review-required", "waived")
    $parts = foreach ($key in $orderedKeys) {
        if ($null -ne $Summary.$key) {
            "$key=$($Summary.$key)"
        }
    }

    $extraKeys = $Summary.PSObject.Properties.Name | Where-Object { $_ -notin $orderedKeys } | Sort-Object
    foreach ($key in $extraKeys) {
        "$key=$($Summary.$key)"
    }

    return ($parts -join " | ")
}

function Invoke-DemoEvaluation {
    param(
        [string]$Label,
        [string]$Target,
        [string]$OutputDir,
        [string]$LabelColor,
        [int]$PostPauseMs = $SectionPauseMs
    )

    Write-SceneTitle $Label $LabelColor

    $commandText = "python -m oss_policy_kit evaluate --target $Target --profile $profileId --summary-only"
    Write-Host $commandText -ForegroundColor DarkGray
    Start-Sleep -Milliseconds $CommandPauseMs

    $jsonText = & python -m oss_policy_kit evaluate `
        --target $Target `
        --profile $profileId `
        --output-dir $OutputDir `
        --summary-only `
        --format json

    if ($LASTEXITCODE -ne 0) {
        throw "Evaluation failed for target '$Target' with exit code $LASTEXITCODE."
    }

    $result = $jsonText | ConvertFrom-Json
    $statusText = Get-StatusText $result.summary_by_status

    Write-Host ""
    Write-Host "summary: $statusText" -ForegroundColor $LabelColor
    Write-Host "controls: $($result.controls_total)" -ForegroundColor White

    Start-Sleep -Milliseconds $PostPauseMs
}

Push-Location $repoRoot
try {
    Clear-Host

    New-Item -ItemType Directory -Force -Path $demoRoot | Out-Null

    & python -m oss_policy_kit --version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not run 'python -m oss_policy_kit --version'. Activate the environment where the kit is installed first."
    }

    Write-Host "OSS Policy Kit Demo" -ForegroundColor Cyan
    Write-Host "hardened first, vulnerable next" -ForegroundColor DarkGray

    Start-Sleep -Milliseconds $IntroPauseMs

    Invoke-DemoEvaluation `
        -Label "HARDENED" `
        -Target "./examples/hardened-repo" `
        -OutputDir "./out/video-demo/hardened" `
        -LabelColor "Green"

    Invoke-DemoEvaluation `
        -Label "VULNERABLE" `
        -Target "./examples/vulnerable-repo" `
        -OutputDir "./out/video-demo/vulnerable" `
        -LabelColor "Red" `
        -PostPauseMs $FinalPauseMs
}
finally {
    Pop-Location
}
