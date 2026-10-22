[CmdletBinding()]
param(
    [ValidateRange(1, 65535)][int]$Port = 8765,
    [ValidateRange(1, 50)][int]$Limit = 10,
    [string]$Query = "in:inbox",
    [string]$Credentials = "",
    [switch]$AuthOnly,
    [switch]$CheckConfig,
    [switch]$Reauth,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$pythonCommand = $null
$pythonPrefix = @()
$candidates = @(
    @{ Command = "python"; Prefix = @() },
    @{ Command = "py"; Prefix = @("-3") }
)
foreach ($candidate in $candidates) {
    $resolvedCommand = Get-Command $candidate.Command -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $resolvedCommand) { continue }
    $candidatePrefix = $candidate.Prefix
    try {
        $null = & $resolvedCommand.Source @candidatePrefix -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $pythonCommand = $resolvedCommand.Source
            $pythonPrefix = $candidatePrefix
            break
        }
    } catch { continue }
}
if ($null -eq $pythonCommand) {
    throw "Python was not found. Install Python 3.10 or newer, then run this script again."
}

$pythonArguments = @("--port", "$Port", "--limit", "$Limit", "--query", $Query)
if ($Credentials) { $pythonArguments += @("--credentials", $Credentials) }
if ($AuthOnly) { $pythonArguments += "--auth-only" }
if ($CheckConfig) { $pythonArguments += "--check-config" }
if ($Reauth) { $pythonArguments += "--reauth" }
if ($NoBrowser) { $pythonArguments += "--no-browser" }

$previousUtf8 = $env:PYTHONUTF8
$previousIoEncoding = $env:PYTHONIOENCODING
try {
    $env:PYTHONUTF8 = "1"
    $env:PYTHONIOENCODING = "utf-8"
    & $pythonCommand @pythonPrefix (Join-Path $PSScriptRoot "gmail_web_oauth.py") @pythonArguments
    $scriptExitCode = $LASTEXITCODE
} finally {
    $env:PYTHONUTF8 = $previousUtf8
    $env:PYTHONIOENCODING = $previousIoEncoding
}
exit $scriptExitCode
