# SPDX-FileCopyrightText: 2026 amurcanov
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

[CmdletBinding()]
param(
    [ValidateRange(1, 2147483647)]
    [int]$ProptestCasesPerSeed = 10000,

    [ValidateRange(1, 86400)]
    [int]$SoakSecondsPerTest = 120,

    [ValidateRange(1, 1000000)]
    [int]$TurnChaosCycles = 100,

    [ValidateRange(1, 1000000)]
    [int]$QueueActionsPerSeed = 4096,

    [ValidateRange(1296, 214736300)]
    [int]$TransportChaosSteps = 240000,

    [ValidateRange(1, 1000000)]
    [int]$ReplayCountersPerSeed = 4096,

    [ValidateRange(2, 4096)]
    [int]$TurnChaosTransactions = 64,

    [ValidateRange(60, 2147483)]
    [int]$StepTimeoutSeconds = 1800,

    [ValidateRange(1, 64)]
    [int]$TestThreads = 1,

    [ValidateNotNullOrEmpty()]
    [UInt64[]]$Seeds = @(104729, 32452843, 49979687),

    [ValidateNotNullOrEmpty()]
    [string[]]$SoakTests = @(
        "deterministic_queue_chaos_soak",
        "deterministic_transport_chaos_soak",
        "deterministic_replay_chaos_soak",
        "deterministic_turn_chaos_soak",
        "one_gibibyte_with_9_27_108_162_workers_and_500_kib_per_worker_limit"
    ),

    [switch]$HarnessSelfTestOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$script:FailureCode = 0
$trackedEnvironment = @(
    "PROPTEST_CASES",
    "PROPTEST_RNG_SEED",
    "PROPTEST_DISABLE_FAILURE_PERSISTENCE",
    "CSQTT_SOAK_SECONDS",
    "CSQTT_SOAK_SEED",
    "CSQTT_TURN_CHAOS_CYCLES",
    "CSQTT_QUEUE_SOAK_ACTIONS",
    "CSQTT_TRANSPORT_CHAOS_STEPS",
    "CSQTT_REPLAY_SOAK_COUNTERS",
    "CSQTT_TURN_CHAOS_TRANSACTIONS"
)
$savedEnvironment = @{}

function Set-ProcessEnvironment {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [AllowNull()]
        [string]$Value
    )

    [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
}

function ConvertTo-NativeArgument {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }

    $builder = New-Object Text.StringBuilder
    [void]$builder.Append([char]34)
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ([int]$character -eq 92) {
            $backslashes++
            continue
        }
        if ([int]$character -eq 34) {
            [void]$builder.Append([char]92, 2 * $backslashes + 1)
            [void]$builder.Append([char]34)
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append([char]92, $backslashes)
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append([char]92, 2 * $backslashes)
    }
    [void]$builder.Append([char]34)
    return $builder.ToString()
}

function Start-CheckedProcess {
    param(
        [Parameter(Mandatory)]
        [string]$Executable,

        [Parameter(Mandatory)]
        [string[]]$ArgumentList,

        [switch]$Capture
    )

    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Executable
    $startInfo.Arguments = (($ArgumentList | ForEach-Object {
        ConvertTo-NativeArgument -Value $_
    }) -join " ")
    $startInfo.WorkingDirectory = $PSScriptRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $Capture.IsPresent
    $startInfo.RedirectStandardError = $Capture.IsPresent
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Failed to start $Executable"
    }
    return $process
}

function Stop-ExactProcessTree {
    param(
        [Parameter(Mandatory)]
        [Diagnostics.Process]$Process
    )

    $Process.Refresh()
    if ($Process.HasExited) {
        return
    }
    & taskkill.exe /PID $Process.Id /T /F *> $null
    $killCode = $LASTEXITCODE
    $Process.WaitForExit()
    $Process.Refresh()
    if ($killCode -ne 0 -or -not $Process.HasExited) {
        throw "Failed to terminate process tree rooted at PID $($Process.Id)"
    }
}

function Invoke-NativeStep {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Executable,

        [Parameter(Mandatory)]
        [string[]]$ArgumentList,

        [ValidateRange(1, 2147483)]
        [int]$TimeoutSeconds = $StepTimeoutSeconds
    )

    Write-Output ""
    Write-Output "=== $Name ==="
    $process = $null
    try {
        $process = Start-CheckedProcess -Executable $Executable -ArgumentList $ArgumentList
        $timeoutMilliseconds = [int]([long]$TimeoutSeconds * 1000L)
        if (-not $process.WaitForExit($timeoutMilliseconds)) {
            $script:FailureCode = 124
            Stop-ExactProcessTree -Process $process
            throw "$Name timed out after $TimeoutSeconds seconds"
        }
        $process.WaitForExit()
        $process.Refresh()
        $nativeCode = $process.ExitCode
        if ($null -eq $nativeCode -or $nativeCode -isnot [int]) {
            $script:FailureCode = 1
            throw "$Name completed without a readable exit code"
        }
        if ([int]$nativeCode -ne 0) {
            if ([int]$nativeCode -gt 0 -and [int]$nativeCode -le 255) {
                $script:FailureCode = [int]$nativeCode
            } else {
                $script:FailureCode = 1
            }
            throw "$Name failed with exit code $nativeCode"
        }
    } finally {
        if ($null -ne $process) {
            $process.Refresh()
            if (-not $process.HasExited) {
                Stop-ExactProcessTree -Process $process
            }
            $process.Dispose()
        }
    }
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Executable,

        [Parameter(Mandatory)]
        [string[]]$ArgumentList,

        [ValidateRange(1, 2147483)]
        [int]$TimeoutSeconds = $StepTimeoutSeconds
    )

    $process = $null
    try {
        $process = Start-CheckedProcess -Executable $Executable -ArgumentList $ArgumentList -Capture
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $timeoutMilliseconds = [int]([long]$TimeoutSeconds * 1000L)
        if (-not $process.WaitForExit($timeoutMilliseconds)) {
            $script:FailureCode = 124
            Stop-ExactProcessTree -Process $process
            throw "$Name timed out after $TimeoutSeconds seconds"
        }
        $process.WaitForExit()
        $process.Refresh()
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        $output = @(($stdout, $stderr) -split "\r?\n" | Where-Object { $_.Length -gt 0 })
        $output | ForEach-Object { [Console]::Out.WriteLine($_) }
        $nativeCode = $process.ExitCode
        if ($null -eq $nativeCode -or $nativeCode -isnot [int]) {
            $script:FailureCode = 1
            throw "$Name completed without a readable exit code"
        }
        if ([int]$nativeCode -ne 0) {
            if ([int]$nativeCode -gt 0 -and [int]$nativeCode -le 255) {
                $script:FailureCode = [int]$nativeCode
            } else {
                $script:FailureCode = 1
            }
            throw "$Name failed with exit code $nativeCode"
        }
        return $output
    } finally {
        if ($null -ne $process) {
            $process.Refresh()
            if (-not $process.HasExited) {
                Stop-ExactProcessTree -Process $process
            }
            $process.Dispose()
        }
    }
}

function Assert-NativeStepFailClosed {
    $savedFailureCode = $script:FailureCode
    Invoke-NativeStep `
        -Name "Harness child exit 0 probe" `
        -Executable $env:ComSpec `
        -ArgumentList @("/D", "/S", "/C", "exit 0") `
        -TimeoutSeconds 30

    $caughtFailure = $false
    try {
        Invoke-NativeStep `
            -Name "Harness child exit 7 probe" `
            -Executable $env:ComSpec `
            -ArgumentList @("/D", "/S", "/C", "exit 7") `
            -TimeoutSeconds 30
    } catch {
        $caughtFailure = $true
        if ($script:FailureCode -ne 7) {
            throw "Harness exit 7 probe was caught with code $($script:FailureCode), expected 7"
        }
        if ($_.Exception.Message -notmatch 'exit code 7$') {
            throw "Harness exit 7 probe produced an unexpected failure: $($_.Exception.Message)"
        }
    } finally {
        $script:FailureCode = $savedFailureCode
    }
    if (-not $caughtFailure) {
        throw "Harness accepted a child process that exited with code 7"
    }
    Write-Output "Harness child exit probes passed"
}

function Get-SoakTimeoutSeconds {
    param(
        [Parameter(Mandatory)]
        [int]$MinimumSeconds,

        [Parameter(Mandatory)]
        [int]$PerTestSeconds,

        [Parameter(Mandatory)]
        [int]$ChaosCycles,

        [Parameter(Mandatory)]
        [int]$TransportSteps
    )

    $perTestDeadline = [long]$PerTestSeconds + 120L
    $chaosDeadline = [long]$ChaosCycles * 2L + 120L
    $transportDeadline = [long][Math]::Ceiling([double]$TransportSteps / 100.0) + 120L
    $timeout = [Math]::Max(
        [long]$MinimumSeconds,
        [Math]::Max($perTestDeadline, [Math]::Max($chaosDeadline, $transportDeadline))
    )
    if ($timeout -gt 2147483L) {
        throw "Computed soak timeout $timeout exceeds WaitForExit capacity"
    }
    return [int]$timeout
}

function Assert-SoakTimeoutRange {
    $maximum = Get-SoakTimeoutSeconds `
        -MinimumSeconds 2147483 `
        -PerTestSeconds 86400 `
        -ChaosCycles 1000000 `
        -TransportSteps 214736300
    if ($maximum -ne 2147483) {
        throw "Maximum soak timeout self-test returned $maximum"
    }
    $derived = Get-SoakTimeoutSeconds `
        -MinimumSeconds 60 `
        -PerTestSeconds 1 `
        -ChaosCycles 1000000 `
        -TransportSteps 1296
    if ($derived -ne 2000120) {
        throw "Derived soak timeout self-test returned $derived"
    }
}

function Get-IgnoredTests {
    Write-Output ""
    Write-Output "=== Discover ignored tests ==="
    $output = @(
        Invoke-NativeCapture `
            -Name "Ignored test discovery" `
            -Executable "cargo" `
            -ArgumentList @("test", "--release", "--all-targets", "--", "--list", "--ignored")
    )

    return @(
        $output |
            ForEach-Object { [string]$_ } |
            ForEach-Object {
                if ($_ -match "^(.+): test$") {
                    $Matches[1]
                }
            }
    )
}

Assert-NativeStepFailClosed
Assert-SoakTimeoutRange
if ($HarnessSelfTestOnly) {
    Write-Output "Rust client stability harness self-test passed"
    exit 0
}

foreach ($name in $trackedEnvironment) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

Push-Location $PSScriptRoot
try {
    if ($Seeds.Count -eq 0) {
        throw "At least one seed is required"
    }

    $powerShellExecutable = (Get-Process -Id $PID).Path
    $lintScript = Join-Path $PSScriptRoot "check_no_runtime_panics.ps1"
    Set-ProcessEnvironment "PROPTEST_DISABLE_FAILURE_PERSISTENCE" $null
    Set-ProcessEnvironment "PROPTEST_CASES" "256"
    Set-ProcessEnvironment "PROPTEST_RNG_SEED" $Seeds[0].ToString([Globalization.CultureInfo]::InvariantCulture)

    Invoke-NativeStep `
        -Name "Runtime panic lint" `
        -Executable $powerShellExecutable `
        -ArgumentList @("-NoLogo", "-NoProfile", "-NonInteractive", "-File", $lintScript)

    Invoke-NativeStep `
        -Name "Release test suite" `
        -Executable "cargo" `
        -ArgumentList @("test", "--release", "--all-targets", "--", "--test-threads", $TestThreads.ToString([Globalization.CultureInfo]::InvariantCulture))

    foreach ($seed in $Seeds) {
        $seedText = $seed.ToString([Globalization.CultureInfo]::InvariantCulture)
        Set-ProcessEnvironment "PROPTEST_CASES" $ProptestCasesPerSeed.ToString([Globalization.CultureInfo]::InvariantCulture)
        Set-ProcessEnvironment "PROPTEST_RNG_SEED" $seedText
        Set-ProcessEnvironment "CSQTT_SOAK_SEED" $seedText

        Invoke-NativeStep `
            -Name "High-case property suite seed $seedText" `
            -Executable "cargo" `
            -ArgumentList @("test", "--release", "--all-targets", "--", "--test-threads", $TestThreads.ToString([Globalization.CultureInfo]::InvariantCulture))
    }

    $ignoredTests = @(Get-IgnoredTests)
    $selectedTests = [Collections.Generic.List[string]]::new()
    $missingTests = [Collections.Generic.List[string]]::new()

    foreach ($requestedTest in $SoakTests) {
        $matches = @(
            $ignoredTests | Where-Object {
                $_ -eq $requestedTest -or $_.EndsWith("::$requestedTest", [StringComparison]::Ordinal)
            }
        )
        if ($matches.Count -eq 0) {
            $missingTests.Add($requestedTest)
        } else {
            foreach ($match in $matches) {
                if (-not $selectedTests.Contains($match)) {
                    $selectedTests.Add($match)
                }
            }
        }
    }

    if ($missingTests.Count -gt 0) {
        $message = "Ignored soak tests not present: $($missingTests -join ', ')"
        throw $message
    }

    if ($selectedTests.Count -eq 0) {
        throw "No ignored soak tests selected"
    }

    Set-ProcessEnvironment "CSQTT_SOAK_SECONDS" $SoakSecondsPerTest.ToString([Globalization.CultureInfo]::InvariantCulture)
    Set-ProcessEnvironment "CSQTT_TURN_CHAOS_CYCLES" $TurnChaosCycles.ToString([Globalization.CultureInfo]::InvariantCulture)
    Set-ProcessEnvironment "CSQTT_QUEUE_SOAK_ACTIONS" $QueueActionsPerSeed.ToString([Globalization.CultureInfo]::InvariantCulture)
    Set-ProcessEnvironment "CSQTT_TRANSPORT_CHAOS_STEPS" $TransportChaosSteps.ToString([Globalization.CultureInfo]::InvariantCulture)
    Set-ProcessEnvironment "CSQTT_REPLAY_SOAK_COUNTERS" $ReplayCountersPerSeed.ToString([Globalization.CultureInfo]::InvariantCulture)
    Set-ProcessEnvironment "CSQTT_TURN_CHAOS_TRANSACTIONS" $TurnChaosTransactions.ToString([Globalization.CultureInfo]::InvariantCulture)
    $soakTimeoutSeconds = Get-SoakTimeoutSeconds `
        -MinimumSeconds $StepTimeoutSeconds `
        -PerTestSeconds $SoakSecondsPerTest `
        -ChaosCycles $TurnChaosCycles `
        -TransportSteps $TransportChaosSteps

    foreach ($seed in $Seeds) {
        $seedText = $seed.ToString([Globalization.CultureInfo]::InvariantCulture)
        Set-ProcessEnvironment "PROPTEST_RNG_SEED" $seedText
        Set-ProcessEnvironment "CSQTT_SOAK_SEED" $seedText

        foreach ($testName in $selectedTests) {
            Invoke-NativeStep `
                -Name "Ignored soak $testName seed $seedText" `
                -Executable "cargo" `
                -ArgumentList @("test", "--release", "--all-targets", $testName, "--", "--ignored", "--exact", "--nocapture", "--test-threads", "1") `
                -TimeoutSeconds $soakTimeoutSeconds
        }
    }

    Write-Output ""
    Write-Output "Stability soak passed"
    Write-Output "Seeds: $($Seeds -join ', ')"
    Write-Output "Property cases per seed: $ProptestCasesPerSeed"
    Write-Output "Queue actions per seed: $QueueActionsPerSeed"
    Write-Output "Transport chaos steps per seed: $TransportChaosSteps"
    Write-Output "Replay counters per seed: $ReplayCountersPerSeed"
    Write-Output "TURN transactions per cycle: $TurnChaosTransactions"
    Write-Output "Executed ignored soak tests: $($selectedTests.Count)"
} catch {
    if ($script:FailureCode -eq 0) {
        $script:FailureCode = 1
    }
    [Console]::Error.WriteLine($_.Exception.Message)
} finally {
    foreach ($name in $trackedEnvironment) {
        Set-ProcessEnvironment $name $savedEnvironment[$name]
    }
    Pop-Location
}

if ($script:FailureCode -ne 0) {
    exit $script:FailureCode
}
