# Display a warning about potential issues due to firewalls
Write-Host "WARNING: The results of this trace may be affected by firewalls or other network configurations."
Write-Host "         Timeouts, incomplete paths, or misleading information may occur."
Write-Host ""

# Prompt the user for the input file
$inputFile = Read-Host "Enter the path to the input file (or press Enter to use any file with '-SUBNET.txt')"

# If no input file is provided, search for any file with "-SUBNET.txt" in the current path
if ([string]::IsNullOrEmpty($inputFile)) {
    $inputFile = Get-ChildItem -Path .\ -Filter "*-SUBNET.txt" | Select-Object -First 1
    if ($null -eq $inputFile) {
        Write-Host "No suitable file found. Exiting."
        exit
    }
    $inputFile = $inputFile.FullName
}

# Prompt the user for the default router octet
$defaultRouterOctet = Read-Host "Enter the default router octet (or press Enter to use .1)"
if ([string]::IsNullOrEmpty($defaultRouterOctet)) {
    $defaultRouterOctet = "1"
}

# Prompt the user for the max hops
$maxHops = Read-Host "Enter the max hops (or press Enter to use 5)"
if ([string]::IsNullOrEmpty($maxHops)) {
    $maxHops = 5
}

# Prepare the output file name
$outputFile = [System.IO.Path]::GetFileNameWithoutExtension($inputFile) + "-TRACE.txt"

# Initialize output array
$outputArray = @()

# Read the file line by line
Get-Content $inputFile | ForEach-Object {
    $subnetParts = $_.Split("/")[0].Split(".")
    $subnetParts[3] = $defaultRouterOctet
    $subnet = [string]::Join(".", $subnetParts)
    Write-Host "Tracing $subnet..."
    
    # Run tracert and parse the output
    $traceResult = tracert -d -h $maxHops $subnet | Select-String "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" -AllMatches | ForEach-Object { $_.Matches.Value }
    
    # Remove redundant entries from the beginning if they match the destination
    if ($traceResult[0] -eq $traceResult[-1]) {
        $traceResult = $traceResult[1..($traceResult.Length - 1)]
    }
    
    # Convert to comma-separated string and add to output array
    $outputArray += ,($traceResult -join ",")
}

# Write the output to the file
$outputArray | Out-File $outputFile

Write-Host "Tracing complete. Results saved to $outputFile."
