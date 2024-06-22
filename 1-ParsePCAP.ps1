# Display script notes
Write-Host “This script will parse the input PCAP file with tshark and create 3 output txt files containing a lists of private subnets, private IP’s and public IP’s observed within the capture.”

try {
    # Prompt for pcap file path and name
    $pcap_file = Read-Host "Enter the path and filename of the pcap file to analyze"

    # Check if the file exists
    if (-not (Test-Path $pcap_file -PathType Leaf)) {
        Write-Host "File not found. Exiting..."
        exit 1
    }

    # Get the filename without the extension
    $filename = [System.IO.Path]::GetFileNameWithoutExtension($pcap_file)

    # Generate timestamp for output file names
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    # Function to get unique IP addresses from tshark
    function Get-UniqueIPAddresses {
        param (
            [string]$pcapFile,
            [string]$ipType
        )

        $outputFile = "${filename}_${timestamp}_temp_${ipType}.txt"

        # Path to tshark command
        $tshark_path = "C:\Program Files\Wireshark\tshark.exe"

        # Run tshark to extract IP addresses and save them in a temporary file
        & $tshark_path -r $pcapFile -T fields -e $ipType | Sort-Object -Unique | Out-File -FilePath $outputFile -Encoding UTF8

        return $outputFile
    }

    # Step 1: Get unique source IP addresses
    $source_ips_file = Get-UniqueIPAddresses -pcapFile $pcap_file -ipType "ip.src"

    # Step 2: Get unique destination IP addresses
    $destination_ips_file = Get-UniqueIPAddresses -pcapFile $pcap_file -ipType "ip.dst"

function Get-UniquePrivateAddresses {
    param (
        [string]$inputFile
    )

    $outputFile = "${filename}_${timestamp}_PRIVATE-IP.txt"

    # Read the IP addresses from the input file
    $ipAddresses = Get-Content $inputFile

    # Filter valid IP addresses
    $validIPs = $ipAddresses | Where-Object { $_ -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" }

    # Convert IP addresses to IPAddress objects
    $ipAddressObjects = $validIPs | ForEach-Object { [System.Net.IPAddress]::Parse($_) }

    # Filter unique private (RFC1918) IP addresses
    $private_ips = $ipAddressObjects | Where-Object {
        $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
        ($_.GetAddressBytes()[0] -eq 10 -or
         ($_.GetAddressBytes()[0] -eq 172 -and $_.GetAddressBytes()[1] -ge 16 -and $_.GetAddressBytes()[1] -le 31) -or
         ($_.GetAddressBytes()[0] -eq 192 -and $_.GetAddressBytes()[1] -eq 168))
    } | ForEach-Object { $_.ToString() } | Sort-Object -Unique

    # Filter out entries with multiple IP addresses (NAT scenarios)
    $filtered_ips = $private_ips | Where-Object { $_ -notlike '*,*' }

    # Save the unique private IP addresses to the output file
    $filtered_ips | Out-File -FilePath $outputFile -Encoding UTF8

    return $outputFile
}


    # Step 3: Get unique private source IP addresses
    $private_source_ips_file = Get-UniquePrivateAddresses -inputFile $source_ips_file

    # Step 4: Get unique private destination IP addresses
    $private_destination_ips_file = Get-UniquePrivateAddresses -inputFile $destination_ips_file

    # Function to enumerate private subnets
    function Enumerate-PrivateSubnets {
        param (
            [string]$inputFile
        )

        $outputFile = "${filename}_${timestamp}_PRIVATE-SUBNET.txt"

        # Read the IP addresses from the input file
        $ipAddresses = Get-Content $inputFile

        # Enumerate private subnets
        $subnets = $ipAddresses | Group-Object { ($_ -split '\.')[0..2] -join '.' } | ForEach-Object {
            $subnet = $_.Name + '.0'
            $subnet + "/24"
        } | Sort-Object -Unique

        # Save the enumerated private subnets to the output file
        $subnets | Out-File -FilePath $outputFile -Encoding UTF8

        return $outputFile
    }

    # Step 5: Enumerate private source IP subnets
    $private_source_subnets_file = Enumerate-PrivateSubnets -inputFile $private_source_ips_file

    # Step 6: Enumerate private destination IP subnets
    $private_destination_subnets_file = Enumerate-PrivateSubnets -inputFile $private_destination_ips_file

    # Function to filter unique public IP addresses and remove private IPs
    function Get-UniquePublicIPAddresses {
        param (
            [string]$inputFile,
            [string]$privateSubnetsFile
        )

        $outputFile = "${filename}_${timestamp}_PUBLIC-IP.txt"

        # Read the IP addresses from the input file
        $ipAddresses = Get-Content $inputFile

        # Read the private subnets from the corresponding file
        $privateSubnets = Get-Content $privateSubnetsFile

        # Filter unique public IP addresses and remove private IPs
        $public_ips = $ipAddresses | Where-Object { 
            $_ -notin $privateSubnets -and
            $_ -notmatch "^10\." -and
            $_ -notmatch "^172\.(1[6-9]|2[0-9]|3[0-1])\." -and
            $_ -notmatch "^192\.168\." -and
            $_ -notlike '*,*'
        } | Sort-Object -Unique

        # Save the unique public IP addresses to the output file
        $public_ips | Out-File -FilePath $outputFile -Encoding UTF8

        return $outputFile
    }

    # Step 7: Get unique public source IP addresses
    $public_source_ips_file = Get-UniquePublicIPAddresses -inputFile $source_ips_file -privateSubnetsFile $private_source_subnets_file

    # Step 8: Get unique public destination IP addresses
    $public_destination_ips_file = Get-UniquePublicIPAddresses -inputFile $destination_ips_file -privateSubnetsFile $private_destination_subnets_file

    # Cleanup: Delete temporary files
    Remove-Item -Path $source_ips_file
    Remove-Item -Path $destination_ips_file

    Write-Host "Analysis complete. Output files:"
    Write-Host "Private source IP addresses: $private_source_ips_file"
    Write-Host "Private destination IP addresses: $private_destination_ips_file"
    Write-Host "Private source IP subnets: $private_source_subnets_file"
    Write-Host "Private destination IP subnets: $private_destination_subnets_file"
    Write-Host "Public source IP addresses: $public_source_ips_file"
    Write-Host "Public destination IP addresses: $public_destination_ips_file"
}
catch {
    Write-Host "An error occurred during execution:"
    Write-Host $_.Exception.Message
}
