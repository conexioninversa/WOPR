# Path to the IOC file

$file = "C:\Path\to\file.ioc"

# Read the IOC file and create an array of firewall rules

$rules = Get-Content $file | ForEach-Object {
     # Create a new firewall rule for each entry in the IOC file
     $ioc = $_
     New-NetFirewallRule -DisplayName "IOC $ioc" -Direction Inbound -Action Block -Enabled True -RemoteAddress $ioc
}

# Show the created firewall rules

$rules
