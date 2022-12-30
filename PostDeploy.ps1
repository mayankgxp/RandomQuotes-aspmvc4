# If for whatever reason this doesn't work, check this file:
Start-Transcript -path "C:\Startup.log" -append

# Generic functions
# Log a message
function Log {
    param (
        [Parameter(Mandatory=$True)]
        [string]$msg
    )

    $time = Get-Date
    Write-Host $time.ToUniversalTime() "-" $msg
}

# Download a file
function Download-File 
{
  param (
    [string]$url,
    [string]$saveAs
  )

  Write-Output "Downloading $url to $saveAs"
  $downloader = new-object System.Net.WebClient

  # Download the file
  $downloader.DownloadFile($url, $saveAs)
}

# Windows
# Install IIS with all features
function Install-IIS {
	Log "Installing IIS"
	$iisInstalled = Install-WindowsFeature Web-Server -IncludeManagementTools -IncludeAllSubFeature
	if ($iisInstalled.Success) {
	    Log "Success"
	}
	else {
	    Log "IIS Install failed"
	}
	return $iisInstalled.Success
}

# AWS
# Get EC2 variables
function Get-EC2Variables {
	# Nested functions
	# Get Tag
	function Get-Tag {
		param (
			[string]$key
		)

		Log "Getting tag $key"

		$tag = Get-EC2Tag | ` Where-Object {$_.ResourceId -eq $instanceId -and $_.Key -eq $name}
		$value = $tag.Value

		Log "Got tag $key = $value"
		return $value;
	}

	# Get Tags
	function Get-Tags {
		param (
			[string]$instanceId
		)

		Log "Getting tags"

		$tags = @{};
		$awsTags = Get-EC2Tag | ` Where-Object {$_.ResourceId -eq $instanceId}
		foreach ($tag in $awsTags) {
            $msg = [string]::Format("Got tag {0} : {1}", $tag.Key, $tag.Value)			
            Log $msg
			$tags.Add($tag.Key, $tag.Value)
		}

		Log "Got all tags"
		return $tags
	}

	# Get InstanceId
	function Get-InstanceId {
		Log "Getting instance id"

		$downloader = New-Object System.Net.WebClient
  		$instanceId = $downloader.DownloadString("http://169.254.169.254/latest/meta-data/instance-id")

		Log "Got instance id $instanceId"
		return $instanceId
	}

	# Get IP Public Address
	function Get-PublicIPAddress
	{
		Log "Getting public IP"

		$downloader = new-object System.Net.WebClient
		$ip = $downloader.DownloadString("http://169.254.169.254/latest/meta-data/public-ipv4")

		Log "Got public IP $ip"
		return $ip
	}

	# Get the variables
	# Set IAM role
	Initialize-AWSDefaults -region ap-southeast-2

	# Get AWS variables
	$instanceId = Get-InstanceId

	# Set the args
	$args = Get-Tags $instanceId

    $ip = Get-PublicIPAddress
	$args.Add("public-ip", $ip)
	$args.Add("instanceId", $instanceId)

	return $args
}

# Octopus
# Install the Tentacle and register with Octopus
function Install-Tentacle {
	param (
		[Parameter(Mandatory=$True)]
		[string]$apiKey,
		[Parameter(Mandatory=$True)]
		[System.Uri]$octopusServerUrl,
		[Parameter(Mandatory=$True)]
		[string]$octopusServerThumbprint,
		[Parameter(Mandatory=$True)]
		[string]$environment,
		[Parameter(Mandatory=$True)]
		[string]$role,
		[Parameter(Mandatory=$True)]
		[string]$instanceId
	)

	Log "Installing Tentacle"

	# Generic Octopus
	$tentacleListenPort = 10933
	$tentacleHomeDirectory = "$env:SystemDrive:\Octopus"
	$tentacleAppDirectory = "$env:SystemDrive:\Octopus\Applications"
	$tentacleConfigFile = "$env:SystemDrive\Octopus\Tentacle\Tentacle.config"
	$tentacleDownloadUrl = "http://octopusdeploy.com/downloads/latest/OctopusTentacle64"

	# Open firewall
	Log "Opening port $tentacleListenPort in Windows firewall"

	& netsh.exe firewall add portopening TCP $tentacleListenPort "Octopus Tentacle"
	if ($lastExitCode -ne 0) {
		throw "Installation failed when modifying firewall rules"
	}

	Log "Firewall rules set"

	# Download the tentacle installer
	Log "Downloading tentacle installer"
	
	$tentaclePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(".\Tentacle.msi")
	if ((test-path $tentaclePath) -ne $true) {
		Download-File $tentacleDownloadPath $tentaclePath
	}

	Log "Downloaded"

	# Install the tentacle
	Log "Installing tentacle MSI"

	$msiExitCode = (Start-Process -FilePath "msiexec.exe" -ArgumentList "/i Tentacle.msi /quiet" -Wait -Passthru).ExitCode
	
	Log "Tentacle MSI installer returned exit code $msiExitCode"
	
	if ($msiExitCode -ne 0) {
		throw "Installation aborted"
	}

	# Configure the tentacle
	cd "${env:ProgramFiles}\Octopus Deploy\Tentacle"

	# Create instance
	& .\tentacle.exe create-instance --instance "Tentacle" --config $tentacleConfigFile --console | Write-Host
	if ($lastExitCode -ne 0) {
		throw "Installation failed on create-instance"
	}

	# Home
	& .\tentacle.exe configure --instance "Tentacle" --home $tentacleHomeDirectory --console | Write-Host
	if ($lastExitCode -ne 0) {
		throw "Installation failed on configure"
	}

	# App
	& .\tentacle.exe configure --instance "Tentacle" --app $tentacleAppDirectory --console | Write-Host
	if ($lastExitCode -ne 0) {
		throw "Installation failed on configure"
	}

	# Port
	& .\tentacle.exe configure --instance "Tentacle" --port $tentacleListenPort --console | Write-Host
	if ($lastExitCode -ne 0) {
		throw "Installation failed on configure"
	}

	# Certificate
	& .\tentacle.exe new-certificate --instance "Tentacle" --console | Write-Host
	if ($lastExitCode -ne 0) {
		throw "Installation failed on creating new certificate"
	}

	# Trust
	& .\tentacle.exe configure --instance "Tentacle" --trust $octopusServerThumbprint --console  | Write-Host
	if ($lastExitCode -ne 0) {
		throw "Installation failed on configure"
	}

	# Register
	& .\tentacle.exe register-with --instance "Tentacle" --server $octopusServerUrl --environment $environment --role $role --name $instanceId --publicHostName $ipAddress --apiKey $apiKey --comms-style TentaclePassive --force --console | Write-Host
	if ($lastExitCode -ne 0) {
		throw "Installation failed on register-with"
	}

	# Windows Service
	& .\tentacle.exe service --instance "Tentacle" --install --start --console | Write-Host
	if ($lastExitCode -ne 0) {
		throw "Installation failed on service install"
	}

	Log "Finished installing Tentacle"
}

# Run the script
# Install IIS
Install-IIS

# Populate variables
$args = Get-EC2Variables

$apiKey = $args["Octopus-API"]
$octopusServerUrl = $args["Octopus-Server"]
$environment = $args["Octopus-Environment"]
$octopusServerThumbprint = $args["Octopus-Thumbprint"]
$roles = $args["Octopus-Roles"]

$instanceId = $args["instance-id"]

# Install Tentacle
Install-Tentacle $apiKey $octopusServerUrl $octopusServerThumbprint $environment $roles $instanceId
