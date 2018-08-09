

Function Log{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [String]$text,
        [Parameter(Mandatory=$false)] [bool]$event,
        [Parameter(Mandatory=$false)] [bool]$error
    )
    if ($event)
    {
        if ($error)
        {
            Write-EventLog -LogName $logName -Source $logName -EventId 2 -EntryType Error -Message $text;
        }
        else
        {
            Write-EventLog -logname $logName -source $logName -eventID 1 -entrytype Information -message $text;
        }
    }
    if ($debugEnabled)
    {
        Write-Host $text;
        #DebugLog $text;
    }
}

Function Add-FLSF5LTMNodes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [String]$F5FQDN,
        [Parameter(Mandatory=$true)] [pscredential]$F5Cred,
        [Parameter(Mandatory=$true)] [String[]]$NodeFQDNs
    )

    $URI = "https://$F5FQDN/mgmt/tm/ltm/node";
    foreach ($NodeFQDN in $NodeFQDNs) {

        try {
            #$nodeIP = $(Resolve-DnsName -Name $NodeFQDN -Type A).IPAddress
            

            #Construct request
            $JSONBody = @{name=$nodeFQDN;partition='Common'}


            #$JSONBody
            $JSONBody.fqdn = @{tmName="$nodeFQDN"; autopopulate="enabled"}
            $JSONBody.logging = "enabled"

            #Convert request to JSON
            $JSONBody = $JSONBody | ConvertTo-Json

            #Make the request
            $response = Invoke-WebRequest -Method POST -Uri "$URI" -Credential $F5Cred -Body $JSONBody -Headers @{"Content-Type"="application/json"}

            $response
        }
        catch {Log $_.exception.message}
    }
}

Function Get-FLSF5Node {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [String]$F5FQDN,
        [Parameter(Mandatory=$true)] [pscredential]$F5Cred,
        [Parameter(Mandatory=$true)] [String[]]$NodeFQDN
    )
$URI = "https://$F5FQDN/mgmt/tm/ltm/node/~Common~$NodeFQDN"
$response = Invoke-WebRequest -Method GET -Uri "$URI" -Credential $f5Cred -Headers @{"Content-Type"="application/json"}

return $response | ConvertFrom-Json
}

Function Remove-FLSF5LTMNodes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [String]$F5FQDN,
        [Parameter(Mandatory=$true)] [pscredential]$F5Cred,
        [Parameter(Mandatory=$true)] [String[]]$NodeFQDNs
    )

    foreach ($nodeFQDN in $NodeFQDNs) {
        try {
            Log "Removing $nodeFQDN..."
            $URI = "https://$F5FQDN/mgmt/tm/ltm/node/~Common~$nodeFQDN"
            Log "URI: $URI"
            $response = Invoke-WebRequest -Method DELETE -Uri "$URI" -Credential $F5Cred -Headers @{"Content-Type"="application/json"}

            if ($response) { $response }
        }
        catch {Log $_.exception.message; }
    }
}

Function Add-FLSF5LTMPool {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [String]$F5FQDN,
        [Parameter(Mandatory=$true)] [pscredential]$F5Cred,
        [Parameter(Mandatory=$true)] [String]$PoolName,
        [Parameter(Mandatory=$true)] [String]$Port,
        [Parameter(Mandatory=$true)] [String[]]$PoolMembers
    )

    try {
        $URI = "https://$F5FQDN/mgmt/tm/ltm/pool"

        #Construct request
        $JSONBody = @{name=$PoolName;partition='Common';members=@()}
        #Create array of member objects
        $Members = @()
        foreach ($poolMember in $PoolMembers) {
            Log $("Adding mamaber: $poolMember/:$Port")

            $Members += @{name=$($poolMember + ":" +$Port)}
        }
        #$Members += @{name="web01.casamda.com:80"}
        
        #Add members to request
        $JSONBody.members = $Members
        $JSONBody.monitor = "http"
        
        #Convert request to JSON
        $JSONBody = $JSONBody | ConvertTo-Json
        
        #Make the request
        Log "URI: $URI"
        Log "JSONBody: $JSONBody"
        $response = Invoke-WebRequest -Method POST -Uri "$URI" -Credential $F5Cred -Body $JSONBody -Headers @{"Content-Type"="application/json"}
        
        $response
    
    }
    catch {Log $_.exception.message}


}

Function Remove-FLSF5LTMPool {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [String]$F5FQDN,
        [Parameter(Mandatory=$true)] [pscredential]$F5Cred,
        [Parameter(Mandatory=$true)] [String[]]$PoolName
    )
    try {
        #Delete pool
        $URI = "https://10.10.60.5/mgmt/tm/ltm/pool/~Common~$PoolName"
        $response = Invoke-WebRequest -Method DELETE -Uri "$URI" -Credential $F5Cred -Headers @{"Content-Type"="application/json"}
        return $response
    }
    catch {Log $_.exception.message}

}

Function Get-FLSF5LTMPool {
#Get Pools
$URI = "https://10.10.60.5/mgmt/tm/ltm/pool"
$response = Invoke-WebRequest -Method GET -Uri "$URI" -Credential $f5Cred -Headers @{"Content-Type"="application/json"}

$response.Content
}

Function Get-FLSF5LTMVirtualSErver {
#Get Virtual
$URI = "https://10.10.60.5/mgmt/tm/ltm/virtual"
$response = Invoke-WebRequest -Method GET -Uri "$URI" -Credential $f5Cred -Headers @{"Content-Type"="application/json"}

$res = $response.Content | ConvertFrom-Json
$res.items

}

Function Remove-FLSF5LTMVirtualServer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [String]$F5FQDN,
        [Parameter(Mandatory=$true)] [pscredential]$F5Cred,
        [Parameter(Mandatory=$true)] [String[]]$VirtualServerName
    )

    try {
        $URI = "https://$F5FQDN/mgmt/tm/ltm/virtual/~Common~$VirtualServerName"
        $response = Invoke-WebRequest -Method DELETE -Uri "$URI" -Credential $F5Cred -Headers @{"Content-Type"="application/json"}
        return $response

    }
    Catch {Log $_.exception.message;}


}

Function Add-FLSF5LTMVirtualServer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [String]$F5FQDN,
        [Parameter(Mandatory=$true)] [pscredential]$F5Cred,
        [Parameter(Mandatory=$true)] [String]$VirtualServerName,
        [Parameter(Mandatory=$true)] [String]$PoolName,
        [Parameter(Mandatory=$false)] [String]$SourceIP = "0.0.0.0/0",
        [Parameter(Mandatory=$true)] [String]$DestinationIP,
        [Parameter(Mandatory=$true)] [ValidateRange(1,65535)] [int]$Port,
        [Parameter(Mandatory=$true)] [ValidateSet(
        "tcp","udp"
        )][String]$IpProtocol,
        [Parameter(Mandatory=$false)] [ValidateSet(
        "source_addr","COOKIEINSERT","SSLSESSION","RULE","URLPASSIVE","CUSTOMSERVERID","DESTIP","SRCIPDESTIP","CALLID","RTSPSID","DIAMETER","NONE"
        )] [string]$PersistenceType="none"
    )
    try {
        #Create Virtual
        
        $URI = "https://$F5FQDN/mgmt/tm/ltm/virtual"

        #Construct request
        $JSONBody = @{name=$VirtualServerName;partition='Common';persist=@()}


        #Add members to request
        $JSONBody.pool = "/Common/$PoolName"
        $JSONBody.source = $SourceIP
        $JSONBody.destination = $($DestinationIP + ":" + $Port)
        $JSONBody.ipProtocol = $IpProtocol
        $PersistArray = @()
        $PersistArray += @{name="source_addr"; partition="Common"; tmDefault="yes";}
        $JSONBody.persist = $PersistArray

        #Convert request to JSON
        $JSONBody = $JSONBody | ConvertTo-Json

        #Make the request
        Log "URI: $URI"
        Log "JSONBody: $JSONBody"
        $response = Invoke-WebRequest -Method POST -Uri "$URI" -Credential $F5Cred -Body $JSONBody -Headers @{"Content-Type"="application/json"}

        $($response.Content | ConvertFrom-Json)
    }
    catch {Log $_.exception.message}
}

Function Get-FLSF5LTMVirtualServer {#Delete Virtual
$URI = "https://10.10.60.5/mgmt/tm/ltm/virtual/~Common~pki"
$response = Invoke-WebRequest -Method GET -Uri "$URI" -Credential $f5Cred -Headers @{"Content-Type"="application/json"}

$response.RawContent
$($response.Content | ConvertFrom-Json)

}

$debugEnabled = $true;
$f5FQDN = "f5-01.casamda.com"
$nodeFQDNs = @("web01.casamda.com","subca03.casamda.com")
$poolName = "WEB01"
$virtualServerName = "WEB01"
$virtualServerDestinationIP = "10.10.1.8"
$port = 80

Add-FLSF5LTMNodes -F5FQDN $f5FQDN  -F5Cred $f5Cred -NodeFQDNs $nodeFQDNs

Add-FLSF5LTMPool -F5FQDN $f5FQDN -F5Cred $f5Cred -PoolName $poolName -Port $port -PoolMembers  $nodeFQDNs

Add-FLSF5LTMVirtualSErver -F5FQDN $f5FQDN -F5Cred $f5Cred -VirtualServerName $virtualServerName -PoolName $poolName -DestinationIP $virtualServerDestinationIP -Port $port -PersistenceType source_addr -IpProtocol tcp

Remove-FLSF5LTMVirtualServer -F5FQDN $f5FQDN -F5Cred $f5Cred -VirtualServerName $virtualServerName

Remove-FLSF5LTMPool -F5FQDN $f5FQDN -F5Cred $f5Cred -PoolName $poolName

Remove-FLSF5LTMNodes -F5FQDN $f5FQDN -F5Cred $f5Cred -NodeFQDNs $nodeFQDNs
