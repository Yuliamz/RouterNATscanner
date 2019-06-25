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



function runScanner(){
	setup
	foreach($line in Get-Content .\NATIp.txt) {
		$title = curl --connect-timeout 3 -m 10 -s -L $line | findstr -i title
		if(![string]::IsNullOrEmpty($title)){
			$save = "$SAVE_FOLDER\$line.txt"
			switch -regex ($title){
				".*HTTP 401 - Unauthorized.*" {techTom $line; break}
				".*<title>Setup</title>.*" {cisco $line; break}
				
				
				default {$title; Break}
			}
		}
	}
}

runScanner

Read-Host -Prompt "Press Enter to exit"