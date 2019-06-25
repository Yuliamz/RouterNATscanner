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

function start(){
	setup
	foreach($line in Get-Content .\NATIp.txt) {
		echo $line
		$title = curl --connect-timeout 3 -m 10 -s -L $line | findstr -i title
		if(![string]::IsNullOrEmpty($title)){
			$save = $line+".txt"
			switch -regex ($title){
				".*HTTP 401 - Unauthorized.*" {techTom $line; break}
				
				default {$title; Break}
			}
		}
	}
}

start

Read-Host -Prompt "Press Enter to exit"