$ACTUAL_PATH = Get-Location;
$SAVE_FOLDER = "$ACTUAL_PATH\save";
$IPs_LIST_PATH = "$ACTUAL_PATH\NATIp.txt";



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
	}

	#Crear directorio donde se guardará los resultados del escaner
	createDirectory $SAVE_FOLDER
}

setup

Read-Host -Prompt "Press Enter to exit"