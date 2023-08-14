param(
    [Parameter(Mandatory=$True, 
    HelpMessage="Ruta de la clave de registro a buscar - EX: 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'")]
    [string]$Key_path
)

## Crear una nueva clave -- RemovableStorageDevices DWORD 32-bit
# HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows

# Comprobamos si existe la clave
# $ruta_clave = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
# $clave = "RemovableStorageDevices"

try {
    
    if ((Get-ChildItem -Path $Key_path -ErrorAction SilentlyContinue) -eq "") {
        # Clave existe - seteamos a 1
        Write-Host "Clave existe - seteamos la clave a 1"
        Set-ItemProperty -Path $Key_path -Name "Deny_All" -Value "1" -Verbose
    } else {
        #Creamos clave
        New-Item -Path $Key_path -Verbose -ErrorAction SilentlyContinue
        Write-Host -ForegroundColor Yellow "Clave ya existe, paramos la ejecución"
        Exit 0
        New-ItemProperty -Path $Key_path -Name "Deny_All" -Value "1" -PropertyType DWORD -Verbose -ErrorAction Stop
    }

} catch {
        #Creamos clave
        New-Item -Path $Key_path -Verbose
        New-ItemProperty -Path $Key_path -Name "Deny_All" -Value "1" -PropertyType DWORD -Verbose

} 