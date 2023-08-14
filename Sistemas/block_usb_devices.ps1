#Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies

## Crear una nueva clave -- RemovableStorageDevices DWORD 32-bit
# HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows

# Comprobamos si existe la clave
$ruta_clave = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
$clave = "RemovableStorageDevices"

try {
    
    if ((Get-ChildItem -Path $ruta_clave -ErrorAction SilentlyContinue) -eq "") {
        # Clave existe - seteamos a 1
        Write-Host "Clave existe - seteamos la clave a 1"
        Set-ItemProperty -Path $ruta_clave -Name "Deny_All" -Value "1" -Verbose
    } else {
        #Creamos clave
        New-Item -Path $ruta_clave -Verbose -ErrorAction SilentlyContinue
        Write-Host -ForegroundColor Yellow "Clave ya existe, paramos la ejecución"
        Exit 0
        New-ItemProperty -Path $ruta_clave -Name "Deny_All" -Value "1" -PropertyType DWORD -Verbose -ErrorAction Stop
    }

} catch {
        #Creamos clave
        New-Item -Path $ruta_clave -Verbose
        New-ItemProperty -Path $ruta_clave -Name "Deny_All" -Value "1" -PropertyType DWORD -Verbose

} 