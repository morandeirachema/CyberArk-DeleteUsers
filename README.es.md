# Script de Eliminación de Usuarios de CyberArk Privilege Cloud

[English](README.md) | **Español**

Un script de PowerShell para eliminar usuarios de CyberArk Privilege Cloud basándose en un archivo CSV que contiene información del usuario incluyendo origen, nombre de usuario y días desde el último inicio de sesión.

## Características

- Eliminación masiva de usuarios desde archivo CSV
- Autenticación OAuth2 con CyberArk Privilege Cloud
- Filtrado de usuarios por días mínimos desde el último inicio de sesión
- Modo de prueba (dry-run) para testing sin eliminación real
- Registro completo en archivo y consola
- Salida de consola con códigos de color
- Manejo de errores y estadísticas detalladas

## Requisitos Previos

- PowerShell 5.1 o superior (Windows PowerShell o PowerShell Core)
- Tenant de CyberArk Privilege Cloud
- Credenciales OAuth2 (Client ID y Client Secret)
- Permisos apropiados para eliminar usuarios en CyberArk

## Configuración

### 1. Habilitar la Ejecución de Scripts de PowerShell

Asegúrese de que la política de ejecución de PowerShell permita la ejecución de scripts:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 2. Configurar Credenciales OAuth2 en CyberArk

1. Inicie sesión en su tenant de CyberArk Privilege Cloud
2. Navegue a Administración > Control de Acceso > Aplicaciones
3. Cree una nueva aplicación o use una existente
4. Anote el Client ID y Client Secret
5. Asegúrese de que la aplicación tenga permisos para eliminar usuarios

### 3. Configurar Credenciales Cifradas (Recomendado para Automatización)

Para una ejecución automatizada segura, use el script de configuración de credenciales para cifrar y almacenar sus credenciales:

**Usando DPAPI (Windows, específico del usuario):**
```powershell
.\Setup-CyberArkCredentials.ps1 -TenantUrl "https://your-tenant.cyberark.cloud"
```

**Usando AES (Multiplataforma, portable):**
```powershell
.\Setup-CyberArkCredentials.ps1 -TenantUrl "https://your-tenant.cyberark.cloud" -UseAES
```

El script:
- Le solicitará el Client ID y Client Secret
- Probará la autenticación con CyberArk
- Cifrará y guardará las credenciales en `.\credentials\cyberark.cred`
- Generará la clave de cifrado (si usa AES) en `.\credentials\aes.key`

**Notas Importantes:**
- **DPAPI**: Las credenciales solo funcionan para el mismo usuario en la misma máquina (ideal para tareas programadas ejecutadas como usuario específico)
- **AES**: Las credenciales funcionan entre usuarios/máquinas pero requieren el archivo de clave (ideal para automatización compartida o contenedores)

## Formato del Archivo CSV

El archivo CSV debe contener las siguientes columnas:

- `origin`: Origen del usuario (ej. LDAP, Local, SAML)
- `username`: Nombre de usuario a eliminar
- `days_since_last_login`: Número de días desde el último inicio de sesión

### Ejemplo de CSV (`users_template.csv`):

```csv
origin,username,days_since_last_login
LDAP,john.doe,120
Local,jane.smith,90
LDAP,admin.user,45
```

## Uso

### Usando Credenciales Almacenadas (Recomendado)

Después de ejecutar el script de configuración, puede usar el script de eliminación sin especificar credenciales:

```powershell
.\Delete-CyberArkUsers.ps1 -CsvPath "users.csv"
```

### Credenciales Manuales

Si no ha configurado credenciales cifradas, puede proporcionarlas manualmente:

```powershell
.\Delete-CyberArkUsers.ps1 -CsvPath "users.csv" `
  -TenantUrl "https://your-tenant.cyberark.cloud" `
  -ClientId "YOUR_CLIENT_ID" `
  -ClientSecret "YOUR_CLIENT_SECRET"
```

### Usando Variables de Entorno

Configure las credenciales como variables de entorno para evitar pasarlas en la línea de comandos:

**Windows PowerShell:**
```powershell
$env:CYBERARK_CLIENT_ID = "your_client_id"
$env:CYBERARK_CLIENT_SECRET = "your_client_secret"

.\Delete-CyberArkUsers.ps1 -CsvPath "users.csv" `
  -TenantUrl "https://your-tenant.cyberark.cloud"
```

**Linux/macOS PowerShell:**
```powershell
$env:CYBERARK_CLIENT_ID = "your_client_id"
$env:CYBERARK_CLIENT_SECRET = "your_client_secret"

./Delete-CyberArkUsers.ps1 -CsvPath "users.csv" `
  -TenantUrl "https://your-tenant.cyberark.cloud"
```

### Filtrar por Días Mínimos

Eliminar solo usuarios que no hayan iniciado sesión por al menos 90 días:

```powershell
.\Delete-CyberArkUsers.ps1 -CsvPath "users.csv" -MinDays 90
```

### Modo de Prueba (Dry Run)

Probar el script sin eliminar usuarios realmente (usando credenciales almacenadas):

```powershell
.\Delete-CyberArkUsers.ps1 -CsvPath "users.csv" -DryRun
```

### Ruta de Credenciales Personalizada

Usar credenciales desde una ubicación diferente:

```powershell
.\Delete-CyberArkUsers.ps1 -CsvPath "users.csv" -CredentialPath "C:\secure\credentials"
```

### Obtener Ayuda

Ver ayuda detallada e información de parámetros:

```powershell
Get-Help .\Delete-CyberArkUsers.ps1 -Full
```

## Parámetros

- **CsvPath** (requerido): Ruta al archivo CSV que contiene los usuarios a eliminar
- **TenantUrl** (opcional): URL del tenant de CyberArk (ej. https://tenant.cyberark.cloud) - Requerido si no se usan credenciales almacenadas
- **ClientId** (opcional): Client ID de OAuth2 (o usar variable de entorno CYBERARK_CLIENT_ID o credenciales almacenadas)
- **ClientSecret** (opcional): Client Secret de OAuth2 (o usar variable de entorno CYBERARK_CLIENT_SECRET o credenciales almacenadas)
- **CredentialPath** (opcional): Ruta al directorio que contiene credenciales cifradas (por defecto: .\credentials)
- **MinDays** (opcional): Eliminar solo usuarios con days_since_last_login >= este valor
- **DryRun** (switch): Simular eliminación sin hacer cambios reales

## Automatización y Tareas Programadas

### Programador de Tareas de Windows

Para ejecutar el script automáticamente en un horario:

1. **Configure las credenciales como el usuario de la tarea:**
   ```powershell
   # Ejecutar como el usuario que ejecutará la tarea programada
   .\Setup-CyberArkCredentials.ps1 -TenantUrl "https://your-tenant.cyberark.cloud"
   ```

2. **Crear una tarea programada:**
   ```powershell
   $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
     -Argument "-ExecutionPolicy Bypass -File C:\path\to\Delete-CyberArkUsers.ps1 -CsvPath C:\path\to\users.csv -MinDays 90"

   $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2am

   Register-ScheduledTask -TaskName "CyberArk-DeleteInactiveUsers" `
     -Action $action -Trigger $trigger -User "DOMAIN\ServiceAccount"
   ```

### Tarea Cron en Linux/macOS

Para automatización multiplataforma usando cifrado AES:

1. **Configure credenciales con AES:**
   ```bash
   pwsh -Command ".\Setup-CyberArkCredentials.ps1 -TenantUrl 'https://your-tenant.cyberark.cloud' -UseAES"
   ```

2. **Crear una tarea cron:**
   ```bash
   # Editar crontab
   crontab -e

   # Agregar entrada (se ejecuta cada lunes a las 2 AM)
   0 2 * * 1 cd /path/to/scripts && pwsh -File Delete-CyberArkUsers.ps1 -CsvPath users.csv -MinDays 90
   ```

### Entornos Docker/Contenedores

Cuando use contenedores, utilice cifrado AES y monte las credenciales como secretos:

```dockerfile
# Almacenar credenciales de forma segura
COPY credentials/cyberark.cred /app/credentials/
COPY credentials/aes.key /app/credentials/

# Ejecutar script
CMD ["pwsh", "-File", "Delete-CyberArkUsers.ps1", "-CsvPath", "users.csv"]
```

## Registro (Logs)

El script crea un archivo de registro nombrado `cyberark_delete_YYYYMMDD_HHMMSS.log` con información detallada sobre:

- Estado de autenticación
- Cada usuario procesado
- Éxito/fallo de las eliminaciones
- Estadísticas finales

Los registros también se muestran en la consola en tiempo real.

## Salida

Al finalizar la ejecución, el script muestra un resumen:

```
========================================
RESUMEN DE ELIMINACIÓN
========================================
Eliminados exitosamente: 10
Fallos al eliminar:      2
Omitidos:                5
========================================
Archivo de log: cyberark_delete_20251026_143022.log
```

## Manejo de Errores

El script maneja varios escenarios de error:

- Formato CSV inválido o columnas faltantes
- Fallos de autenticación
- Usuario no encontrado en CyberArk
- Errores de API durante la eliminación
- Problemas de conectividad de red

Todos los errores se registran con mensajes detallados.

## Recomendaciones de Seguridad

1. Almacene las credenciales de forma segura usando variables de entorno o un gestor de secretos
2. Nunca confirme credenciales en el control de versiones
3. Use cuentas de servicio con los permisos mínimos requeridos
4. Pruebe con `-DryRun` antes de la eliminación real
5. Respalde los datos de usuario antes de ejecutar eliminaciones masivas
6. Revise el archivo CSV cuidadosamente antes de la ejecución
7. Considere usar PowerShell SecureString para credenciales en entornos de producción

## Referencia de API

El script usa los siguientes endpoints de la API REST de CyberArk:

- `POST /oauth2/platformtoken` - Autenticación OAuth2
- `GET /api/Users?search={username}` - Búsqueda de usuarios
- `DELETE /api/Users/{id}` - Eliminación de usuarios

## Solución de Problemas

### Fallo de Autenticación

- Verifique que la URL del tenant sea correcta
- Compruebe que el Client ID y Client Secret sean válidos
- Asegúrese de que la aplicación OAuth2 tenga los permisos necesarios

### Usuario No Encontrado

- Verifique que el nombre de usuario en el CSV coincida exactamente (no distingue mayúsculas)
- Compruebe que el usuario exista en CyberArk
- Asegúrese de tener permiso para ver el usuario

### Fallo en la Eliminación

- Verifique que tenga permiso para eliminar usuarios
- Compruebe si el usuario tiene dependencias (cajas fuertes, cuentas, etc.)
- Revise el archivo de registro para mensajes de error detallados

## Licencia

Este script se proporciona tal cual para uso con CyberArk Privilege Cloud.

## Soporte

Para problemas o preguntas:
1. Revise los archivos de registro para mensajes de error detallados
2. Consulte la documentación de la API de CyberArk Privilege Cloud
3. Contacte a su administrador de CyberArk
