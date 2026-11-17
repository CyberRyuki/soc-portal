<#
  Crea la aplicación «Portal SOC ACME» en Entra ID con los permisos de Microsoft Graph que usa el portal,
  concede el consentimiento de administrador y genera un secreto.

  Requisitos:
    - Ejecutarlo un Administrador global o Administrador de roles con privilegios (para conceder permisos de aplicación).
    - PowerShell 7 o Windows PowerShell 5.1 con el módulo Microsoft.Graph:
        Install-Module Microsoft.Graph -Scope CurrentUser

  Uso:
    .\m365-setup.ps1                 # lectura + acciones (revocar sesiones, bloquear, etc.)
    .\m365-setup.ps1 -SoloLectura    # solo lectura (pon M365_READ_ONLY=true en el .env)
#>
param([switch]$SoloLectura, [int]$MesesSecreto = 12, [string]$Nombre = "Portal SOC ACME")

$ErrorActionPreference = "Stop"
Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Directory.Read.All" -NoWelcome

# Permisos de aplicación de Microsoft Graph
$lectura = @(
  "SecurityAlert.Read.All",        # alertas de Defender
  "AuditLog.Read.All",             # inicios de sesión y auditoría
  "Directory.Read.All",            # usuarios, organización y dominios
  "IdentityRiskyUser.Read.All",    # usuarios en riesgo
  "IdentityRiskEvent.Read.All",    # detecciones de riesgo
  "SecurityEvents.Read.All",       # Secure Score
  "ServiceHealth.Read.All",        # estado de los servicios
  "MailboxSettings.Read",          # reglas de bandeja de entrada
  "User.Read.All"
)
$acciones = @(
  "User.RevokeSessions.All",           # revocar sesiones
  "User.EnableDisableAccount.All",     # bloquear / desbloquear inicio de sesión
  "User-PasswordProfile.ReadWrite.All",# forzar cambio de contraseña
  "IdentityRiskyUser.ReadWrite.All",   # confirmar compromiso / descartar riesgo
  "SecurityAlert.ReadWrite.All",       # resolver alertas
  "MailboxSettings.ReadWrite"          # desactivar reglas
)
$nombres = if ($SoloLectura) { $lectura } else { $lectura + $acciones }

$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$roles = foreach ($n in $nombres) {
  $r = $graph.AppRoles | Where-Object { $_.Value -eq $n -and $_.AllowedMemberTypes -contains "Application" }
  if ($r) { $r } else { Write-Warning "Permiso no encontrado en este tenant: $n" }
}

if (Get-MgApplication -Filter "displayName eq '$Nombre'") {
  throw "Ya existe una aplicación llamada '$Nombre'. Bórrala o usa -Nombre con otro nombre."
}

$app = New-MgApplication -DisplayName $Nombre -SignInAudience "AzureADMyOrg" -RequiredResourceAccess @(
  @{ ResourceAppId = $graph.AppId; ResourceAccess = @($roles | ForEach-Object { @{ Id = $_.Id; Type = "Role" } }) }
)
$sp = New-MgServicePrincipal -AppId $app.AppId

# Consentimiento de administrador = asignar cada permiso a la aplicación
foreach ($r in $roles) {
  New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graph.Id -AppRoleId $r.Id | Out-Null
}

$secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
  DisplayName = "portal-soc"; EndDateTime = (Get-Date).AddMonths($MesesSecreto)
}
$tenant = (Get-MgContext).TenantId

Write-Host ""
Write-Host "Aplicación creada con $($roles.Count) permisos y consentimiento concedido." -ForegroundColor Green
Write-Host "Copia estas líneas al .env del servidor del portal (el secreto no se vuelve a mostrar):" -ForegroundColor Yellow
Write-Host ""
Write-Host "M365_TENANT_ID=$tenant"
Write-Host "M365_CLIENT_ID=$($app.AppId)"
Write-Host "M365_CLIENT_SECRET=$($secret.SecretText)"
if ($SoloLectura) { Write-Host "M365_READ_ONLY=true" }
Write-Host ""
Write-Host "El secreto caduca el $($secret.EndDateTime.ToString('yyyy-MM-dd')). Anota la fecha para renovarlo." -ForegroundColor Yellow
Disconnect-MgGraph | Out-Null
