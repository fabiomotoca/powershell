
<#
    This is script validates data inconsistency on BambooHR database and a local Active Directory.

    Sorry, it is in PT-BR
#>

# A linha abaixo e obrigatoria ou o Invoke-RestMethod nao ira funcionar
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Email relay info

$From = "pwsh-script@domain.com"
$To = "fabio.silva@domain.com"
$Cc = "gabriel.santos@domain.cm"
$Subject = "BambooHR API - PowerShell Script"
$Body = ""
$SMTPServer = "smtp-relay.gmail.com"
$SMTPPort = "587"

<#
    Os atriutos abaixo podem ser resgatados da API e utilizados para comparacao

    id                 type     name                 
    --                 ----     ----                 
    displayName        text     Display name         
    firstName          text     First name           
    lastName           text     Last name            
    preferredName      text     Preferred name       
    gender             gender   Gender               
    jobTitle           list     Job title            
    workPhone          text     Work Phone           
    workEmail          email    Work Email           
    department         list     Department
    location           list     Location             
    linkedIn           text     LinkedIn URL         
    workPhoneExtension text     Work Ext.            
    supervisor         employee Manager              
    photoUploaded      bool     Employee photo exists
    photoUrl           url      Employee photo url   
    canUploadPhoto     bool  
#>

# Iniciando a API do BambooHR e pegando as informacoes de todos os usuarios
$username = '<API_KEY>'
$password = 'x'
$accept = 'application/json'
$uri = 'https://api.bamboohr.com/api/gateway.php/tfgco/v1/employees/directory'
$headers = @{
    "Accept"=$accept
}
$secpwd = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $secpwd)
$bambooResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -Credential $credential
                       
# Pegar as informacoes do Active Directory
$adResponse = Get-ADUser -Filter * -SearchBase "<AD_BASEDN>" -Properties * | Where-Object {$_.alive -eq $true}

# Consistencias

$rigthId = 0
$rigthDpto = 0
$rigthEmail = 0

# Inconsistencias
$wrongId = 0
$wrongDpto = 0

$wrongMail = 0
$bambooNullMail = 0

# Total de Usuarios
$totalUsers = 0

Foreach( $user in $adResponse ){

    <#
        A variavel $bambooResponse possui toda a lista de usuarios resgatada da API
        $_.workEmail => Email cadastrado no BambooHR
        $user.mail => email do usuario atual no foreach
    #>

    $bamboo = $bambooResponse.employees | where {$_.workEmail -eq $user.mail}
    
    <#
        Write-Host "Bamboo Registered Email" $bamboo.workEmail "And Actual Department" $bamboo.department
        Write-Host "AD Registered Email" $user.mail "And Actual Department" $user.Department
        Write-Host "Is the same department:" ($bamboo.workEmail -eq $user.mail)
        Write-Host "Is the same Id:" ($bamboo.id -eq $user.EmployeeID)
    #>

    # Check de Inconsistencias
    if($bamboo.id -ne $user.EmployeeID){ $wrongId++ } else{ $rigthId++ }

    if($bamboo.department -ne $user.Department){ $wrongDpto++ } else{ $rigthDpto++ }

    if($bamboo.workEmail -ne $user.mail){ $wrongMail++ } else{ $rigthEmail++ }
    
    if($bamboo.workEmail -eq $null){ $bambooNullMail++ }

    $totalUsers++

}

$Body = "`n Total de Consistencias `n `n"
$Body += "`t Consistencias de id: $($rigthId) `n"
$Body += "`t Consistencias de departamento: $($rigthDpto) `n"
$Body += "`t Consistencias de email: $($rigthEmail) `n"

$Body += "`n Total de Inconsistencias `n `n"
$Body += "`t Inconsistencias de id: $($wrongId) `n"
$Body += "`t Inconsistencias de departamento: $($wrongDpto) `n"
$Body += "`t Inconsistencias de email: $($wrongMail) `n"
$Body += "`t BambooHR total de emails nulos: $($bambooNullMail) `n"
 
$Body += "`n Total de Usuarios (alive = true): $($totalUsers) `n`n -- `n fim do script `n ffs"

Write-Host $Body

Send-MailMessage -From $From -to $To -Cc $Cc -Subject $Subject -Body $Body -SmtpServer $SMTPServer -port $SMTPPort -UseSsl –DeliveryNotificationOption OnSuccess