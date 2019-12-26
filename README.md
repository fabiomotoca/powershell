# My Powershell Scripts

## Create a new OU

```powershell
New-ADOrganizationalUnit -Name FL-Sales -Path "DC=YOURDOMAIN,DC=COM"
```

## Create users in the new OU

```powershell
New-ADUser -Name "User1" -SamAccountName USER1 -Path "OU=FL-SALES,DC=YOURDOMAIN,DC=COM"
New-ADUser -Name "User2" -SamAccountName USER2 -Path "OU=FL-SALES,DC=YOURDOMAIN,DC=COM"
New-ADUser -Name "User3" -SamAccountName USER3 -Path "OU=FL-SALES,DC=YOURDOMAIN,DC=COM"
```

## Create a new group in the new OU

```powershell
New-ADGroup -Name "FL-Sales-AcctOp" -SamAccountName FL-Sales-AcctOp -GroupCategory Security -GroupScope DomainLocal -Path "OU=FL-SALES,DC=YOURDOMAIN,DC=COM"
```

## Add users to the group

```powershell
Add-ADGroupMember FL-Sales-AcctOp USER1,USER2,USER3
```

## Enumerate the group

```powershell
Get-ADGroupMember FL-Sales-AcctOp
```

## Import users from a CSV

```powershell
Import-Csv <file.csv> | foreach {New-ADUser -SamAccountName $_.SAMAccountName -Name ($_.FirstName + " " + $_.LastName) -GivenName $_.FirstName -Surname $_.LastName -EmployeeID $_.EmployeeID -Title $_.Title -StreetAddress $_.StreetAddress -City $_.City -PostalCode $_.PostalCode -State $_.State -Department $_.Department -EmailAddress $_.Email -OfficePhone $_.PhoneNumber  -Path "CN=users,DC=YOURDOMAIN,DC=com" -Enabled $true -ChangePasswordAtLogon $true -AccountPassword (ConvertTo-SecureString -AsPlainText 'Pa$$w0rd' -Force)}
```

## DNS - Add a Type A Record

Add-DnsServerResourceRecordA -Name "srv1" -ZoneName "contoso.com" -IPv4Address "10.0.10.27"

## DNS - Add a CNAME Record

Add-DnsServerResourceRecordCName -Name "server2" -HostNameAlias "server2.lab.contoso.com" -ZoneName "contoso.com"

## Sending Email (Using Relay)

```powershell
$From = "pwsh-script@contoso.com"
$To = "fabio.silva@contoso.com"
$Cc = "douglas.azevedo@contoso.com"
$Attachment = "file.txt"
$Subject = "This email is sent using relay"
$Body = "This is what I want to say `n new line 1 `n new line 2"
$SMTPServer = "smtp-relay.gmail.com"
$SMTPPort = "587"
Send-MailMessage -From $From -to $To -Cc $Cc -Subject $Subject -Body $Body -SmtpServer $SMTPServer -port $SMTPPort -UseSsl -Attachments $Attachment –DeliveryNotificationOption OnSuccess
```

## Sending Email (Username + Password)

```powershell
$From = "pwsh-script@contoso.com"
$To = "fabio.silva@contoso.com"
$Cc = "douglas.azevedo@contoso.com"
$Attachment = "file.txt"
$Subject = "Here's the Email Subject"
$Body = "This is what I want to say"
$SMTPServer = "smtp.gmail.com"
$SMTPPort = "587"
Send-MailMessage -From $From -to $To -Cc $Cc -Subject $Subject -Body $Body -SmtpServer $SMTPServer -port $SMTPPort -UseSsl -Credential (Get-Credential) -Attachments $Attachment –DeliveryNotificationOption OnSuccess
```