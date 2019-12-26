# My Powershell Scripts

# Summary

1. [Create a new OU](#create-a-new-ou)
2. [Create users in the new OU](#create-users-in-the-new-ou)
3. [Create a new group in the new OU](#create-a-new-group-in-the-new-ou)
4. [Add users to the group](#add-users-to-the-group)
5. [Enumerate the group](#enumerate-the-group)
6. [Import users from a CSV](#import-users-from-a-csv)
7. [DNS - Add a Type A Record](#dns---add-a-type-a-record)
8. [DNS - Add a CNAME Record](##dns---add-a-cname-record)
9. [Sending Email (Using Relay)](#sending-email-using-relay)
10. [Sending Email(Username + Password)](#sending-email-username--password)
11. [Bulk Change User Password on Active Directory](#bulk-change-user-password-on-active-directoy)
12. [Bulk Change User Eamil and Add the Old Email as an Alias](#bulk-change-user-email-and-add-the-old-email-as-an-alias)
13. [Generate a CSV File From users on Active Directory Filtering Attributes](#generate-a-csv-file-from-users-on-active-directory-filtering-attributes)
14. [Bulk Change Users Password on Active Directory](#bulk-change-users-password-on-active-directory)
15. [List Users on More Than One OU Active Directory](#list-users-on-more-than-one-ou-on-active-directory)
16. [Change a Custom Attribute from Null to False](#change-a-custom-attribute-from-null-to-false)

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

## Bulk Change User Password on Active Directoy

Create an users.csv file with 02 columns; email and password.

```powershell
Import-Module ActiveDirectory 

# Import the CSV
$csv = Import-Csv -Path .\users.csv

# Loop through all items in the CSV 
ForEach ($item In $csv) {

        # Get a line from the csv file
        $user_email = $item.email
        $user_password = ConvertTo-SecureString $item.password -AsPlainText -Force

        # Find the user using his email address
        $user_dn = Get-ADUser -Filter {mail -eq $user_email}

        Set-ADAccountPassword -Identity $user_dn -Reset -NewPassword $user_password
        Set-ADUser -Identity $user_dn -ChangePasswordAtLogon 1

        # Success, log it
        $changelog = "The password for USER $($user_email) was set."
        Write-Host $changelog
        $changelog | Out-File -Append .\changelog.txt
}
```

## Bulk Change User Email and Add the Old Email as an Alias

Create an users.csv file with 03 columns; SamAccountName, NewEmail, Alias. This file is optional, but you will need to change the script a bit.

```powershell
Import-Module ActiveDirectory

$csv = Import-Csv -Path .\users.csv

ForEach ($item In $csv){

        # Get a line from csv file
        $sam_account = $item.SamAccountName
        $new_email = $item.NewEmail
        $alias = $item.Alias

        # Set attributes
        Set-ADUser -Identity $sam_account -EmailAddress $new_email
        Set-ADUser -Identity $sam_account -Add @{proxyAddresses=$alias}

        # Success, write to a log
        $changelog = "The USER $($sam_account) was set from $($alias) to $($new_email)"
        Write-Host $changelog
        $changelog | Out-File -Append .\changelog.txt

        Start-Sleep -Seconds 1.0
}
```

## Generate a CSV File From Users on Active Directory Filtering Attributes

You select the attribute using select-object before you filter using the where-object. If you don't select the attribute you can't filter it, remember that.

This line will give you the enabled users on AD.

```powershell
Get-ADUser -Filter * -SearchBase "<YOURBASEDN>" -Properties * | Select-Object EmployeeID,displayName,setGender,department,SamAccountName,mail,mobile,birthdayDate,admissionDate,whenCreated,costCenter,Enabled | Where-Object {$_.Enabled -like “true”} | Export-Csv enabled-users.csv
```

## Bulk Change Users Password on Active Directory

Create a users.csv file with 01 column; SamAccountName.

Change the NEWPASSWORD to something you want.

```powershell
Import-Csv users.csv |  Select SamAccountName | Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NEWPASSWORD" -Force)
```

## List Users on More Than One OU on Active Directory

Change YOURBASEDN, *EX-EMPLOYEES*, *SERVICE ACCOUNT* and *EXTERNAL*.

```powershell
Get-ADUser -Filter * -SearchBase "YOURBASEDN" -Properties * | Where-Object {$_.DistinguishedName -like '*EX-EMPLOYEES*' -or $_.DistinguishedName -like '*SERVICE ACCOUNT*' -or $_.DistinguishedName -like '*EXTERNAL*'} | Select DistinguishedName,SamAccountName
```

## Change a Custom Attribute from Null to False

Change YOURBASEDN, *EX-EMPLOYEES*, *SERVICE ACCOUNT* and *EXTERNAL*.

The custom attribute in this case is called "alive".

```powershell
Get-ADUser -Filter * -SearchBase "YOURBASEDN" -Properties * | Where-Object {$_.DistinguishedName -like '*EX-EMPLOYEES*' -or $_.DistinguishedName -like '*SERVICE ACCOUNT*' -or $_.DistinguishedName -like '*EXTERNAL*'} | Select DistinguishedName,SamAccountName,alive | Where-Object {$_.alive -eq $null} | ForEach {Set-ADUser $_.SamAccountName -Replace @{alive=$false}}
```
