# My Powershell Scripts

## Create a new OU

New-ADOrganizationalUnit -Name FL-Sales -Path "DC=YOURDOMAIN,DC=COM"

## Create users in the new OU

New-ADUser -Name "User1" -SamAccountName USER1 -Path "OU=FL-SALES,DC=YOURDOMAIN,DC=COM"
New-ADUser -Name "User2" -SamAccountName USER2 -Path "OU=FL-SALES,DC=YOURDOMAIN,DC=COM"
New-ADUser -Name "User3" -SamAccountName USER3 -Path "OU=FL-SALES,DC=YOURDOMAIN,DC=COM"

## Create a new group in the new OU

New-ADGroup -Name "FL-Sales-AcctOp" -SamAccountName FL-Sales-AcctOp -GroupCategory Security -GroupScope DomainLocal -Path "OU=FL-SALES,DC=YOURDOMAIN,DC=COM"

## Add users to the group

Add-ADGroupMember FL-Sales-AcctOp USER1,USER2,USER3

## Enumerate the group

Get-ADGroupMember FL-Sales-AcctOp

## Import users from a CSV

Import-Csv <file.csv> | foreach {New-ADUser -SamAccountName $_.SAMAccountName -Name ($_.FirstName + " " + $_.LastName) -GivenName $_.FirstName -Surname $_.LastName -EmployeeID $_.EmployeeID -Title $_.Title -StreetAddress $_.StreetAddress -City $_.City -PostalCode $_.PostalCode -State $_.State -Department $_.Department -EmailAddress $_.Email -OfficePhone $_.PhoneNumber  -Path "CN=users,DC=YOURDOMAIN,DC=com" -Enabled $true -ChangePasswordAtLogon $true -AccountPassword (ConvertTo-SecureString -AsPlainText 'Pa$$w0rd' -Force)}