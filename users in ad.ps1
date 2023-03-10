New-ADGroup -Name “HRpersoneel” -Description “group for HR people” -GroupScope global

$ADUsers = Import-csv C:\Usercvs\user.csv


foreach ($User in $ADUsers)
{

    $Username    = $User.username
    $Password    = $User.password
    $Firstname   = $User.firstname
    $Lastname    = $User.lastname
    $Department = $User.department
    $bozo = $User.ou
    $path = "C:\HR\$($username)"

    New-ADUser -SamAccountName $Username -UserPrincipalName "$Username@scripting.local" `
    -Name "$Firstname $Lastname" -GivenName $Firstname -Surname $Lastname -path $bozo `
    -Enabled $True -ChangePasswordAtLogon $True -DisplayName "$Lastname, $Firstname" `
    -Department $Department -AccountPassword (convertto-securestring $Password -AsPlainText -Force)
    Add-ADGroupMember -Identity "HRpersoneel" -Members $Username

    New-Item $path -Itemtype directory -force
    
    $acl = Get-Acl $path
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($username,"Read, Write","ContainerInherit, ObjectInherit","None","Allow")
    $acl.AddAccessRule($rule)
    Set-Acl $path $acl
}