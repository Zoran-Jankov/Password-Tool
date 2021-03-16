#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$TempPassword = "Privremen0"
$SearchBase = "OU=Korisnici,OU=Centrala,DC=uni,DC=net"
$Admin = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$Users = $null

#-----------------------------------------------------------[Functions]------------------------------------------------------------

<#
.SYNOPSIS
Writes a log entry to console, log file and report file.

.DESCRIPTION
Creates a log entry with timestamp and message passed thru a parameter Message, and saves the log entry to log file, to report log
file, and writes the same entry to console. In "Settings.cfg" file paths to report log and permanent log file are contained, and
option to turn on or off whether a console output, report log and permanent log should be written. If "Settings.cfg" file is absent
it loads the default values. Depending on the NoTimestamp parameter, log entry can be written with or without a timestamp.
Format of the timestamp is "yyyy.MM.dd. HH:mm:ss:fff", and this function adds " - " after timestamp and before the main message.

.PARAMETER Message
A string message to be written as a log entry

.PARAMETER NoTimestamp
A switch parameter if present timestamp is disabled in log entry

.EXAMPLE
Write-Log -Message "A log entry"

.EXAMPLE
Write-Log "A log entry"

.EXAMPLE
Write-Log -Message "===========" -NoTimestamp

.EXAMPLE
"A log entry" | Write-Log

.NOTES
Version:        2.2
Author:         Zoran Jankov
#>
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
                   Position = 0,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true,
                   HelpMessage = "A string message to be written as a log entry")]
        [string]
        $Message,

        [Parameter(Mandatory = $false,
                   Position = 1,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true,
                   HelpMessage = "A switch parameter if present timestamp is disabled in log entry")]
        [switch]
        $NoTimestamp = $false
    )

    begin {
        if (Test-Path -Path ".\Settings.cfg") {
            $Settings = Get-Content ".\Settings.cfg" | ConvertFrom-StringData

            $LogFile         = $Settings.LogFile
            $ReportFile      = $Settings.ReportFile
            $WriteTranscript = $Settings.WriteTranscript -eq "true"
            $WriteLog        = $Settings.WriteLog -eq "true"
            $SendReport      = $Settings.SendReport -eq "true"
        }
        else {
            $Desktop = [Environment]::GetFolderPath("Desktop")
            $LogFile         = "\\s3\Sektor informacionih tehnologija\Logs\Password-Tool.log"
            $ReportFile      = "$Desktop\Report.log"
            $WriteTranscript = $false
            $WriteLog        = $true
            $SendReport      = $false
        }
        if (-not (Test-Path -Path $LogFile)) {
            New-Item -Path $LogFile -ItemType File
        }
        if ((-not (Test-Path -Path $ReportFile)) -and $SendReport) {
            New-Item -Path $ReportFile -ItemType File
        }
    }

    process {
        if (-not($NoTimestamp)) {
            $Timestamp = Get-Date -Format "yyyy.MM.dd. HH:mm:ss:fff"
            $LogEntry = "$Timestamp - $Message"
        }
        else {
            $LogEntry = $Message
        }

        if ($WriteTranscript) {
            Write-Verbose $LogEntry -Verbose
        }
        if ($WriteLog) {
            Add-content -Path $LogFile -Value $LogEntry
        }
        if ($SendReport) {
            Add-content -Path $ReportFile -Value $LogEntry
        }
    }
}
<#
.SYNOPSIS
Returns a hash table of AD User objects mapped with usernames of the same users

.DESCRIPTION
Long description

.PARAMETER SearchBase
Specifies an Active Directory path to search under

.EXAMPLE
Get-AccountsInfo -SearchBase 'OU=Users,DC=company,DC=com'

.EXAMPLE
Get-AccountsInfo 'OU=Users,DC=company,DC=com'

.EXAMPLE
'OU=Users,DC=company,DC=com' | Get-AccountsInfo -SearchBase

.NOTES
Version:        1.0
Author:         Zoran Jankov
#>
function Get-AccountsInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
                   Position = 0,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true,
                   HelpMessage = "Specifies an Active Directory path to search under")]
        [string]
        $SearchBase
    )

    process {
        $Accounts = Get-ADUser -SearchBase $SearchBase -Filter {Enabled -eq $true} `
            -Properties 'LockedOut', 'PasswordLastSet', 'UserPrincipalName' | Sort-Object -Property 'UserPrincipalName'

        return $Accounts
    }
}

<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER OnlyLockedOut
Parameter description

.PARAMETER Users
Parameter description

.EXAMPLE
An example

.NOTES
Version:        1.0
Author:         Zoran Jankov
#>
function Get-ComboBoxItems {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
                   Position = 0,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true,
                   HelpMessage = "Specifies if only locked out are to be added")]
        [bool]
        $OnlyLockedOut,

        [Parameter(Mandatory = $true,
                   Position = 1,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true,
                   HelpMessage = "AD user list")]
        [Object[]]
        $Accounts
    )

    process {
        $ComboBoxItems = @()
        foreach ($Account in $Accounts) {
            if ($OnlyLockedOut) {
                if ($Account.LockedOut) {
                    $ComboBoxItems += $Account.UserPrincipalName
                }
            }
            else {
                $ComboBoxItems += $Account.UserPrincipalName
            }
        }
        return $ComboBoxItems
    }
}

function Get-DisplayData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
                   Position = 0,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true,
                   HelpMessage = "")]
        [String]
        $Username,

        [Parameter(Mandatory = $true,
                   Position = 1,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true,
                   HelpMessage = "")]
        $UserBase
    )

    process {
        $SelectedUser = $UserBase | Where-Object {$_.UserPrincipalName -eq $Username}
        if ($null -ne $SelectedUser) {
            if ($SelectedUser.LockedOut) {
                $BlockedLabel.Text = "Locked Out"
                $BlockedLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#ff0000")
            }
            else {
                $BlockedLabel.Text = "Active"
                $BlockedLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#00ff00")
            }
            try {
                $LastPassChange = $SelectedUser.PasswordLastSet.toString("dd.MM.yyyy. HH:mm")
            }
            catch {
                $LastPassChange = "Unknown"
            }
        }
        else {
            $BlockedValue = ""
            $LastPassChange = ""
        }
        return @{
            Status = $BlockedValue;
            LastPassChange = $LastPassChange
        }
    }  
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

$Users = Get-AccountsInfo -SearchBase $SearchBase
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$MainForm                        = New-Object system.Windows.Forms.Form
$MainForm.ClientSize             = New-Object System.Drawing.Point(560,240)
$MainForm.text                   = "Password Tool"
$MainForm.TopMost                = $true
$MainForm.FormBorderStyle        = 'Fixed3D'
$MainForm.MaximizeBox            = $false
$MainForm.ShowIcon               = $false

$UserLabel                       = New-Object system.Windows.Forms.Label
$UserLabel.text                  = "User"
$UserLabel.AutoSize              = $true
$UserLabel.width                 = 25
$UserLabel.height                = 10
$UserLabel.location              = New-Object System.Drawing.Point(30,30)
$UserLabel.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$UserComboBox                    = New-Object system.Windows.Forms.ComboBox
$UserComboBox.width              = 440
$UserComboBox.height             = 24
$UserComboBox.location           = New-Object System.Drawing.Point(80,30)
$UserComboBox.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
$UserComboBox.AutoCompleteMode   = 'SuggestAppend'
$UserComboBox.AutoCompleteSource = 'ListItems'

$OnlyLockedOutCheckbox           = New-Object System.Windows.Forms.CheckBox
$OnlyLockedOutCheckbox.AutoSize  = $true
$OnlyLockedOutCheckbox.Location  = New-Object System.Drawing.Size(30,90)
$OnlyLockedOutCheckbox.Text      = "Show Only Locked Out"
$OnlyLockedOutCheckbox.Checked   = $false

$BlockedLabel                    = New-Object system.Windows.Forms.Label
$BlockedLabel.AutoSize           = $true
$BlockedLabel.width              = 25
$BlockedLabel.height             = 10
$BlockedLabel.location           = New-Object System.Drawing.Point(80,130)
$BlockedLabel.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

$UnblockButton                   = New-Object system.Windows.Forms.Button
$UnblockButton.text              = "Unlock"
$UnblockButton.width             = 150
$UnblockButton.height            = 30
$UnblockButton.location          = New-Object System.Drawing.Point(30,180)
$UnblockButton.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$LastPassChangeLabel             = New-Object system.Windows.Forms.Label
$LastPassChangeLabel.text        = "Last Password Change"
$LastPassChangeLabel.AutoSize    = $true
$LastPassChangeLabel.width       = 25
$LastPassChangeLabel.height      = 10
$LastPassChangeLabel.location    = New-Object System.Drawing.Point(390,90)
$LastPassChangeLabel.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$LastPassChangeValue             = New-Object system.Windows.Forms.Label
$LastPassChangeValue.AutoSize    = $true
$LastPassChangeValue.width       = 25
$LastPassChangeValue.height      = 10
$LastPassChangeValue.location    = New-Object System.Drawing.Point(390,130)
$LastPassChangeValue.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

$ResetPasswordButton             = New-Object system.Windows.Forms.Button
$ResetPasswordButton.text        = "Reset Password"
$ResetPasswordButton.width       = 150
$ResetPasswordButton.height      = 30
$ResetPasswordButton.location    = New-Object System.Drawing.Point(380,180)
$ResetPasswordButton.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$MainForm.controls.AddRange(@(
    $UserLabel,
    $UserComboBox,
    $OnlyLockedOutCheckbox,
    $BlockedLabel,
    $UnblockButton,
    $LastPassChangeLabel,
    $LastPassChangeValue,
    $ResetPasswordButton
))

$UserComboBox.Items.Clear()
$UserComboBox.Items.AddRange((Get-ComboBoxItems -OnlyLockedOut $OnlyLockedOutCheckbox.Checked -Accounts $Users))

$UserComboBox.Add_TextChanged({
    $DisplayData = Get-DisplayData -Username ($UserComboBox.Text) -UserBase $Users
    $BlockedLabel.Text = $DisplayData.Status
    $LastPassChangeValue.Text = $DisplayData.LastPassChange
})

$OnlyLockedOutCheckbox.Add_CheckStateChanged({
    $UserComboBox.Items.Clear()
    $UserComboBox.Items.AddRange((Get-ComboBoxItems -OnlyLockedOut $OnlyLockedOutCheckbox.Checked -Accounts $Users))
})

$UnblockButton.Add_Click({
    $Username = $UserComboBox.Text
    $SelectedUser = $Users | Where-Object {$_.UserPrincipalName -eq $Username}
    
    $Choice = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to unblock $UserName user account?", "Unblock Account", 4)
    if ($Choice -eq 'Yes') {
        try {
            Unlock-ADAccount -Identity $SelectedUser
        }
        catch {
            Write-Log -Message ("Admin '$Admin' failed to unblock '$UserName' user account`r`n" + $_.Exception)
            [System.Windows.Forms.MessageBox]::Show("Failed to unblock $UserName user account", "Error")
            continue
        }
        $Users = Get-AccountsInfo -SearchBase $SearchBase
        Update-Display
        Update-ComboBox
        Write-Log -Message "Admin '$Admin' successfully unblocked '$UserName' user account"
        [System.Windows.Forms.MessageBox]::Show("$UserName user account successfully unblocked", "Info")
    }
})

$ResetPasswordButton.Add_Click({
    $SelectedUser = $Users | Where-Object {$_.UserPrincipalName -eq $UserComboBox.Text}
    $UserName = $UserComboBox.Text
    $Choice = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to reset $UserName user account password?", "Reset Account Password", 4)
    if ($Choice -eq 'Yes') {
        try {
            Set-ADAccountPassword -Identity $SelectedUser `
                -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $TempPassword -Force)
            Unlock-ADAccount -Identity $SelectedUser
            Set-ADUser -Identity $SelectedUser -ChangePasswordAtLogon $true
        }
        catch {
            Write-Log -Message ("Admin '$Admin' failed to change '$UserName' user account password`r`n" + $_.Exception)
            [System.Windows.Forms.MessageBox]::Show("Failed to change $UserName user account password", "Error")
            continue
        }
        $Users = Get-AccountsInfo -SearchBase $SearchBase
        Update-Display
        Update-ComboBox
        Write-Log -Message "Admin '$Admin' successfully changed '$UserName' user account password"
        [System.Windows.Forms.MessageBox]::Show("$UserName user account password successfully changed", "Info")
    }
})

[void]$MainForm.ShowDialog()