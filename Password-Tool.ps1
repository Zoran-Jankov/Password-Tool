$TempPassword = "Privremen0"
$Admin = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$SearchBase = "OU=Korisnici,OU=Centrala,DC=uni,DC=net"

$Users = Get-ADUser -SearchBase $SearchBase -Filter {Enabled -eq $true} `
    -Properties 'LockedOut', 'PasswordLastSet' | Sort-Object -Property 'UserPrincipalName'

$UsersTable = [ordered]@{}
foreach ($Accout in $Users) {
    $UsersTable.Add($Accout.UserPrincipalName, $Accout)
}

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

function Get-AccountInfo {
    param (
        $User
    )
}

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$MainForm                        = New-Object system.Windows.Forms.Form
$MainForm.ClientSize             = New-Object System.Drawing.Point(560,240)
$MainForm.text                   = "Password Tool"
$MainForm.TopMost                = $true
$MainForm.FormBorderStyle        = 'Fixed3D'
$MainForm.MaximizeBox            = $false

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

$BlockedLabel                    = New-Object system.Windows.Forms.Label
$BlockedLabel.AutoSize           = $true
$BlockedLabel.width              = 25
$BlockedLabel.height             = 10
$BlockedLabel.location           = New-Object System.Drawing.Point(30,90)
$BlockedLabel.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

$UnblockButton                   = New-Object system.Windows.Forms.Button
$UnblockButton.text              = "Unlock"
$UnblockButton.width             = 150
$UnblockButton.height            = 30
$UnblockButton.location          = New-Object System.Drawing.Point(30,180)
$UnblockButton.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$ResetPasswordButton             = New-Object system.Windows.Forms.Button
$ResetPasswordButton.text        = "Reset Password"
$ResetPasswordButton.width       = 150
$ResetPasswordButton.height      = 30
$ResetPasswordButton.location    = New-Object System.Drawing.Point(380,180)
$ResetPasswordButton.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$LastPassChangeValue             = New-Object system.Windows.Forms.Label
$LastPassChangeValue.AutoSize    = $true
$LastPassChangeValue.width       = 25
$LastPassChangeValue.height      = 10
$LastPassChangeValue.location    = New-Object System.Drawing.Point(390,130)
$LastPassChangeValue.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

$LastPassChangeLabel             = New-Object system.Windows.Forms.Label
$LastPassChangeLabel.text        = "Last Password Change"
$LastPassChangeLabel.AutoSize    = $true
$LastPassChangeLabel.width       = 25
$LastPassChangeLabel.height      = 10
$LastPassChangeLabel.location    = New-Object System.Drawing.Point(390,90)
$LastPassChangeLabel.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$MainForm.controls.AddRange(@($UserLabel,$UserComboBox,$BlockedLabel,$UnblockButton,$ResetPasswordButton,$LastPassChangeValue,$LastPassChangeLabel))

foreach ($User in $Users) {
    $UserComboBox.Items.Add($User.Name)
}

$UserComboBox.Add_TextChanged({
    $SelectedUser = $UsersTable.Get_Item($UserComboBox.Text)
    if ($SelectedUser -ne $null) {
        if ($SelectedUser.LockedOut) {
            $BlockedLabel.Text = "Locked Out"
            $BlockedLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#ff0000")
            LastPassChangeValue
        }
        else {
            $BlockedLabel.Text = "Active"
            $BlockedLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#00ff00")
        }
        $LastPassChangeValue.Text = ($SelectedUser.PasswordLastSet.tostring("dd.MM.yyyy. HH:mm"))
    }
    else {
        $BlockedLabel.Text = ""
        $LastPassChangeValue.Text = ""
    }
})

$UnblockButton.Add_Click({
    $SelectedUser = $UsersTable.Get_Item($UserComboBox.Text)
    try {
        Unlock-ADAccount -Identity $SelectedUser
    }
    catch {
        $UserName = $UserComboBox.Text
        Write-Log -Message ("Admin ""$Admin"" failed to unblock ""$UserName"" account`r`n" + $_.Exception)
        break
    }
    $BlockedLabel.Text = "Active"
    $BlockedLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#00ff00")
    Write-Log -Message "Admin ""$Admin"" successfully unblocked ""$UserName"" account"
})

$ResetPasswordButton.Add_Click({
    $SelectedUser = $UsersTable.Get_Item($UserComboBox.Text)
    Set-ADAccountPassword -Identity $SelectedUser `
        -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $TempPassword -Force)
        Unlock-ADAccount -Identity $SelectedUser
        Set-ADUser -Identity $SelectedUser -ChangePasswordAtLogon $true
})

[void]$MainForm.ShowDialog()