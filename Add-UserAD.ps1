#K.V.Yankovich 2024

Add-Type -AssemblyName System.Windows.Forms
Function Select-File {
    param (
        [Parameter (Mandatory=$true)]
        [string]$title,
        [Parameter (Mandatory=$true)] 
        [string]$filter
        )
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.OpenFileDialog]$openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Title = $title
    $openFileDialog.InitialDirectory = ".\"
    $openFileDialog.filter = $filter
    $openFileDialog.ShowHelp = $true
    If ($openFileDialog.ShowDialog() -eq "Cancel")
    {
        [System.Windows.Forms.MessageBox]::Show("No File Selected. Please select a file !", "Error", 0, [System.Windows.Forms.MessageBoxIcon]::Exclamation)
        Return null
    }
        $Global:SelectedFile = $openFileDialog.FileName
        Return $SelectedFile #add this return
}
function Get-Password {
    param (
        [Parameter (Mandatory=$true)]
        [string]$pass_number_group,
        [Parameter (Mandatory=$true)]
        [string]$pass_group_char_lenght,
        [Parameter (Mandatory=$true)]
        [string]$pass_group_char_separator
        )

    [string]$upperChars = "ABCDEFGHKLMNOPRSTUVWXYZ".ToCharArray() 
    [string]$lowerChars = "abcdefghiklmnoprstuvwxyz".ToCharArray() 
    [string]$numbers = "0123456789".ToCharArray()

    [System.Random]$random = New-Object System.Random

    while (-not ($containsUpper -and $containsLower -and $containsNumbers)){
    [string]$password =""
        for ($n = 1; $n -le $pass_number_group; $n++) {
            for ($i = 0; $i -lt $pass_group_char_lenght; $i++) {
                $charType = $random.Next(0, 3)
                switch ($charType) {
                    0 { $password += ($upperChars | Get-Random -Count 1) -join '' }
                    1 { $password += ($lowerChars | Get-Random -Count 1) -join '' }
                    2 { $password += ($numbers | Get-Random -Count 1) -join '' }
                    Default {}
                }
            }
            if ($n -lt $pass_number_group) {
                $password = [string]::Concat($password, "-")
            }
        }
        [string]$containsUpper = $password -cmatch "[A-Z]"
        [string]$containsLower = $password -cmatch "[a-z]"
        [string]$containsNumbers = $password -cmatch "[0-9]"
    }  
    return $password   
}

function Get-Translit {
    param ([string]$inString)
    $Translit = @{
        [char]'а' = "a"; [char]'А' = "A"; [char]'б' = "b"; [char]'Б' = "B"
        [char]'в' = "v"; [char]'В' = "V"; [char]'г' = "g"; [char]'Г' = "G"
        [char]'д' = "d"; [char]'Д' = "D"; [char]'е' = "e"; [char]'Е' = "E"
        [char]'ё' = "yo"; [char]'Ё' = "Yo"; [char]'ж' = "zh"; [char]'Ж' = "Zh"
        [char]'з' = "z"; [char]'З' = "Z"; [char]'и' = "i"; [char]'И' = "I"
        [char]'й' = "j"; [char]'Й' = "J"; [char]'к' = "k"; [char]'К' = "K"
        [char]'л' = "l"; [char]'Л' = "L"; [char]'м' = "m"; [char]'М' = "M"
        [char]'н' = "n"; [char]'Н' = "N"; [char]'о' = "o"; [char]'О' = "O"
        [char]'п' = "p"; [char]'П' = "P"; [char]'р' = "r"; [char]'Р' = "R"
        [char]'с' = "s"; [char]'С' = "S"; [char]'т' = "t"; [char]'Т' = "T"
        [char]'у' = "u"; [char]'У' = "U"; [char]'ф' = "f"; [char]'Ф' = "F"
        [char]'х' = "h"; [char]'Х' = "H"; [char]'ц' = "c"; [char]'Ц' = "C"
        [char]'ч' = "ch"; [char]'Ч' = "Ch"; [char]'ш' = "sh"; [char]'Ш' = "Sh"
        [char]'щ' = "sch"; [char]'Щ' = "Sch"; [char]'ъ' = ""; [char]'Ъ' = ""
        [char]'ы' = "y"; [char]'Ы' = "Y"; [char]'ь' = ""; [char]'Ь' = ""
        [char]'э' = "e"; [char]'Э' = "E"; [char]'ю' = "yu"; [char]'Ю' = "Yu"
        [char]'я' = "ya"; [char]'Я' = "Ya"
    }
    $outCHR=""
    foreach ($CHR in $inCHR = $inString.ToCharArray()) {
            if ($translit[$CHR] -cne $Null ) {
                $outCHR += $translit[$CHR]
            } else {
                $outCHR += $CHR
            }
    }
    Write-Output $outCHR
}

function Write-Log {
    param (
    [string]$logString,
    $runPath
    )
    [string]$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    [string]$logFile = $runPath + "\" + $stamp.Remove(8) + ".log"
    [string]$logMessage = "$stamp $logString"
    Add-content $logFile -value $logMessage
}

function Get-HashtableEmployees {
    param (
        [Parameter (Mandatory = $true)]
            $arrString,
        [Parameter (Mandatory = $true)]
            $pattern
    )
    $hashtableEmployees = @{}
    $rawFields = $pattern | Select-String "(?<=<)\w+(?<!>)" -AllMatches
    [string[]]$fields = $rawFields.Matches.Value
    $arrString | Select-String -Pattern $pattern | ForEach-Object {
        $hashtableFields = @{}
        for ($i = 0; $i -le $fields.Length; $i++) {
            $n = $i + 1
            [string]$stringValue = $($_.matches.groups[$n])
            $stringValue = $stringValue.TrimStart("")
            $stringValue = $stringValue.TrimEnd("")
            $stringValue = $stringValue -replace '\s{2,}', ' '
            if ($stringValue) {
                $hashtableFields.add($fields[$i], $stringValue)
            }
        }
        $hashtableEmployees.add([guid]::NewGuid().ToString(), $hashtableFields)
    }
    return $hashtableEmployees 
}

function Add-Group {
    param (
        [parameter(Mandatory=$true)]
        $fieldSelectionOfGroups, 
        [parameter(Mandatory=$false)]
        [string]$uGender, 
        [parameter(Mandatory=$true)]
        [string]$uSAM,
        [parameter(Mandatory=$true)]
        [System.Collections.ArrayList]$groups,
        [parameter(Mandatory=$true)]
        [System.Collections.ArrayList]$groupsPattern
        )
         
    #Добавляем в стандартные группы
    $DEFAULT_GROUP.Split(",") | ForEach-Object { Add-ADGroupMember -Identity $_ -Members $uSAM }
    #Добавляем в остальные группы
    for ($i = 0; $i -lt $groups.Count; $i++) {
        if ($fieldSelectionOfGroups -match ($groupsPattern[$i]).ToString()) {
            (($groups[$i]).ToString()).Split(",") | ForEach-Object { Add-AdGroupMember -Identity $_ -Members $uSAM }
        }
    }
}

#Main
$runPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
try {
    $addConf = Select-File -title "Выбирите файл конфигурации" -filter "Configuration file (*.conf) | *.conf"
    $dataFile = Select-File -title "Выбирите файл с исходными данными" -filter "Txt file (*.txt) | *.txt"
} catch [System.IO.FileNotFoundException] {
        Write-Warning -Message $PSItem.Exception.Message -WarningAction Stop
}
[string[]]$arrStr  = Get-Content $dataFile
#Adding variables from the configuration file
$listGroups = [System.Collections.ArrayList]::new()
$listGroupsPattern = [System.Collections.ArrayList]::new()
$listFieldsGroupsPattern = [System.Collections.ArrayList]::new()

foreach ($option in $(Get-Content -Path $addConf)) {
    $nameLoadedVariable = $option.split("=")[0]
    $valueLoadedVariable = $option.split("=",2)[1]
    if ($nameLoadedVariable -match "^.*_FILTER_LIST$"){
        Set-Variable -Name "FILTER_LIST" -Value $valueLoadedVariable
        Set-Variable -Name "filterField" -Value ($nameLoadedVariable.ToString().Replace("_FILTER_LIST", "")).ToLower()
    } else {
        Set-Variable -Name $nameLoadedVariable -Value $valueLoadedVariable
    }
    
    if ($nameLoadedVariable -match "GROUPS_\d{1}") {
        $gr = $listGroups.Add($valueLoadedVariable)
    }
    if ($nameLoadedVariable -match "GROUPS_PATTERN_\w{1,}_\d{1}") {
        [string]$fieldSelectionOfGroups = ($nameLoadedVariable.ToString().Replace("GROUPS_PATTERN_", "")).ToLower()
        $fieldSelectionOfGroups = $fieldSelectionOfGroups.Remove([int]($fieldSelectionOfGroups.Length - 2)) 
        if (-not $listFieldsGroupsPattern.Contains($fieldSelectionOfGroups)) {
            $fgp = $listFieldsGroupsPattern.Add($fieldSelectionOfGroups)
        }
        $gp = $listGroupsPattern.Add($valueLoadedVariable)
    }
     
}
    
if($arrStr.Count -ge 0) {
    $hashsetEmployees = Get-HashtableEmployees $arrStr $PATTERN_SEARCH
    
    #Фильтр
    if($FILTER_LIST_ENABLE -eq "true") {
        [System.Collections.Generic.List[string]]$filterList = $FILTER_LIST.Split(",")
        $removeList = [System.Collections.Generic.List[string]]::new()
        foreach ($itemKey in $hashsetEmployees.Keys) {
            if (-not $filterList.Contains([string]$hashsetEmployees.$itemKey.$filterField)) {
                $empl = ($hashsetEmployees.$itemKey).fio
                Write-Warning  "$empl - предоставление доступа не возможно ($hashsetEmployees.$itemKey.$filterField)"
                $removeList.Add($itemKey)
            }
        }

        if ($removeList.Count -gt 0) {
            $removeList | ForEach-Object { $hashsetEmployees.Remove($_) }
        }     
    }
    if ($hashsetEmployees.Count -gt 0) {
        Import-Module activedirectory    
        foreach ($key in $hashsetEmployees.Keys) {
            $uname = $hashsetEmployees.$key.fio
            [System.Collections.Generic.List[string]]$listString = $uname.Split("")
            if ($listString.Count -ge 1) {
                [string]$lastName = $listString[0]
                [string]$firstName = $listString[1] 
                [string]$middleName = $listString[2]

                #Переводим в транслит фамилию, имя и отчество
                [string]$enLastName=Get-Translit($lastName)
                [string]$enFirstName=Get-Translit($firstName)
                [string]$enMidleName=Get-Translit($middleName)    

                [string]$userSAM = $enLastName + $enFirstName[0] + $enMidleName[0]
                [string]$upn = $userSAM + "@" + $DOMAIN

                #Проверяем пользователя в системе
                if (@(Get-ADUser -Filter "SamAccountName -eq '$($userSAM)'").Count -ne 0) {
                    Write-Warning "$userSAM уже существует"
                    #Раскоментируйте для удаления пользователя
                    #Remove-ADUser $userSAM
                    #Write-Warning "$userSAM пользователь удален"
                } else {
                    #Генерируем пароль
                    [string]$rawPass = Get-Password -pass_number_group $PASS_NUMBER_GROUP -pass_group_char_lenght $PASS_GROUP_CHAR_LENGHT -pass_group_char_separator $PASS_GROUP_CHAR_SEPARATOR                                         
                    $password = ConvertTo-SecureString -String $rawPass -AsPlainText -Force

                    #Создаем нового пользователя (параметры можно менять)
                    New-ADUser -Name $uname `
                    -DisplayName $uname `
                    -GivenName $firstName `
                    -Surname $lastName `
                    -OtherName $middleName `
                    -UserPrincipalName $upn `
                    -SamAccountName $userSAM `
                    -Company $COMPANY `
                    -Title $hashsetEmployees.$key.position `
                    -Department $hashsetEmployees.$key.division `
                    -EmailAddress $upn `
                    -AccountPassword $password `
                    -CannotChangePassword $false `
                    -PasswordNeverExpires $false `
                    -ChangePasswordAtLogon:$true `
                    -PasswordNotRequired $false `
                    -Path $OU_PATH `
                    -Enabled $false

                    if (@(Get-ADUser -Filter "SamAccountName -eq '$($userSAM)'").Count -ne 0) {
                        Write-Host "Добавлен пользователь $uname ($userSAM)"

                        # Добавляем группы 
                        foreach ($field in $listFieldsGroupsPattern) {
                            Add-Group -fieldSelectionOfGroups $hashsetEmployees.$key.$field -uSAM $userSAM -groups $listGroups -groupsPattern $listGroupsPattern
                        }
    
                        #Save log
                        Write-Log -logString "Добавлен пользователь $userSAM, пароль $rawPass" -runPath $runPath
                    }
                }
            }
        }  
    }            
} else {
    Write-Warning "Нет пользователей для добавления"
}
    
