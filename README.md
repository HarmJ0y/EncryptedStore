## EncryptedStore

Functions focued on storing data in single encrypted file for long term collection.

The store is 'packetized', with discrete units of the format below appended to a single file,
preventing the need to decrypt the store every time additional data is added.

The 'packet' structure for each file is (currently) as follows:

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

* Read raw file contents
* Pad original full file PATH to 260 Bytes
* Compress [PATH + file] using IO.Compression.DeflateStream
* If using RSA+AES, generate a random AES key and encrypt using the RSA public key
* Generate random 16 Byte IV
* Encrypt compressed stream with AES-CBC using the predefined key and generated IV
* Calculate length of encrypted block + IV
* append 4 Byte representation of length to ENCSTORE.bin
* append 0 byte if straight AES used, 1 if RSA+AES used
* optionally append 128 bytes of RSA encrypted random AES key if RSA+AES scheme used
* append IV to ENCSTORE.bin
* append encrypted file to ENCSTORE.bin

To decrypt ENCSTORE.bin, while there is more data to decrypt:

* Read first 4 Bytes of ENCSTORE.bin and calculate length value X
* Read next size X Bytes of encrypted file
* Read first byte of encrypted block to determine encryption scheme
    * 0 == straight AES
    * 1 == RSA + AES where random AES key encrypted with RSA pub key
* If RSA+AES is used, read the next 128 bytes of the RSA encrypted AES key and decrypt using the RSA private key
* Read next 16 Bytes of encrypted block and extract IV
* Read remaining block and decrypt AES-CBC compressed stream using predefined key and extracted IV
* Decompress [PATH + file] using IO.Compression.DeflateStream
* Split path by \ and create nested folder structure to mirror original path
* Write original file to mirrored path


### EncryptedStore.ps1

The PowerShell implementation of EncryptedStore.


#### Write-EncryptedStore

Compresses and encrypts the data passed by $Data with the supplied AES/RSA $Key and write 
the data to the specified encrypted $StorePath. -StorePath can be on the filesystem
("${Env:Temp}\debug.bin"), registry (HKLM:\SOFTWARE\something\something\key\valuename), 
or WMI (ROOT\Software\namespace:ClassName). RSA keys can be generated with New-RSAKeyPair.

If the passed data is a filename, the file is encrypted along with the original path.
Otherwse, the passed data itself is encrypted along with a timestamp to be used as the
extracted file format. If you to tag non-file data, use -DataTag.

Ex:

    PS C:\> Write-EncryptedStore -FilePath C:\Folder\secret.txt,C:\Folder\secret2.txt -StorePath C:\Temp\debug.bin -Key 'Password123!'

    PS C:\> 'secret.txt','secret2.txt' | Write-EncryptedStore -StorePath C:\Temp\debug.bin -Key 'Password123!'

    PS C:\> "keystrokes" | Write-EncryptedStore -StorePath C:\Temp\debug.bin -Key 'Password123!' -DataTag 'keylog'


#### Read-EncryptedStore

Takes a given encrypted store specified by $StorePath and extracts,
decrypts, and decompresses all files/data contained within it. Extracted
files are written out to a created nested folder structure mirroring
the file's original path. -List will list the files without extracting them.

Ex:
    
    PS C:\> Read-EncryptedStore -StorePath C:\Temp\debug.bin -Key 'Password123!'
    File data written to C:\Temp\C\Temp\secret.txt
    File data written to C:\Temp\C\Temp\secret2.txt


### EncryptedStore.py

The Python implementation of EncryptedStore.

Note: RSA containers are not currently supported.


To list the files in a store:

    # ./EncryptedStore.py --store store.bin --key 'Password123!' --list

    Files:

    C:\Temp\secret.txt           :   1684 bytes
    C:\Temp\secret2.txt          :   60173 bytes


To extract files from a store to a mirrored directory structure in the current directory:

    # /tmp/EncryptedStore.py --store store.bin --key 'Password123!'

    Extracted 1684 bytes of 'C:/Temp/secret.txt' to '/tmp/C:/Temp/secret.txt'
    Extracted 60173 bytes of 'C:/Temp/secret2.txt' to '/tmp/C:/Temp/secret2.txt'
