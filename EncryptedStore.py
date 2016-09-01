#!/usr/bin/python

import hashlib
import struct
import argparse
import zlib
import os
import re
from binascii import hexlify
from Crypto.Cipher import AES


def decrypt_store(storePath, key, listFiles=False):
    """
    Decrypts/decompresses an encrypted store or lists its contents.

    Args:
        storePath:  the path to the encrypted store
        key:        the key for the encrypted store
        listFiles:  list files in the store instead of extracting

    Returns:
        Prints file listings if 'listFiles' is specified, otherwise
        extracts files to the local folder, preserving the original
        file paths.

    Notes:

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
    """

    pattern = re.compile('^<RSAKeyValue><Modulus>.*</Modulus><Exponent>.*</Exponent><P>.*</P><Q>.*</Q><DP>.*</DP><DQ>.*</DQ><InverseQ>.*</InverseQ><D>.*</D></RSAKeyValue>$')
    if pattern.match(key):
        print '[!] RSA decryption not currently supported, use EncryptedStore.ps1\n'
        return

    if len(key) != 32:
        key = hashlib.md5(key).hexdigest()

    f = open(storePath)
    data = f.read()
    f.close()

    dataLen = len(data)

    if dataLen > 20:

        print ""
        if(listFiles):
            print "Files:\n"

        offset = 0
        while offset < dataLen:
            blockSize = struct.unpack("<L", data[offset:4+offset])[0]
            cryptoSpecification = ord(data[offset+4])
            
            if cryptoSpecification == 1:
                print "\n[!] RSA decryption not currently supported, skipping block at %s\n" % (offset)
                offset += 5 + blockSize
                continue

            IV = data[(offset+5):(offset+21)]
            cipher = AES.new(key, AES.MODE_CBC, IV)
            decryptedBlock = cipher.decrypt(data[(offset+21):(offset+21+blockSize)])

            # 'Deflate' the .NET stream
            decompressedBlock = zlib.decompressobj(-zlib.MAX_WBITS).decompress(decryptedBlock)

            # first 260 characters are the original file path, the remainder is the file contents
            fileName = decompressedBlock[0:260].strip()
            fileContents = decompressedBlock[260:]

            if listFiles:
                print "%s\t\t\t:\t%s bytes" %(fileName, len(fileContents))
            else:
                fileName = fileName.replace('\\', '/')
                parts = fileName.split("/")

                currentDir = os.path.dirname(os.path.realpath(__file__))

                outFolder = "%s%s%s" % (currentDir, os.path.sep, (os.path.sep).join(parts[:-1]))
                outFile = outFolder + os.path.sep + parts[-1]

                if not (os.path.abspath(outFolder).startswith(currentDir)):
                    print "\n[!] Warning: traversal detected for : %s " %(outFile)
                else:
                    if not os.path.exists(outFolder):
                        os.makedirs(outFolder)

                    # ensure existing files aren't overwritten
                    outFileBase = outFile
                    counter = 1
                    while os.path.exists(outFile):
                        outFile = "%s_%s" %(outFileBase, counter)
                        counter += 1

                    f = open(outFile, 'w')
                    f.write(fileContents)

                    print "Extracted %s bytes of '%s' to '%s'" % (len(fileContents), fileName, outFile)

            offset += 5 + blockSize

        print ""


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    parser.add_argument('-s', '--store', required=True, help='Encrypted store for encryption/decryption.')
    parser.add_argument('-k', '--key', required=True, help='The encryption key to use for the store.')
    parser.add_argument('-l', '--list', action='store_true', help='List filenames and file sizes of the encrypted store.')

    args = parser.parse_args()

    decrypt_store(args.store, args.key, args.list)
