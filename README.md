# Cipher

## Overview

Encryption utility for use with configuration files to allow specific sections of the
file to be encrypted with a symmetric cipher powered by AWS KMS and the AWS encryption SDK.

## Configuration

On my macbook I ran into an issue with the program failing with an obscure error
message: `TrustStore configured to enable native roots but no valid root certificates parsed!`.

The problem turned out to be that the AWS SDK could not find the SSL root certificates
on my system.  The solution was to install them using homebrew and set an environment
variable with the path to the root certificate file.

```shell
brew install openssl@3
export SSL_CERT_FILE=$(brew --prefix)/etc/openssl@3/cert.pem
```
## Usage

Currently the program accepts either two or three command line arguments.
The first is the command to execute.  The second is the input file to process.
The third is optional and specifies the file to write output to if different
than the input file.

Valid commands are:

- `cat`: Decrypt any `CIPHER` blocks in the file, remove any marker tags, and print the result to stdout.
- `decrypt`: Same as `cat` but writes the result to a file.
- `encrypt`: Replace any `SECURE` blocks in the file with encrypted `CIPHER` blocks.
- `rewind`: Replace any encrypted `CIPHER` blocks in the file with decrypted `SECURE` blocks.
- `edit`: Produce a temporary file using `rewind`, run `vi` on that temporary file, then run `encrypt` on the resulting file and write it to the output file.

The KMS key to use is defined by setting the environment variable `CIPHER_KEY_ARN`.
Setting it to `DEBUG` causes the program to simply use base64 encoding instead of using true encryption.  **DO NOT USE DEBUG FOR REAL DATA**
