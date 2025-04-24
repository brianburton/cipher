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
than the input file. A hyphen `-` can be used as either the input file name
to read from `stdin` or the output file name to print to `stdout`.

Valid commands are:

- `cat`: Decrypt any `CIPHER` blocks in the file, remove any marker tags, and print the result to stdout.
- `decrypt`: Same as `cat` but writes the result to a file.
- `encrypt`: Replace any `SECURE` blocks in the file with encrypted `CIPHER` blocks.
- `rewind`: Replace any encrypted `CIPHER` blocks in the file with decrypted `SECURE` blocks.
- `edit`: Produce a temporary file using `rewind`, run `vi` on that temporary file, then run `encrypt` on the resulting file and write it to the output file.

The KMS key to use is defined by setting the environment variable `CIPHER_KEY_ARN`.
Setting it to `DEBUG` causes the program to simply use base64 encoding instead of using true encryption.  **DO NOT USE DEBUG FOR REAL DATA**

## Testing with localstack

To use [localstack](https://github.com/localstack/localstack) for testing you can set the `CIPHER_BASE_URL` to the endpoint address of your localstack container.
For example:

```shell
$ docker ps
CONTAINER ID   IMAGE                   COMMAND                  CREATED      STATUS                PORTS                                                                    NAMES
74e1d8333b9d   localstack/localstack   "docker-entrypoint.sh"   3 days ago   Up 3 days (healthy)   127.0.0.1:4510-4560->4510-4560/tcp, 127.0.0.1:4566->4566/tcp, 5678/tcp   localstack-main
$ awslocal kms list-keys
{
    "Keys": [
        {
            "KeyId": "faa80122-88a6-4c9b-9cbc-3fdf91674a5e",
            "KeyArn": "arn:aws:kms:us-east-2:000000000000:key/faa80122-88a6-4c9b-9cbc-3fdf91674a5e"
        }
    ]
}
$ export CIPHER_BASE_URL="http://localhost:4566"
$ export CIPHER_KEY_ARN="arn:aws:kms:us-east-2:000000000000:key/faa80122-88a6-4c9b-9cbc-3fdf91674a5e"
$ cargo run -- encrypt sample.txt encrypted.txt
$ $ cat _encrypted.txt
root:
  userid: "fred"
  password: <<CIPHER>>... lots of base64 ...<</CIPHER>>
  credentials: <<CIPHER>>... lots of base64 ...<</CIPHER>>
```

## Installation

To build and install for local use:

```shell
cargo install --path .
```

Which should install the compiled binary to `$HOME/.cargo/bin/cipher`.
