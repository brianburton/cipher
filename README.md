Created local key as follows:

```
(aws) freedom:aws$ aws --endpoint-url=http://localhost:4566 kms create-key
{
    "KeyMetadata": {
        "AWSAccountId": "000000000000",
        "KeyId": "faa80122-88a6-4c9b-9cbc-3fdf91674a5e",
        "Arn": "arn:aws:kms:us-east-2:000000000000:key/faa80122-88a6-4c9b-9cbc-3fdf91674a5e",
        "CreationDate": 1745172160.423345,
        "Enabled": true,
        "Description": "",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled",
        "Origin": "AWS_KMS",
        "KeyManager": "CUSTOMER",
        "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
        "KeySpec": "SYMMETRIC_DEFAULT",
        "EncryptionAlgorithms": [
            "SYMMETRIC_DEFAULT"
        ],
        "MultiRegion": false
    }
}
```
