---
slug: storage
title: Secure Storage
---

The secure storage service implements a key/value store for all other services to store and retrieve encrypted keys or data. To encrypt data the secure storage generates keys that are encrypted using the hardware secure element or a user supplied passphrase.

The secure storage is implemented as a sqlite database with two tables secrets and store.

The schema for the secrets table is as follows:
```
CREATE TABLE secrets (id TEXT NOT NULL, value TEXT, salt TEXT, iv TEXT, PRIMARY KEY (id));
```
where **id** is the ID of the generated key, **value** is the value of the key, **iv** the the IV used to encrypt and decrypt the key and **salt** is the salt sed ofr encryption and decryption when a userpasspharse is supplied.

An example of the secrets table row is given below:

|ID|VALUE|SALT|IV|
|--|-----|----|--|
|master|LbknNO6o+s+u1b4wg9eGzQjHCanicVtDlDJBWZ0u4VaV25oIUCt1b5bthzLwhQO0|Z95m5G/+jgb3ga0dufa//w|hka2MmSUkJUJBf7TQMYnug|
|rest|a2UiZR/DLYb3hX61ZQ7Mb/vdVVIchJzkuNnoIhLDCHXe9453IlWjOfOymodUZIsq|RLdlnafYj7279lne7A5UoA|lgTKNxgxbeCxg4VySS/7vw|
|94:b9:7e:15:47:95|lPVf5wqMnb9+8Q8Cik5oetOI9MfA6qjPm1tKTR3WGPWgZYtaybEeDKWGX/x4EUUB|gFvI5tfeHANOafJlFsHXpg|mH2yeX/FEvJd1ilg25Zwcg|

The **value**, **salt** and **iv** are base64 encoded.

When a user or service wants to store a key/value she will need to provide and ID for the key that will be used to encrypt/decrypt the user's value. If such an ID does not exists in the secrets table, the service will randomly generate one and encrypt it using the hardware secure element or the user supplied passphrase. When the user provides the passphrase the service will generate an encryption key using the \b salt and Password-Based Key Derivation Function Password-Based Key Derivation Function 2. The derived key is not stored on the device. If the user instead uses the hardware secure element, the key derivation, encryption and decryption is done in secure memory.

Each key/value is stored in the store table with the following schema:
```
CREATE TABLE store (key TEXT NOT NULL, value TEXT, id TEXT, iv TEXT, PRIMARY KEY (key));
```
where **key** is the key for the value, **value** is the value to be stored, **id** is the key id used to encrypt/decrypt the value and **iv** is the IV used to encrypt/decrypt the value.

An example of the store table rows is given below.

|KEY|VALUE|ID|IV|
|---|-----|--|--|
|7815f8ce-57b8-49c8-9121-5b98986cbccd|GCM564Ugwyh0bW3f4JuFkw|master|Ja0pz9cdH7p3Q+BBP2MIrw|
|db07c38a-2842-4f45-9672-74d57ec99e63|23cHWe6r033czxopWsv6Ng|master|FU7hUGGbifro65cv0u0OwQ|
|1a35f54d-c5f9-4072-85b0-4b40f8fb4a14|LR3iRw6SrN/pWKSTJvNtrA|master|x9hFentG2Q6iynHXCk2ktA|
|831ffbb1-2e79-422a-bdad-e9e96a56d568|CdoxKK4PbDvWD9cOdRcTXQ|master|RHR1AGsjpWVHDR4VN2PiLA|

The **value** and **iv** is base64 encoded.

Each row of the key/value store contains the **id** of the key that was used to encrypt/decrypt the **value**. The encryption algorithm used is AES 256 CBC.
