# Certificates

## Description

This library, is a full tool collections in order to create, read, parse, export, use... all the openssl (and few more) certificates/keys, in order to use for sign/verify and decryp/encrypt emails and documents, connect to SFTP/SSH servers, enable secure sockets and encrypt communications with web, ftp, webocket servers, and more.

The native PHP openssl functions, works from distincts key entry points, some functions require an object, the key contents, file path starting with an **file://**, other do not need it, this library remove the differences, unifying the container instantiation, any one drive the conversion internally, on order to avoid the user adaptations.

## Install

This public package, is available from composer and from [GitHub](https://github.com/JuanchoSL/Certificate) for zip download

```bash
composer require juanchosl/certificates
composer update
```

## Containers (Repositories)

These are immutable objects that contain credentials, data, and information associated and linked together, ensuring proper operation and preventing unwanted manipulations that could cause loss or undesired effects.

They only have getters to read and extract parts of the element, which may vary depending on the container, although generically the following would be available:

- Export method (**export**), which normally extracts the original information, in binary, text, array, etc., depending on the container

- Reading details (**getDetails**), the details of the contained element or **getDetail($name)** for a knowed detail

- Conversion to string (**\_\_tostring** -> Stringable), converts the content to a PER or DEM string depending on the contained element, always in a supported standard format

- Saving to file (**save**), after converting to a string, saves the data in a local file located in the path passed as a parameter. If not specified, the file will be created in the system's temporary directory, and the path will be returned by reference in the same parameter for later use.

- Conversion to the standard Openssl-compatible object in PHP (**\_\_invoke**) for use in encryption/decryption or signature/verification functions.

### Private Key Container [OpenSSL Private Asymmetric Key](https://docs.openssl.org/master/man1/openssl-pkey/)

The basic container of the package, a private key, allows us to use OPENSSL actions, sign and decrypt documents (using an [asymmetric key](https://www.php.net/manual/es/function.openssl-pkey-get-private.php)), and connect to local systems such as computers or remote systems such as SFTP servers via SSH. It does not require personal data, and therefore does not need to be signed to generate a certificate with personal data. It never expires and must always be kept safe and protected, never sharing it with anyone; for this purpose, the public key is used.

```php
$private_key = new PrivateKeyContainer($origin);
```

We can apply an encryption key, which will prevent it from being used if someone could gain access to it, requiring that the user know and provide it before it can be used.

```php
$private_key = new PrivateKeyContainer($origin, $password);
```

If we have a non protected key, and we want protect it, can open the original non protected key, put a new password and export or save the key with the new protectin password

```php
$private_key = new PrivateKeyContainer($unprotected_origin);
$private_key->setPassword($password);
$private_key = $private_key->export();
```

### Public OPENSSL Key Container [OpenSSL Public Asymmetric Key](https://www.php.net/manual/es/class.opensslasymmetrickey.php)

It is the [public key](https://www.php.net/manual/es/function.openssl-pkey-get-public.php) generated together with the private key, uniquely associated, and which must be shared with third parties in order to use the utilities described in the previous point.

```php
$public_key = new PublicKeyContainer($origin);
```

or

```php
$public_key = (new PrivateKeyContainer($origin))->getPublicKey();
```

### Public OPENSSH Key Container [OPENSSH](https://www.ssh.com/academy/ssh/public-key-authentication)

PHP does not have native support to create or convert keys in the OPENSSH format, but it is widely used, especially in [SFTP or SSH](https://www.php.net/manual/es/function.ssh2-auth-pubkey-file.php) systems, so we have seen fit to add the necessary functionality to be able to generate key pairs for this purpose and to be able to extract the SSL public key and convert it to the standard SSH format.

```php
$openssh_key = new PublicSshKeyContainer($origin);
```

or

```php
$openssh_key = (new PublicKeyContainer($origin))->getOpenSSH();
```

### Certificate Signing Request Container @TODO

Equivalent to [OpenSSLCertificateSigningRequest](https://www.php.net/manual/es/class.opensslcertificatesigningrequest.php "La clase OpenSSLCertificateSigningRequest")

### x509 Certificate Container [OpenSSLCertificate](https://www.php.net/manual/es/class.opensslcertificate.php)

The container for [x509](https://docs.openssl.org/master/man1/openssl-x509/#input-output-and-general-purpose-options) certificates allows us to access the public information of the owner, as well as that of the certifier who issued the certificate, the uses for which it was created and the associated public key, which would allow it to be used to verify our digital signature or be used by third parties to encrypt documents or emails that only we can decrypt with our associated private key.

```php
$certificate = new CertificateContainer($origin);
```

### Certificate Chain Container

It is a collection that includes the list of certificates (x509) in our certification chain. It can be used to build PKCS7, PKCS8, and PKCS12 bundles and be added to the signature/verification and encryption/decryption systems.

It is not strictly a standard, but it allows for unified information and easy, quick, and simple use in the scenarios described above. It would be equivalent to the CA CHAIN ​​that our certificates provide, in an iterable, countable collection, exportable to a file or a chain, like the other containers provided with this library.

```php
$chain = new ChainContainer($origin);
```

### Pkcs12 Bundle Container [OpenSSL-PKCS12](https://docs.openssl.org/master/man1/openssl-pkcs12/)

This is [a signed package](https://www.php.net/manual/es/function.openssl-pkcs12-export-to-file.php) that includes all our information, our private key, certificate, public key, and optionally our certification chain, in a single file that must be password-protected, allowing the entire data package to be stored in a single standardized file.
It can be added to our computer's repository, email program, or connection application, allowing us to [use our credentials](https://www.php.net/manual/es/function.openssl-pkcs12-read.php) to sign or decrypt emails, sign documents such as PDFs, connect to remote services, etc.

```php
$pkcs = new Pkcs12Container($origin, $password);
$private = $pkcs->getPrivateKey(?$private_credential);
$cert = $pkcs->getCertificate();
$public = $cert->getPublicKey();
```

you can use your _pkcs12_ bundle in order to export the public part (your certificate with public key and CA chain if is included) to file formatted standard pkcs7 with extension .p7b, and send to others

```php
$pkcs = new Pkcs12Container($origin, $password);
$pkcs->getPublicBundle()->save($path_to_save);
```

In order to change the password of the bundle (or the private key password), actually do not provide a simple method to do it, due the internal dependency, in order to avoid missmatches. You needs to open with the actual credential, extract the containers, change the password and use the Pkcs12Creator

```php
$pkcs = new Pkcs12Container($origin, $password);
$cert = $pkcs->getCertificate();
$chain = $pkcs->getChain();
$old_private = $pkcs->getPrivateKey(?$old_pass)->setPassword($new_password)->export();
$new_private = new PrivateKeyContainer($old_private);
$new_binary_pkcs = (new Pkcs12Creator($description, $can_be_new_password))->setPrivateKey($new_private)->setCertificate($cert)->setChain($chain);
```

### Pkcs8 PEM Container [OpenSSL-PKCS8-PEM](https://tecnocratica.net/wikicratica/books/certificados/page/formatos-de-los-certificados)

PEM PKCS8 container is an all in one, multi purpose, with data encoded to base64 ASCII.
It is a bundle that can includes the entire information package (just like PKCS12) but without requiring a password for the entire package. It allows the public part to be extracted without specifying it, but still allows the private key to be encrypted by applying an unique password using the PKCS5 protocol, as recommended by the PKCS8 standard.

### Pkcs8 Signed Bundle Container [OpenSSL-PKCS8](https://docs.openssl.org/master/man1/openssl-pkcs8/)

Our PKCS8 container is an intermediate between PKCS7 and PKCS12.
It is a bundle that includes the entire information package (just like PKCS12) signed with the private key (as PKCS7), but without requiring a password for read the contents package. It allows the public part to be extracted without specifying it, but still allows the private key to be encrypted by applying an unique password using the PKCS5 protocol, as recommended by the PKCS8 standard.

### Pkcs7 Signed Bundle Container [OpenSSL-PKCS7](https://docs.openssl.org/master/man1/openssl-pkcs7/)

This is a signed package that includes our public information, certificate, with the public key and optionally our certification chain, in a single file, so that it can be shared and used to verify our signatures or give third parties the possibility of encrypting content that only we, with our private key, can decrypt.

With PHP, we can [export all certificates](https://www.php.net/manual/es/function.openssl-pkcs7-read.php) in a single array, with the library, we can put in separate the user certificate and the CA chain as a collection,

## Creators

### PKCS12

Creates a standard PKCS12 container, in order to save all the credentials into an unique repository. The creator check for required files, private key and certificate, for an non empty password, check than the certificate are related and it has been created with the private key

```php
$private = new PrivateKeyContainer($private_file_or_data);
$certificate = new CertificateContainer($certificate_file_or_data);
$chain = new ChainContainer($chain_file_or_data);
$pkcs12 = (new Pkcs12Creator($description, $password))->setPrivateKey($private)->setCertificate($certificate)->setChain($chain);

$binary = $pkcs12->export();
```

or save it into file, PKCS12 are alwways in binary format

```php
$pkcs12->save($destiny_path); #returns true|false
```

### PKCS8

Creates a PKCS8 container, in order to save all the credentials into an unique repository. The creator check for required files, private key and certificate, for a non empty password, check than the certificate are related and it has been created with the private key

```php
$private = new PrivateKeyContainer($private_file_or_data);
$certificate = new CertificateContainer($certificate_file_or_data);
$chain = new ChainContainer($chain_file_or_data);
$pkcs8 = (new Pkcs8Creator)->setPrivateKey($private)->setCertificate($certificate)->setChain($chain)->export();
```

### PKCS7

Creates a standard PKCS7 container, in order to save all the public credentials signed into an unique repository. The creator check for required files, private key and certificate, check than the .certificate are related and it has been created with the private key.The Private key is required only for sign the bundle, it is not included.

```php
$private = new PrivateKeyContainer($private_file_or_data);
$certificate = new CertificateContainer($certificate_file_or_data);
$chain = new ChainContainer($chain_file_or_data);
$pkcs7 = (new Pkcs7Creator)->setPrivateKey($private)->setCertificate($certificate)->setChain($chain);
```

then you can export it as binary data (DER)

```php
$binary_pkcs7 = $pkcs7->export();
```

export it as ASCII Base64 data with headers BEGIN PKCS7 | END PKCS7

```php
$b64_pkcs7 = (string) $pkcs7;
```

or save into a selected file

```php
$pkcs7->save($desired_saving_path);
```

## Readers and Factories

Using factories, you can instantiate containers from few origins and formats, dellegating to the library the container selection, usefull when you can receive distincts types and avoid the user check and control.

### Container Factory

If you can receive data from files or strings and streams, don't needs open and check to select the right container, you can use someone factory that do this work.

> All containers are auto callables except **Pkcs12** or **encrypted primary key**, because its needs a password, the factory try to create a LockedContainer that need to be invoked passing the password por unlock it.

Actually you have available:

- createFromUnknow -> Check the data and send to method file, contents or entity
- createFromFile -> Check the file mimetype and send it to function mimetype if is available, or try to process using contents
- createFromContents -> Check the contents and send to process as string or binary
- createFromMimetype -> using the readed mimetype, create an compatible  container for it if is available
- createFromEntity -> if is an standard openssl php function, try to convert. It can use Stream objects using the user mimetype, uploaded path or the stream contents.
- createFromBinary -> as last chance, try using binary data as Pkcs12 package

```php
$stream = $psr15_server_request->getUploadedFiles()['file']->getStream();
$container = (new ContainerFactory)->createFromEntity($stream);
```


## Interfaces

- CertificateReadable -> Have a certificate accesible
- ChainReadable -> Have a certificates collection accesible
- Detailable -> Have readable details
- Exportable -> can be exported
- FingerprintReadable ->have a standard fingerprint calculation accesible
- Formateable -> have a standar format, extension and mimetype, available por save or download
- PasswordProtectable -> Is an element with a password required (Pkcs12)
- PasswordUnprotectable -> Is an element that can be encrypted with a pasword, and can be removed too
- PrivateKeyReadable -> Have a private key accesible
- PublicKeyReadable -> Have a public key accesible
- Saveable -> can be saved into a file
- Standarizable -> can be converted to native php object
- Verifyable -> can be verifyed with other key from other container
- Stringable -> can be exported as string

|                       | Certificate | Chain | Pkcs12 | Pkcs8 | PEM | Pkcs7 | Priv key | Pub key | Pub SSH |
| --------------------- | :---------: | :---: | :----: | :---: | :-: | :---: | :------: | :-----: | :-----: |
| CertificateReadable   |             |       |   X    |   X   |     |   X   |          |         |         |
| ChainReadable         |             |   X   |   X    |   X   |     |   X   |          |         |         |
| Detailable            |      X      |       |   X    |       |     |       |    X     |    X    |    X    |
| Exportable            |      X      |       |        |   X   |     |   X   |    X     |    X    |    X    |
| FingerprintReadable   |      X      |       |        |       |     |       |          |         |    X    |
| Formateable           |      X      |       |   X    |   X   |     |   X   |    X     |    X    |    X    |
| PasswordProtectable   |             |       |   X    |       |     |       |          |         |         |
| PasswordUnprotectable |             |       |        |       |     |       |    X     |         |         |
| PrivateKeyReadable    |             |       |   X    |   X   |     |       |          |         |         |
| PublicKeyReadable     |      X      |       |        |       |     |       |    X     |         |         |
| Saveable              |      X      |   X   |   X    |   X   |     |   X   |    X     |    X    |    X    |
| Standarizable         |      X      |       |        |       |     |       |    X     |    X    |         |
| Verifyable            |      X      |       |        |       |     |       |          |         |         |
| Stringable            |      X      |   X   |        |       |     |   X   |    X     |    X    |    X    |
| Countable             |             |   X   |        |       |     |       |          |         |         |
| Iterable              |             |   X   |        |       |     |       |          |         |         |
