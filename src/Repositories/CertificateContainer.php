<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use Exception;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FingerprintReadableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Interfaces\StandarizableInterface;
use JuanchoSL\Certificates\Interfaces\VerifyableInterface;
use JuanchoSL\Certificates\Traits\DetailableTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Certificates\Traits\StringableTrait;
use OpenSSLCertificate;
use Stringable;

class CertificateContainer implements
    PublicKeyReadableInterface,
    ExportableInterface,
    Stringable,
    SaveableInterface,
    DetailableInterface,
    StandarizableInterface,
    FingerprintReadableInterface,
    FormateableInterface,
    VerifyableInterface
{

    use DetailableTrait, StringableTrait, SaveableTrait;

    protected $data = null;

    public function __construct(OpenSSLCertificate|string $cert_content)
    {
        if (is_string($cert_content) && is_file($cert_content) && file_exists($cert_content)) {
            $cert_content = file_get_contents($cert_content);
        }
        $this->data = openssl_x509_read($cert_content);
    }

    public function getPublicKey(): PublicKeyContainer
    {
        return new PublicKeyContainer(openssl_get_publickey($this->data));
    }

    public function getDetails(): array|false
    {
        return $this->details ??= openssl_x509_parse($this->data, false);
    }

    public function export(): string
    {
        openssl_x509_export($this(), $out);
        return $out;
    }

    public function __invoke(): mixed
    {
        return $this->data;
    }

    public function getFingerprint(string $hash): bool|string
    {
        $alloweds = openssl_get_md_methods(true);
        if (!in_array($hash, $alloweds)) {
            throw new Exception("The {$hash} hash is not a valid value");
        }
        $fingerprint = openssl_x509_fingerprint($this->data, $hash);
        if ($hash != 'md5') {
            $fingerprint = base64_encode($fingerprint);
        }
        return $fingerprint;
    }


    public function getExtension(): string
    {
        return 'crt';
    }

    public function getMediaType(): string
    {
        return 'application/x-x509-user-cert';
    }

    public function checkPurpose(int $purpose, bool $strict = false): bool
    {
        $result = openssl_x509_checkpurpose($this->data, $purpose);
        return $result;
    }

    /**
     * Verifies digital signature of x509 certificate against a public key
     * @url https://www.php.net/manual/en/function.openssl-x509-verify.php
     * @param \JuanchoSL\Certificates\Repositories\PublicKeyContainer $public
     * @throws \Exception On error, throw an exception with the string message
     * @return bool
     */
    public function checkIssuerByPublicKey(PublicKeyContainer $public): bool
    {
        $result = openssl_x509_verify($this->data, $public());
        if ($result < 0) {
            throw new Exception(openssl_error_string());
        }
        return boolval($result);
    }

    /**
     * Checks if a private key corresponds to this certificate.
     * The php function does not check if private is really a private key, using a PrivateKeyContainer
     * we force the use of a really private key 
     * @url https://www.php.net/manual/es/function.openssl-x509-check-private-key.php
     * @param PrivateKeyContainer $private The private key to verify
     * @throws Exception If an error 
     * @return bool result
     */
    public function checkSubjectPrivateKey(#[\SensitiveParameter] PrivateKeyContainer $private): bool
    {
        return openssl_x509_check_private_key($this->data, $private());
    }
}