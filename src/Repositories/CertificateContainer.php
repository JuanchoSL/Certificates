<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use Co\Curl\Exception;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FingerprintReadableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Interfaces\StandarizableInterface;
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
    FormateableInterface
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
}