<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use Exception;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\PasswordProtectableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Interfaces\StandarizableInterface;
use JuanchoSL\Certificates\Traits\DetailableTrait;
use JuanchoSL\Certificates\Traits\PasswordProtectableTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Certificates\Traits\StringableTrait;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use Stringable;

class PrivateKeyContainer implements
    ExportableInterface,
    Stringable,
    SaveableInterface,
    DetailableInterface,
    PasswordProtectableInterface,
    StandarizableInterface,
    FormateableInterface
{

    use PasswordProtectableTrait, StringableTrait, SaveableTrait, DetailableTrait;

    protected $data = null;

    public function __construct(OpenSSLAsymmetricKey|OpenSSLCertificate|string $fullpath, ?string $passphrase = null)
    {
        if (is_string($fullpath) && is_file($fullpath) && file_exists($fullpath) && !str_starts_with($fullpath, 'file://')) {
            $fullpath = 'file://' . $fullpath;
        }
        $this->setPassword($passphrase);
        $this->data = openssl_pkey_get_private($fullpath, $this->password);
        if ($this->data == false) {
            throw new Exception(openssl_error_string());
        }
    }

    public function getPublicKey(): PublicKeyContainer
    {
        return new PublicKeyContainer($this->getDetail('key'));
    }

    public function getDetails(): array|false
    {
        return $this->details ??= openssl_pkey_get_details($this->data);
    }

    public function export(): string
    {
        openssl_pkey_export($this->data, $out, $this->password);
        return $out;
    }

    public function __invoke(): mixed
    {
        return $this->data;
    }

    public function getExtension(): string
    {
        return 'key';
    }

    public function getMediaType(): string
    {
        return 'application/pkcs8';
    }
}