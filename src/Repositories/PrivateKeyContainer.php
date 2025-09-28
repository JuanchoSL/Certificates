<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use Exception;
use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Factories\ExtractorFactory;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\PasswordUnprotectableInterface;
use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Interfaces\StandarizableInterface;
use JuanchoSL\Certificates\Traits\DetailableTrait;
use JuanchoSL\Certificates\Traits\PasswordUnprotectableTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Certificates\Traits\StringableTrait;
use JuanchoSL\Exceptions\ForbiddenException;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use Stringable;

class PrivateKeyContainer implements
    ExportableInterface,
    Stringable,
    SaveableInterface,
    DetailableInterface,
    PasswordUnprotectableInterface,
    StandarizableInterface,
    FormateableInterface,
    PublicKeyReadableInterface
{

    use PasswordUnprotectableTrait, StringableTrait, SaveableTrait, DetailableTrait;

    protected $data = null;

    public function __construct(#[\SensitiveParameter] OpenSSLAsymmetricKey|OpenSSLCertificate|string $fullpath, #[\SensitiveParameter] ?string $passphrase = null)
    {
        if (is_string($fullpath)) {
            if (str_starts_with($fullpath, 'file://')) {
                $fullpath = substr($fullpath, 7);
            }
            if (is_file($fullpath) && file_exists($fullpath)) {
                $fullpath = file_get_contents($fullpath);
            }
        }

        if (is_string($fullpath) && (new ExtractorFactory)->readerPart($fullpath, ContentTypesEnum::CONTENTTYPE_PRIVATE_KEY_ENCRYPTED) && empty($passphrase)) {
            throw new ForbiddenException("You need the password to uncrypt this private key");
        }
        $this->setPassword($passphrase);
        $this->data = openssl_pkey_get_private($fullpath, $this->password?->getValue());
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
        openssl_pkey_export($this->data, $out, $this->password?->getValue());
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