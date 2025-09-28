<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use Exception;
use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Factories\ConverterFactory;
use JuanchoSL\Certificates\Factories\ExtractorFactory;
use JuanchoSL\Certificates\Interfaces\Complex\PrivateKeyInterface;
use JuanchoSL\Certificates\Interfaces\Complex\PublicKeyInterface;
use JuanchoSL\Certificates\Traits\DetailableTrait;
use JuanchoSL\Certificates\Traits\LoggableTrait;
use JuanchoSL\Certificates\Traits\PasswordUnprotectableTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Certificates\Traits\StringableTrait;
use JuanchoSL\Exceptions\ForbiddenException;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;

class PrivateKeyContainer implements
    PrivateKeyInterface
{

    use PasswordUnprotectableTrait, StringableTrait, SaveableTrait, DetailableTrait, LoggableTrait;

    protected OpenSSLAsymmetricKey $data;

    public function __construct(#[\SensitiveParameter] OpenSSLAsymmetricKey|OpenSSLCertificate|string $fullpath, #[\SensitiveParameter] ?string $passphrase = null)
    {
        if (is_string($fullpath)) {
            if (str_starts_with($fullpath, 'file://')) {
                $fullpath = substr($fullpath, 7);
            }
            if (is_file($fullpath) && file_exists($fullpath)) {
                $fullpath = file_get_contents($fullpath);
            }
            if ((new ExtractorFactory)->readerPart($fullpath, ContentTypesEnum::CONTENTTYPE_PRIVATE_KEY_ENCRYPTED) && empty($passphrase)) {
                throw new ForbiddenException("You need the password to uncrypt this private key");
            }
        }
        $this->setPassword($passphrase);
        $data = openssl_pkey_get_private($fullpath, $this->password?->getValue());
        if ($data == false) {
            throw new Exception(openssl_error_string());
        }
        $this->data = $data;
    }

    public function getPublicKey(): PublicKeyInterface
    {
        return new PublicKeyContainer($this->getDetail('key'));
    }

    public function getDetails(): array|false
    {
        return $this->details ??= openssl_pkey_get_details($this->data);
    }

    public function export(): string
    {
        $header = ($this->isProtected()) ? ContentTypesEnum::CONTENTTYPE_PRIVATE_KEY_ENCRYPTED : ContentTypesEnum::CONTENTTYPE_PRIVATE_KEY;
        return (new ConverterFactory())->convertFromPemToBinary((string) $this, $header);
    }

    public function __tostring(): string
    {
        openssl_pkey_export($this(), $out, $this->password?->getValue());
        return $out;
    }

    public function __invoke(): OpenSSLAsymmetricKey
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