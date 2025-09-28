<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Factories\ConverterFactory;
use JuanchoSL\Certificates\Factories\ExtractorFactory;
use JuanchoSL\Certificates\Interfaces\CertificateReadableInterface;
use JuanchoSL\Certificates\Interfaces\ChainReadableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Traits\Bundles\CertificateTrait;
use JuanchoSL\Certificates\Traits\Bundles\ChainTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Certificates\Traits\StringableTrait;
use Stringable;

class Pkcs7Container implements
    ExportableInterface,
    Stringable,
    SaveableInterface,
    CertificateReadableInterface,
    ChainReadableInterface,
    FormateableInterface
{
    use StringableTrait, SaveableTrait, ChainTrait, CertificateTrait;

    private $pkcs7 = null;

    public function __construct(string $cert_content)
    {
        if (is_file($cert_content) && file_exists($cert_content)) {
            $cert_content = file_get_contents($cert_content);
        }
        if (str_contains($cert_content, chr(0)) === false) {
            if (str_starts_with($cert_content, '-----')) {
                $cert_content = (new ConverterFactory())->convertFromPemToBinary($cert_content, ContentTypesEnum::CONTENTTYPE_PKCS7);
            }
        }
        $cert_content = (new ConverterFactory())->convertFromBinaryToDer($cert_content, ContentTypesEnum::CONTENTTYPE_PKCS7);
        $this->pkcs7 = $cert_content;
        openssl_pkcs7_read($cert_content, $data);
        $certs = $this->certsShorting($data, true);
        $cert = array_shift($certs);
        $this->cert = new CertificateContainer($cert);
        $this->chain = new ChainContainer($certs);
    }

    public function export(): string
    {
        return base64_decode((new ExtractorFactory())->extractParts($this->pkcs7, ContentTypesEnum::CONTENTTYPE_PKCS7));
    }

    public function __tostring(): string
    {
        return $this->pkcs7;//(new ConverterFactory())->convertFromBinaryToDer($this->export(), ContentTypesEnum::CONTENTTYPE_PKCS7);
    }

    public function getExtension(): string
    {
        return 'p7b';
    }

    public function getMediaType(): string
    {
        return 'application/x-pkcs7-certificates';
    }
}