<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use Exception;
use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Factories\ExtractorFactory;
use JuanchoSL\Certificates\Interfaces\CertificateReadableInterface;
use JuanchoSL\Certificates\Interfaces\ChainReadableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\PrivateKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Traits\Bundles\CertificateTrait;
use JuanchoSL\Certificates\Traits\Bundles\ChainTrait;
use JuanchoSL\Certificates\Traits\Bundles\PrivateKeyTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use Stringable;

class PEMContainer implements
    ExportableInterface,
    PrivateKeyReadableInterface,
    CertificateReadableInterface,
    ChainReadableInterface,
    FormateableInterface,
    SaveableInterface,
    Stringable
{

    use SaveableTrait, ChainTrait, PrivateKeyTrait, CertificateTrait;


    public function __construct(string $cert_content)
    {
        if (is_file($cert_content) && file_exists($cert_content)) {
            $cert_content = file_get_contents($cert_content);
        }
        $extractor = new ExtractorFactory();

        if ($extractor->readerPart($cert_content, ContentTypesEnum::CONTENTTYPE_PRIVATE_KEY)) {
            $this->key = current($extractor->extractParts($cert_content, ContentTypesEnum::CONTENTTYPE_PRIVATE_KEY));
        } elseif ($extractor->readerPart($cert_content, ContentTypesEnum::CONTENTTYPE_PRIVATE_KEY_ENCRYPTED)) {
            $this->key = current($extractor->extractParts($cert_content, ContentTypesEnum::CONTENTTYPE_PRIVATE_KEY_ENCRYPTED));
        } else {
            throw new Exception("The contents do not have a private key");
        }

        if ($extractor->readerPart($cert_content, ContentTypesEnum::CONTENTTYPE_CERTIFICATE)) {
            $certs = $extractor->extractParts($cert_content, ContentTypesEnum::CONTENTTYPE_CERTIFICATE);
            if (!empty($certs)) {
                $certs = $this->certsShorting($certs, false);
                $this->cert = new CertificateContainer(array_shift($certs));
            }
            $this->chain = new ChainContainer($certs);
        }
    }

    public function export(): iterable
    {
        return [
            (string) $this->getCertificate(),
            (string) $this->getChain(),
            (string) $this->key
        ];
    }
    public function __tostring(): string
    {
        return implode(PHP_EOL, $this->export());
    }

    public function getExtension(): string
    {
        return (empty($this->cert)) ? 'key' : 'pem';
    }

    public function getMediaType(): string
    {
        return (empty($this->cert)) ? 'application/pkcs8' : 'application/x-pem-file';
    }
}