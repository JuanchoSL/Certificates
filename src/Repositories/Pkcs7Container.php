<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

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

    protected $pkcs7 = null;

    public function __construct(string $cert_content)
    {
        if (is_file($cert_content) && file_exists($cert_content)) {
            $cert_content = file_get_contents($cert_content);
        }
        if (!str_starts_with($cert_content, '-----')) {
            $cert_content = implode("\n", ['-----BEGIN PKCS7-----', base64_encode($cert_content), '-----END PKCS7-----']);
        }
        $this->pkcs7 = $cert_content;
        openssl_pkcs7_read($cert_content, $data);
        $certs = $this->certsShorting($data);
        $this->cert = array_pop($certs);
        $this->cert = new CertificateContainer($this->cert);
        $this->chain = new ChainContainer($certs);
    }

    public function export(): string
    {
        return $this->pkcs7;
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