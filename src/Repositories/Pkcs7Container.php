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
        $this->chain = $certs;
/*
        $extras = [];
        $last = '';

        if (count($data) > 1) {
            do {
                foreach ($data as $key => $crt) {
                    $x509 = openssl_x509_read($crt);
                    $details = openssl_x509_parse($x509);
                    $compare = (empty($last)) ? $details['subject']['CN'] : $last;
                    if ($details['issuer']['CN'] == $compare) {
                        $extras[] = $crt;
                        $last = $details['subject']['CN'];
                        unset($data[$key]);
                        continue;
                    }
                }
            } while (!empty($data));
            $cert = array_slice($extras, -1);
            $extras = array_slice($extras, 0, -1);
        } else {
            $cert = $data;
        }
        $this->cert = new CertificateContainer(current($cert));
        $this->extras = new ChainContainer($extras);
*/
    }

/*
    public function getCertificate(): CertificateContainer
    {
        return $this->cert;
    }

    public function getChain(): ChainContainer
    {
        return $this->extras;
    }
*/
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