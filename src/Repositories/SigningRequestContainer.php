<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use JuanchoSL\Certificates\Interfaces\Complex\PublicKeyInterface;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Traits\DetailableTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Certificates\Traits\StringableTrait;
use OpenSSLCertificateSigningRequest;
use Stringable;

class SigningRequestContainer implements Stringable, ExportableInterface, SaveableInterface, DetailableInterface, PublicKeyReadableInterface, FormateableInterface
{

    use StringableTrait, SaveableTrait, DetailableTrait;

    protected $data = null;

    public function __construct(OpenSSLCertificateSigningRequest|string $fullpath)
    {
        if (is_string($fullpath) && is_file($fullpath) && file_exists($fullpath) && !str_starts_with($fullpath, 'file://')) {
            $fullpath = 'file://' . $fullpath;
        }
        openssl_csr_export($fullpath, $data, false);
        $this->data = $data;
    }

    public function getPublicKey(): PublicKeyInterface
    {
        return new PublicKeyContainer(openssl_csr_get_public_key($this->data));
    }

    public function getDetails(): array|false
    {
        if (is_null($this->details)) {
            $this->details['subject'] = openssl_csr_get_subject($this->data, false);
            $this->details['extensions'] = [];
            preg_match_all("/\s+Requested Extensions:\s+[\.\S\s]+\s+X509v3 (Basic Constraints:\s+[\.\S\s]+[\r|\n]+\s+)X509v3 (Key Usage:\s+[\.\S\s]+[\r\n]+\s+)X509v3 (Subject Alternative Name:\s+[\.\S\s]+[\r|\n]+)\s+(Signature Algorithm:\s+[\s\S\.]+)[\r|\n]+\s+Signature Value:/m", $this->data, $matches);
            if (!empty(current($matches) && count($matches) > 1)) {
                for ($i = 1; $i < count($matches); $i++) {
                    $val = current($matches[$i]);
                    $val = preg_replace('/[\r|\n]+/m', ' ', $val);
                    $val = preg_replace('/\s+/', ' ', $val);
                    foreach (['signatureTypeLN' => 'Signature Algorithm'] as $key => $value) {
                        if (str_contains($val, $value)) {
                            $this->details[$key] = trim(str_replace($value . ":", '', $val));
                        }
                    }
                    foreach (['basicConstraints' => 'Basic Constraints', 'keyUsage' => 'Key Usage', 'extendedKeyUsage' => 'Extended Key Usage', 'subjectAltName' => 'Subject Alternative Name'] as $key => $value) {
                        if (str_contains($val, $value)) {
                            $this->details['extensions'][$key] = trim(str_replace($value . ":", '', $val));
                        }
                    }
                }
            }
            if (isset($this->details['signatureTypeLN'])) {
                $type = $this->getPublicKey()->getDetail('type');
                switch ($type) {
                    case OPENSSL_KEYTYPE_RSA:
                        $type = 'RSA';
                        break;
                    case OPENSSL_KEYTYPE_DSA:
                        $type = 'DSA';
                        break;
                }
                preg_match("/([a-z]+\d*)\w*{$type}\w/", $this->details['signatureTypeLN'], $matches);
                if (!empty($matches[1])) {
                    $this->details['signatureTypeSN'] = strtoupper($type . "-" . $matches[1]);
                }
            }
        }
        return $this->details;
    }

    public function export(): mixed
    {
        return $this->data;
    }

    public function getExtension(): string
    {
        return 'p10';//csr
    }

    public function getMediaType(): string
    {
        return 'application/pkcs10';
    }
}