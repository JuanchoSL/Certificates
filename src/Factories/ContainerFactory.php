<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\ChainContainer;
use JuanchoSL\Certificates\Repositories\PEMContainer;
use JuanchoSL\Certificates\Repositories\Pkcs12Container;
use JuanchoSL\Certificates\Repositories\Pkcs7Container;
use JuanchoSL\Certificates\Repositories\Pkcs8Container;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use JuanchoSL\Certificates\Repositories\PublicKeyContainer;
use JuanchoSL\Certificates\Repositories\PublicSshKeyContainer;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use Psr\Http\Message\StreamInterface;

class ContainerFactory
{

    public function createFromUnknow(mixed $origin)
    {
        if (is_string($origin)) {
            if (is_file($origin) && file_exists($origin)) {
                return $this->createFromFile($origin);
            } elseif (str_contains($origin, '----BEGIN')) {
                return $this->createFromString($origin);
            } else {
                return $this->createFromBinary($origin);
            }
        } elseif (is_object($origin)) {
            return $this->createFromEntity($origin);
        }
    }
    public function createFromFile(string $origin)
    {
        $finfo = finfo_open(FILEINFO_MIME);
        $mimetype = finfo_file($finfo, $origin);
        finfo_close($finfo);
        if (str_contains(strtolower($mimetype), 'charset=binary')) {
            return $this->createFromBinary($origin);
            //}elseif(str_contains(strtolower($mimetype), 'application/x-pkcs12')){
            //return new Pkcs12Container($origin);
        } elseif (str_contains(strtolower($mimetype), 'application/x-pkcs7')) {
            return new Pkcs7Container($origin);
        } elseif (str_contains(strtolower($mimetype), 'application/pkcs8')) {
            return new Pkcs8Container($origin);
        }
        $origin = file_get_contents($origin);
        if (substr($origin, 3, 1) == '-') {
            return $this->createFromString($origin);
        }
    }
    public function createFromString(string $origin)
    {
        $extractor = new ExtractorFactory();
        if ($extractor->readerPart($origin, ContentTypesEnum::CONTENTTYPE_PKCS7)) {
            return new Pkcs7Container($origin);
        }
        if ($extractor->readerPart($origin, ContentTypesEnum::CONTENTTYPE_PKCS8)) {
            return new Pkcs8Container($origin);
        }
        $private = $certificate = $chain = $public = false;
        if ($extractor->readerPart($origin, ContentTypesEnum::CONTENTTYPE_PRIVATE_KEY) or $extractor->readerPart($origin, ContentTypesEnum::CONTENTTYPE_PRIVATE_KEY_ENCRYPTED)) {
            $private = true;
        }
        if ($extractor->readerPart($origin, ContentTypesEnum::CONTENTTYPE_CERTIFICATE)) {
            $certificate = true;
            if (count($extractor->extractParts($origin, ContentTypesEnum::CONTENTTYPE_CERTIFICATE)) > 1) {
                $chain = true;
            }
        }
        if ($extractor->readerPart($origin, ContentTypesEnum::CONTENTTYPE_PUBLIC_KEY)) {
            $public = true;
        }
        if ($private or $certificate) {
            if (!$certificate) {
                return new PrivateKeyContainer($origin);
            } elseif (!$private) {
                if (!$chain) {
                    return new CertificateContainer($origin);
                } else {
                    return new ChainContainer($origin);
                }
            } else {
                return new PEMContainer($origin);
            }
        } elseif ($public) {
            return new PublicKeyContainer($origin);
        } elseif (str_starts_with($origin, 'ssh-')) {
            return new PublicSshKeyContainer($origin);
        }

    }
    public function createFromEntity($origin)
    {
        $type = get_class($origin);

        switch ($type) {
            case OpenSSLCertificate::class:
                return new CertificateContainer($origin);

            case OpenSSLAsymmetricKey::class:
                return new PrivateKeyContainer($origin);

            case StreamInterface::class:
                return $this->createFromString((string) $origin->getStream());
        }
    }
    public function createFromBinary($origin)
    {
        //return new Pkcs12Container($origin);
        //echo base64_encode($origin);
        $finfo = finfo_open(FILEINFO_MIME);
        $mimetype = finfo_file($finfo, $origin);
        finfo_close($finfo);
        return $mimetype;
    }

}
