<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\ChainContainer;
use JuanchoSL\Certificates\Repositories\LockedContainer;
use JuanchoSL\Certificates\Repositories\PEMContainer;
use JuanchoSL\Certificates\Repositories\Pkcs12Container;
use JuanchoSL\Certificates\Repositories\Pkcs7Container;
use JuanchoSL\Certificates\Repositories\Pkcs8Container;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use JuanchoSL\Certificates\Repositories\PublicKeyContainer;
use JuanchoSL\Certificates\Repositories\PublicSshKeyContainer;
use JuanchoSL\Certificates\Repositories\SigningRequestContainer;
use JuanchoSL\Exceptions\NotFoundException;
use JuanchoSL\Exceptions\UnsupportedMediaTypeException;
use JuanchoSL\HttpData\Containers\Stream;
use JuanchoSL\HttpData\Containers\UploadedFile;
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
            }
            return $this->createFromContents($origin);
        } elseif (is_object($origin)) {
            return $this->createFromEntity($origin);
        }
    }
    public function createFromFile(string $origin)
    {
        if (!is_file($origin) || !file_exists($origin)) {
            throw new NotFoundException("The file {$origin} does not exists or it is not readable");
        }
        $contents = file_get_contents($origin);
        if (str_contains($contents, chr(0)) !== false) {
            $finfo = finfo_open(FILEINFO_MIME);
            $mimetype = finfo_file($finfo, $origin);
            finfo_close($finfo);
            return $this->createFromMimetype($origin, $mimetype);
        }
        return $this->createFromContents($contents);
    }
    public function createFromContents(string $origin)
    {
        if (str_contains($origin, chr(0)) !== false) {
            return $this->createFromBinary($origin);
        }
        return $this->createFromString($origin);
    }
    protected function createFromString(string $origin)
    {
        $extractor = new ExtractorFactory();
        if ($extractor->readerPart($origin, ContentTypesEnum::CONTENTTYPE_PKCS7)) {
            return new Pkcs7Container($origin);
        }
        if ($extractor->readerPart($origin, ContentTypesEnum::CONTENTTYPE_PKCS8)) {
            return new Pkcs8Container($origin);
        }
        if ($extractor->readerPart($origin, ContentTypesEnum::CONTENTTYPE_PKCS12)) {
            return new LockedContainer($origin, Pkcs12Container::class);
        }
        if ($extractor->readerPart($origin, ContentTypesEnum::CONTENTTYPE_PUBLIC_KEY)) {
            return new PublicKeyContainer($origin);
        }
        if ($extractor->readerPart($origin, ContentTypesEnum::CONTENTTYPE_CERTIFICATE_REQUEST)) {
            return new SigningRequestContainer($origin);
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
        if ($private or $certificate) {
            if (!$certificate) {
                if ($extractor->readerPart($origin, ContentTypesEnum::CONTENTTYPE_PRIVATE_KEY_ENCRYPTED)) {
                    return new LockedContainer($origin, PrivateKeyContainer::class);
                }
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
    public function createFromMimetype($origin, $mimetype)
    {
        list($mimetype, $charset) = explode(";", $mimetype);
        switch (trim($mimetype)) {
            case 'application/x-x509-ca-certificates':
            case 'application/x-x509-user-certificates':
            case 'application/x-x509-ca-cert':
            case 'application/x-x509-user-cert':
                return $this->createFromString((string) $origin);

            case 'application/x-pkcs7-certificates':
                return new Pkcs7Container($origin);

            case 'application/pkcs8':
                return new Pkcs8Container($origin);

            case 'application/x-pkcs12':
            case 'application/octet-stream':
                return new LockedContainer($origin, Pkcs12Container::class);
        }
        throw new UnsupportedMediaTypeException("The file {$origin} with mimetype {$mimetype} does not have available container");
    }

    public function createFromEntity($origin)
    {
        $type = get_class($origin);

        switch ($type) {
            case OpenSSLCertificate::class:
                return new CertificateContainer($origin);

            case OpenSSLAsymmetricKey::class:
                return new PrivateKeyContainer($origin);

            case Stream::class:
            case UploadedFile::class:
                $knowed = [
                    "application/pkcs8" => 'p8',
                    "application/pkcs10" => 'p10',
                    "application/pkix-cert" => 'cer',
                    "application/pkix-crl" => 'crl',
                    "application/pkcs7-mime" => 'p7c',
                    "application/x-x509-ca-cert" => 'crt',
                    "application/x-x509-user-cert" => 'crt',
                    "application/x-pkcs7-crl" => 'crl',
                    "application/x-pem-file" => 'pem',
                    "application/x-pkcs12" => 'p12',
                    "application/x-pkcs7-certificates" => 'p7b',
                    "application/x-pkcs7-certreqresp" => 'p7r'
                ];
                try {
                    if (
                        in_array($origin->getClientMediaType(), array_keys($knowed))
                    ) {
                        return $this->createFromMimetype((string) $origin->getStream(), $origin->getClientMediaType());
                    } elseif (in_array($ext = pathinfo($origin->getClientFilename(), PATHINFO_EXTENSION), array_values($knowed))) {
                        $mime = array_search($ext, $knowed);
                        return $this->createFromMimetype((string) $origin->getStream(), $mime);
                    }
                    return $this->createFromFile($origin->getStream()->getMetadata('uri'));
                } catch (\Exception $e) {
                    return $this->createFromContents((string) $origin->getStream());
                }
        }
    }

    public function createFromBinary($origin)
    {
        return new LockedContainer($origin, Pkcs12Container::class);
    }

}
