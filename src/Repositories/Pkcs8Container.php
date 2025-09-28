<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Factories\ConverterFactory;
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

class Pkcs8Container implements
    ExportableInterface,
    SaveableInterface,
    PrivateKeyReadableInterface,
    CertificateReadableInterface,
    ChainReadableInterface,
    FormateableInterface
{

    use PrivateKeyTrait, CertificateTrait, ChainTrait, SaveableTrait;

    protected $pkcs8 = null;

    public function __construct(string $cert_content)
    {
        if (is_file($cert_content) && file_exists($cert_content)) {
            $cert_content = file_get_contents($cert_content);
        }
        if (str_contains($cert_content, chr(0)) === false) {
            if (str_starts_with($cert_content, '-----')) {
                if (str_contains($cert_content, 'PKCS8')) {
                    $type = ContentTypesEnum::CONTENTTYPE_PKCS8;
                } else {
                    $type = ContentTypesEnum::CONTENTTYPE_CMS;
                    $cert_content = (new ConverterFactory())->convertFromPemToBinary($cert_content, $type);//IMPORTANT have double encoded
                }
                $cert_content = (new ConverterFactory())->convertFromPemToBinary($cert_content, $type);
            }
        }
        $this->pkcs8 = $cert_content;

        $org_file = tempnam(sys_get_temp_dir(), 'cms');
        file_put_contents($org_file, (string) $cert_content);
        $message = tempnam(sys_get_temp_dir(), 'cms');
        $ca = tempnam(sys_get_temp_dir(), 'cms');
        $crt = tempnam(sys_get_temp_dir(), 'cms');
        $pk7 = tempnam(sys_get_temp_dir(), 'cms');
        $sigfile = tempnam(sys_get_temp_dir(), 'cms');
        openssl_cms_verify($org_file, OPENSSL_CMS_NOVERIFY | OPENSSL_CMS_BINARY, $crt, [], null, $message, $pk7, $sigfile, OPENSSL_ENCODING_DER);
        $contents = file_get_contents($message);
        $extractor = new ExtractorFactory();
        if (empty($key = $extractor->extractParts($contents, ContentTypesEnum::CONTENTTYPE_PRIVATE_KEY))) {
            $key = $extractor->extractParts($contents, ContentTypesEnum::CONTENTTYPE_PRIVATE_KEY_ENCRYPTED);
        }
        $this->key = current($key);
        if ($extractor->readerPart($contents, ContentTypesEnum::CONTENTTYPE_CERTIFICATE)) {
            $parts = $extractor->extractParts($contents, ContentTypesEnum::CONTENTTYPE_CERTIFICATE);
            if (count($parts) > 0) {
                $parts = $this->certsShorting($parts, true);
                $this->cert = new CertificateContainer(array_shift($parts));
                if (count($parts) > 0) {
                    $this->chain = new ChainContainer($parts);
                }
            }
        }
        /*
        $this->key = file_get_contents($message);
        //$this->cert = new CertificateContainer(file_get_contents($crt));
        $publics = new Pkcs7Container((new ConverterFactory())->convertFromPemToBinary(file_get_contents($pk7), ContentTypesEnum::CONTENTTYPE_CMS));
        $this->cert = $publics->getCertificate();
        $this->chain = $publics->getChain();
        */
        unset($org_file);
        unset($message);
        unset($ca);
        unset($crt);
        unset($pk7);
        unset($sigfile);
    }
    /*
        public function getPublicBundle(#[\SensitiveParameter] ?string $passphrase = null): Pkcs7Container
        {
            //@TODO Needs the password? can use the priv key from object or throw exception if it is empty
            return (new Pkcs7Filler($this->getPrivateKey($passphrase)))->setCertificate($this->getCertificate())->setChain($this->getChain());
        }
    */
    public function export(): string
    {
        return $this->pkcs8;
    }

    public function __tostring(): string
    {
        return (new ConverterFactory())->convertFromBinaryToDer($this->export(), ContentTypesEnum::CONTENTTYPE_PKCS8);
    }

    public function getExtension(): string
    {
        return 'p8';
    }

    public function getMediaType(): string
    {
        return 'application/pkcs8';
    }
}