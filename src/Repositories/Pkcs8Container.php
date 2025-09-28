<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Factories\ConverterFactory;
use JuanchoSL\Certificates\Factories\Pkcs7Filler;
use JuanchoSL\Certificates\Interfaces\CertificateReadableInterface;
use JuanchoSL\Certificates\Interfaces\ChainReadableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\PrivateKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Traits\Bundles\PrivateKeyTrait;

class Pkcs8Container extends Pkcs7Container implements
    ExportableInterface,
    SaveableInterface,
    PrivateKeyReadableInterface,
    CertificateReadableInterface,
    ChainReadableInterface,
    FormateableInterface
{

    use PrivateKeyTrait;
    protected $pkcs8 = null;
    protected $key = null;

    public function __construct(string $cert_content)
    {
        if (is_file($cert_content) && file_exists($cert_content)) {
            $cert_content = file_get_contents($cert_content);
        }
        $this->pkcs8 = $cert_content;
        if (str_starts_with($cert_content, '-----')) {
            if (str_contains($cert_content, 'PKCS8')) {
                $type = ContentTypesEnum::CONTENTTYPE_PKCS8;
            } else {
                $type = ContentTypesEnum::CONTENTTYPE_CMS;
                $cert_content = (new ConverterFactory())->convertFromPemToBinary($cert_content, $type);//IMPORTANT have double encoded
            }
            $cert_content = (new ConverterFactory())->convertFromPemToBinary($cert_content, $type);
        }

        $org_file = tempnam(sys_get_temp_dir(), 'cms');
        file_put_contents($org_file, (string) $cert_content);
        $message = tempnam(sys_get_temp_dir(), 'cms');
        $ca = tempnam(sys_get_temp_dir(), 'cms');
        $crt = tempnam(sys_get_temp_dir(), 'cms');
        $pk7 = tempnam(sys_get_temp_dir(), 'cms');
        $sigfile = tempnam(sys_get_temp_dir(), 'cms');
        openssl_cms_verify($org_file, OPENSSL_CMS_NOVERIFY | OPENSSL_CMS_BINARY, $crt, [], null, $message, $pk7, $sigfile, OPENSSL_ENCODING_DER);
        $this->key = file_get_contents($message);
        //$this->cert = new CertificateContainer(file_get_contents($crt));
        parent::__construct((new ConverterFactory())->convertFromPemToBinary(file_get_contents($pk7), ContentTypesEnum::CONTENTTYPE_CMS));
        unset($org_file);
        unset($message);
        unset($ca);
        unset($crt);
        unset($pk7);
        unset($sigfile);
    }

    public function getPublicBundle(#[\SensitiveParameter] ?string $passphrase = null): Pkcs7Container
    {
        //@TODO Needs the password? can use the priv key from object or throw exception if it is empty
        return (new Pkcs7Filler($this->getPrivateKey($passphrase)))->setCertificate($this->getCertificate())->setChain($this->getChain());
    }

    public function export(): string
    {
        return $this->pkcs8;
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