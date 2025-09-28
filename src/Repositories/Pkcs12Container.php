<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Factories\ConverterFactory;
use JuanchoSL\Certificates\Factories\PemFiller;
use JuanchoSL\Certificates\Interfaces\CertificateReadableInterface;
use JuanchoSL\Certificates\Interfaces\ChainReadableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\PasswordProtectableInterface;
use JuanchoSL\Certificates\Interfaces\PrivateBundleReadableInterface;
use JuanchoSL\Certificates\Interfaces\PrivateKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Traits\Bundles\CertificateTrait;
use JuanchoSL\Certificates\Traits\Bundles\ChainTrait;
use JuanchoSL\Certificates\Traits\Bundles\PrivateKeyTrait;
use JuanchoSL\Certificates\Traits\DetailableTrait;
use JuanchoSL\Certificates\Traits\PasswordProtectableTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Exceptions\UnauthorizedException;

class Pkcs12Container implements
    //PrivateBundleReadableInterface,
    PasswordProtectableInterface,
    ExportableInterface,
    SaveableInterface,
    //DetailableInterface,
    PrivateKeyReadableInterface,
    CertificateReadableInterface,
    ChainReadableInterface,
    FormateableInterface
{

    use PrivateKeyTrait, CertificateTrait, ChainTrait, PasswordProtectableTrait, SaveableTrait;

    private $pkcs12 = null;
    protected $extras = null;

    public function __construct(string $cert_content, #[\SensitiveParameter] string $password)
    {
        
        if (is_file($cert_content) && file_exists($cert_content)) {
            $cert_content = file_get_contents($cert_content);
        }
        if (str_contains($cert_content, chr(0)) === false) {
            if (str_starts_with($cert_content, '-----')) {
                $cert_content = (new ConverterFactory())->convertFromPemToBinary($cert_content, ContentTypesEnum::CONTENTTYPE_PKCS12);
            }
        }
        $this->pkcs12 = $cert_content;
        $this->setPassword($password);
        if (!openssl_pkcs12_read($this->pkcs12, $output, $this->password->getValue())) {
            throw new UnauthorizedException("The password is not valid in order to open the container");
        }
        //echo "<pre>".print_r($output, true);exit;
        //$this->details = $output;
        $this->key = $output['pkey'];//$this->getDetail('pkey');
        $this->cert = new CertificateContainer($output['cert']);
        $this->chain = new ChainContainer($output['extracerts'] ?? []);
    }
    /*
        public function getPrivateBundle(#[\SensitiveParameter] ?string $passphrase = null): Pkcs8Container
        {
            return (new Pkcs8Filler($this->getPrivateKey($passphrase)))->setCertificate($this->getCertificate())->setChain($this->getChain());
        }
        public function getPrivatePem(#[\SensitiveParameter] ?string $passphrase = null): PemContainer
        {
            return (new PemFiller($this->getPrivateKey($passphrase)))->setCertificate($this->getCertificate())->setChain($this->getChain());
        }
    */
    public function export(): string
    {
        return $this->pkcs12;
    }

    public function __tostring(): string
    {
        return (new ConverterFactory())->convertFromBinaryToPem($this->export(), ContentTypesEnum::CONTENTTYPE_PKCS12);
    }
    /*
        public function getDetails(): array
        {
            return $this->details;
        }
    */
    public function getExtension(): string
    {
        return 'p12';
    }

    public function getMediaType(): string
    {
        return 'application/x-pkcs12';
    }
}