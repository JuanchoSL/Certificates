<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use JuanchoSL\Certificates\Factories\Pkcs8Filler;
use JuanchoSL\Certificates\Interfaces\CertificateReadableInterface;
use JuanchoSL\Certificates\Interfaces\ChainReadableInterface;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\PasswordProtectableInterface;
use JuanchoSL\Certificates\Interfaces\PrivateKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Traits\DetailableTrait;
use JuanchoSL\Certificates\Traits\PasswordProtectableTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Exceptions\UnauthorizedException;

class Pkcs12Container extends Pkcs8Container implements
    PasswordProtectableInterface,
    ExportableInterface,
    SaveableInterface,
    DetailableInterface,
    PrivateKeyReadableInterface,
    CertificateReadableInterface,
    ChainReadableInterface,
    FormateableInterface
{

    use DetailableTrait, PasswordProtectableTrait, SaveableTrait;

    protected $data = null;
    protected $extras = null;

    public function __construct(string $cert_content, #[\SensitiveParameter] string $password)
    {
        if (is_file($cert_content) && file_exists($cert_content)) {
            $cert_content = file_get_contents($cert_content);
        }
        $this->data = $cert_content;
        $this->setPassword($password);
        if (!openssl_pkcs12_read($this->data, $output, $password)) {
            throw new UnauthorizedException("The password is not valid in order to open the container");
        }
        $this->details = $output;
        $this->key = $this->getDetail('pkey');
        $this->cert = new CertificateContainer($this->getDetail('cert'));
        $this->chain = new ChainContainer($this->getDetail('extracerts') ?? []);
    }

    public function getPrivateBundle(#[\SensitiveParameter] ?string $passphrase = null): Pkcs8Container
    {
        return (new Pkcs8Filler($this->getPrivateKey($passphrase)))->setCertificate($this->getCertificate())->setChain($this->getChain());
    }

    public function export(): string
    {
        return $this->data;
    }

    public function getDetails(): array
    {
        return $this->details;
    }

    public function getExtension(): string
    {
        return 'p12';
    }

    public function getMediaType(): string
    {
        return 'application/x-pkcs12';
    }
}