<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use Exception;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\ChainContainer;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use Stringable;

class Pkcs12Creator implements Stringable, SaveableInterface
{

    use SaveableTrait;

    protected ?PrivateKeyContainer $private = null;
    protected ?CertificateContainer $certificate = null;
    protected ?ChainContainer $extracerts = null;
    protected ?string $password = null;
    protected ?string $friendly_name = null;

    public function __construct(string $friendly_name, string $password)
    {
        $this->friendly_name = $friendly_name;
        $this->password = $password;
    }

    public function setPrivateKey(PrivateKeyContainer $private): static
    {
        $this->private = $private;
        return $this;
    }

    public function setCertificate(CertificateContainer $certificate): static
    {
        $this->certificate = $certificate;
        return $this;
    }
    public function setChain(ChainContainer $certificates): static
    {
        $this->extracerts = $certificates;
        return $this;
    }

    public function __tostring(): string
    {
        return (string) $this;
    }
    public function export(): mixed
    {
        if (empty($this->password)) {
            throw new Exception("The Password bundle can not be empty");
        }
        $extras = ['friendly_name' => $this->friendly_name];
        if (!empty($this->extracerts)) {
            $extras['extracerts'] = $this->extracerts->export();
        }
        if (empty($this->certificate) or empty($this->private)) {
            throw new Exception("The Private Key and the user Certificate are required");
        }
        if (!openssl_x509_check_private_key($this->certificate->__invoke(), $this->private->__invoke())) {
            throw new Exception("The Certificate is not valid for the Private key");
        }
        openssl_pkcs12_export((string) $this->certificate, $output, (string) $this->private, $this->password, $extras);
        return $output;
    }
}