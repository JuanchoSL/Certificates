<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use JuanchoSL\Certificates\Factories\DnsDkimFactory;
use JuanchoSL\Certificates\Factories\PublicSshFactory;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Interfaces\StandarizableInterface;
use JuanchoSL\Certificates\Traits\DetailableTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Certificates\Traits\StringableTrait;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use Stringable;

class PublicKeyContainer implements
    DetailableInterface,
    ExportableInterface,
    Stringable,
    SaveableInterface,
    StandarizableInterface,
    FormateableInterface
{

    use DetailableTrait, StringableTrait, SaveableTrait;

    protected $data = null;

    public function __construct(#[\SensitiveParameter] OpenSSLAsymmetricKey|OpenSSLCertificate|string $cert_content)
    {
        if (is_string($cert_content) && is_file($cert_content) && file_exists($cert_content)) {
            $cert_content = file_get_contents($cert_content);
        }
        $this->data = openssl_pkey_get_public($cert_content);
    }

    public function getDetails(): array|false
    {
        return $this->details ??= openssl_pkey_get_details($this->data);
    }

    public function export(): string
    {
        return $this->getDetail('key');
    }

    public function __invoke(): mixed
    {
        return $this->data;
    }

    public function getDkim(?string $selector = NULL)
    {
        return (new DnsDkimFactory())->createFromPublicKeyContainer($this, $selector);
    }

    public function getOpenSSH(?string $comment = null)
    {
        return (new PublicSshFactory)->createFromPublicKeyContainer($this, $comment);
    }

    public function getExtension(): string
    {
        return 'pub';
    }

    public function getMediaType(): string
    {
        return 'text/plain';
    }
}