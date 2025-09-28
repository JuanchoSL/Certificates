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
        openssl_csr_export($fullpath, $data);
        $this->data = $data;
    }

    public function getPublicKey(): PublicKeyInterface
    {
        return new PublicKeyContainer(openssl_csr_get_public_key($this->data));
    }

    public function getDetails(): array|false
    {
        return $this->details ??= openssl_csr_get_subject($this->data, false);
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