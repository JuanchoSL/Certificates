<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Traits\DetailableTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Certificates\Traits\StringableTrait;
use Stringable;

class PublicSpkiKeyContainer implements PublicKeyReadableInterface, DetailableInterface, Stringable, ExportableInterface
{

    use DetailableTrait, StringableTrait, SaveableTrait;

    protected $key = 'SPKAC=';
    protected $data = null;

    public function __construct(string $cert_content)
    {
        if (is_string($cert_content) && is_file($cert_content) && file_exists($cert_content)) {
            $cert_content = file_get_contents($cert_content);
            if (str_contains($cert_content, chr(0))) {
                base64_encode($cert_content);
            }
        }
        if (!str_starts_with($cert_content, $this->key)) {
            $cert_content = $this->key . $cert_content;
        }
        $this->data = $cert_content;
    }


    public function getPublicKey(): PublicKeyContainer
    {
        return (new PublicKeyContainer($this->getDetail('key')));
    }

    public function getDetails(): array|false
    {
        $data = preg_replace("/{$this->key}/", '', $this->data);
        return [
            'challenge' => openssl_spki_export_challenge($data),
            'key' => openssl_spki_export($data)
        ];
    }

    public function verify(): bool
    {
        return openssl_spki_verify($this->data);
    }

    public function check(string $challenge): bool
    {
        return $challenge === openssl_spki_export_challenge($this->data);
    }

    public function export(): string
    {
        return base64_decode(preg_replace("/{$this->key}/", '', $this->data));
        return $this->data;
    }

    public function __tostring(): string
    {
        return $this->data;
    }

    public function __invoke(): mixed
    {
        return $this->data;
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