<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use Exception;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FingerprintReadableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Traits\DetailableTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Certificates\Traits\StringableTrait;
use Stringable;

class PublicSshKeyContainer implements ExportableInterface, SaveableInterface, Stringable, DetailableInterface, FormateableInterface, FingerprintReadableInterface
{

    use StringableTrait, SaveableTrait, DetailableTrait;

    protected $data = null;

    public function __construct(string $fullpath)
    {
        if (is_file($fullpath) && file_exists($fullpath)) {
            $fullpath = file_get_contents($fullpath);
        }
        $this->data = $fullpath;
        $this->details = $this->getDetails();
    }

    public function getDetails(): array|false
    {
        list($type, $key, $comment) = explode(" ", $this->data, 3);
        return compact(['type', 'key', 'comment']);
    }

    public function export(): string
    {
        return $this->data;
    }

    public function getFingerprint(string $algo, bool $hex): bool|string
    {
        $alloweds = openssl_get_md_methods();
        if (!in_array($algo, $alloweds)) {
            throw new Exception("The {$algo} hashing algorithm is not a valid value");
        }
        preg_match('~ssh-(\w+)\s([\w=/+]+)\s*~m', $this->data, $matches);
        $key = base64_decode($matches[2]);
        if (($fingerprint = openssl_digest($key, $algo, !$hex)) !== false && !$hex) {
            $fingerprint = base64_encode($fingerprint);
        }
        return $fingerprint ?? false;
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