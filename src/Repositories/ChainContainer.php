<?php //declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use Countable;
use Iterator;
use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Factories\ExtractorFactory;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use Stringable;

class ChainContainer implements
    Stringable,
    Iterator,
    Countable,
    SaveableInterface,
    FormateableInterface
{

    use SaveableTrait;

    protected array|CertificateContainer $chain = [];

    public function __construct(array|string $fullpath)
    {
        if (is_string($fullpath)) {
            if (is_file($fullpath) && file_exists($fullpath)) {
                $fullpath = file_get_contents($fullpath);
            }
            $extractor = new ExtractorFactory();
            $fullpath = $extractor->extractParts($fullpath, ContentTypesEnum::CONTENTTYPE_CERTIFICATE);
            /*
            preg_match_all('~-----BEGIN CERTIFICATE-----([\r|\n]+)([\w\s=/+]+)([\r|\n]+)-----END CERTIFICATE-----~m', $fullpath, $matches);
            if (!empty($matches[0])) {
                $extracerts = [];
                foreach ($matches[0] as $extracert) {
                    $extracerts[] = $extracert;
                }
                $fullpath = $extracerts;
            }
            */
        }
        if (is_iterable($fullpath)) {
            foreach ($fullpath as $extracert) {
                $this->chain[] = new CertificateContainer($extracert);
            }
        }
        $this->rewind();
    }

    function rewind(): void
    {
        reset($this->chain);
    }
    function current(): mixed
    {
        return current($this->chain);
    }
    function key(): int|string|null
    {
        return key($this->chain);
    }
    function next(): void
    {
        next($this->chain);
    }
    function valid(): bool
    {
        return key($this->chain) !== null;
    }

    public function __invoke(): array
    {
        $data = [];
        foreach ($this->chain as $cert) {
            $data[] = $cert();
        }
        return $data;
    }

    public function count(): int
    {
        return count($this->chain);
    }

    public function export(): array
    {
        $data = [];
        foreach ($this->chain as $cert) {
            $data[] = (string) $cert;
        }
        return $data;
    }

    public function __tostring(): string
    {
        return implode(PHP_EOL, $this->export());
    }

    public function getExtension(): string
    {
        return 'crt';
    }

    public function getMediaType(): string
    {
        return 'application/x-x509-ca-cert';
    }
}