<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Factories\ExtractorFactory;
use JuanchoSL\Certificates\Interfaces\Complex\ChainInterface;
use JuanchoSL\Certificates\Traits\IterableTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;

class ChainContainer implements ChainInterface
{

    use SaveableTrait, IterableTrait;

    public function __construct(array|string $fullpath)
    {
        if (is_string($fullpath)) {
            if (is_file($fullpath) && file_exists($fullpath)) {
                $fullpath = file_get_contents($fullpath);
            }
            $extractor = new ExtractorFactory();
            $fullpath = $extractor->extractParts($fullpath, ContentTypesEnum::CONTENTTYPE_CERTIFICATE);
        }
        if (is_iterable($fullpath)) {
            foreach ($fullpath as $extracert) {
                $this->iterable[] = new CertificateContainer($extracert);
            }
        }
        $this->rewind();
    }

    public function __invoke(): array
    {
        $data = [];
        foreach ($this->iterable as $cert) {
            $data[] = $cert();
        }
        return $data;
    }

    public function export(): array
    {
        $data = [];
        foreach ($this->iterable as $cert) {
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