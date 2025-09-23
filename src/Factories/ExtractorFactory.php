<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Enums\ContentTypesEnum;

class ExtractorFactory
{

    public function readerPart(string $data, ContentTypesEnum $type)
    {
        return str_contains($data, '---BEGIN ' . $type->value . '---') && str_contains($data, '---END ' . $type->value . '---');
    }
    public function extractParts(string $data, ContentTypesEnum $type)
    {
        $type = $type->value;
        preg_match_all("~-----BEGIN {$type}-----([\r|\n]+)([\w\s=/+]+)([\r|\n]+)-----END {$type}-----~m", $data, $matches);
        return (!empty($matches[0])) ? $matches[0] : [];
    }
}
