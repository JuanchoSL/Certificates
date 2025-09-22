<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Enums\ContentTypesEnum;

class ConverterFactory
{

    public function convertFromBinaryToDer(string $data, ContentTypesEnum $type)
    {
        $type = $type->value;
        $data = base64_encode($data);
        return implode("\n", ["-----BEGIN {$type}-----", trim($data, "\r\n"), "-----END {$type}-----"]);
    }
    public function convertFromBinaryToPem(string $data, ContentTypesEnum $type)
    {
        $type = $type->value;
        $data = chunk_split(base64_encode($data), 65);
        return implode("\n", ["-----BEGIN {$type}-----", trim($data, "\r\n"), "-----END {$type}-----"]);
    }

    public function convertFromPemToBinary(string $data, ContentTypesEnum $type)
    {
        $type = $type->value;
        preg_match("~-----BEGIN {$type}-----([\r|\n]+)([\w\s=/+]+)([\r|\n]+)-----END {$type}-----~m", $data, $matches);
        return (!empty($matches[2])) ? base64_decode($matches[2]) : null;
    }
}
