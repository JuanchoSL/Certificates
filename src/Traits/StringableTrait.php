<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits;

trait StringableTrait
{

    public function __tostring(): string
    {
        return $this->export();
    }
}