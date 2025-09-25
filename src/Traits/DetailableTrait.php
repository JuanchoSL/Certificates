<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits;

trait DetailableTrait
{

    protected ?array $details = null;

    public function getDetail(string $index): mixed
    {
        if (is_null($this->details)) {
            $this->details = $this->getDetails();
        }
        return (array_key_exists($index, $this->details)) ? $this->details[$index] : null;
    }
}