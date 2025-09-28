<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits;

use SensitiveParameter;
use SensitiveParameterValue;

trait PasswordUnprotectableTrait
{

    protected ?SensitiveParameterValue $password = null;

    public function setPassword(#[SensitiveParameter] ?string $password = null): static
    {
        $this->password = (empty($password)) ? null : new SensitiveParameterValue($password);
        return $this;
    }

    public function isProtected(): bool
    {
        return !empty($this->password?->getValue());
    }
}