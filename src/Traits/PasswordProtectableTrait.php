<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits;

use Exception;
use SensitiveParameter;
use SensitiveParameterValue;

trait PasswordProtectableTrait
{

    protected ?SensitiveParameterValue $password = null;

    public function setPassword(#[SensitiveParameter] string $password): static
    {
        if (empty($password)) {
            throw new Exception("The password can not be empty");
        }
        $this->password = new SensitiveParameterValue($password);
        return $this;
    }
}