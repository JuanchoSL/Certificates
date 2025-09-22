<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits;

trait PasswordProtectableTrait
{

    protected ?string $password = null;

    public function setPassword(?string $password = null): static
    {
        $this->password = empty($password) ? null : $password;
        return $this;
    }
}