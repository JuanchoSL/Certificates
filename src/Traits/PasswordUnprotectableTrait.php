<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits;

trait PasswordUnprotectableTrait
{

    protected ?string $password = null;

    public function setPassword(#[\SensitiveParameter] ?string $password = null): static
    {
        $this->password = empty($password) ? null : $password;
        return $this;
    }
}