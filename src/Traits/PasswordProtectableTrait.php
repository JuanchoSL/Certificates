<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits;

use Exception;

trait PasswordProtectableTrait
{

    protected ?string $password = null;

    public function setPassword(#[\SensitiveParameter] string $password): static
    {
        if (empty($password)) {
            throw new Exception("The password can not be empty");
        }
        $this->password = $password;
        return $this;
    }
}