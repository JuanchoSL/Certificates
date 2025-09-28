<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use JuanchoSL\Certificates\Interfaces\PasswordProtectableInterface;
use JuanchoSL\Certificates\Interfaces\PasswordUnprotectableInterface;
use JuanchoSL\Exceptions\ForbiddenException;

class LockedContainer
{

    protected $origin;
    protected $destiny;

    public function __construct(string $origin, $destiny)
    {
        $this->origin = $origin;
        $this->destiny = $destiny;
    }

    public function __invoke(#[\SensitiveParameter] string $password): PasswordProtectableInterface|PasswordUnprotectableInterface
    {
        return new $this->destiny($this->origin, $password);
    }

    public function __call($method, $args)
    {
        throw new ForbiddenException("This is a protected package, needs to invoke with the right password to unlock it.");
    }
}