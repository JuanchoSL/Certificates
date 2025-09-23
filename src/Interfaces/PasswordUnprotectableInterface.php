<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

interface PasswordUnprotectableInterface
{

    /**
     * Set the password for the element in order to change before export or save
     * @param string $password The password, leave blank in order to remove it from container
     * @return static The element
     */
    public function setPassword(#[\SensitiveParameter] ?string $password = ''): static;
}