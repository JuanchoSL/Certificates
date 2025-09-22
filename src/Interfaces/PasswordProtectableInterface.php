<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

interface PasswordProtectableInterface
{

    /**
     * Set the password for the element in order to change before export or save
     * @param string $password The password
     * @return static The element
     */
    public function setPassword(string $password): static;
}