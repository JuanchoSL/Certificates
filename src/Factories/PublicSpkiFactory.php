<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Interfaces\Complex\PrivateKeyInterface;
use JuanchoSL\Certificates\Interfaces\PrivateKeyReadableInterface;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use JuanchoSL\Certificates\Repositories\PublicSpkiKeyContainer;

class PublicSpkiFactory
{

    public function createFromPrivateKeyString(string $privateKey, string $challenge, ?string $password = null): PublicSpkiKeyContainer
    {
        return $this->createFromPrivateKeyContainer(new PrivateKeyContainer($privateKey, $password), $challenge);
    }

    public function createFromPrivateKeyContainer(PrivateKeyInterface $privateKey, string $challenge): PublicSpkiKeyContainer
    {

        return $privateKey->getSpkiKey($challenge);
    }

    public function createFromPrivateKeyReadable(PrivateKeyReadableInterface $private_key_parent, string $challenge, ?string $password = null): PublicSpkiKeyContainer
    {
        return $this->createFromPrivateKeyContainer($private_key_parent->getPrivateKey($password), $challenge);
    }

    public function createFromFile(string $file, string $challenge, ?string $password = null): PublicSpkiKeyContainer
    {
        $factory = new ContainerFactory;
        if (is_file($file) && file_exists($file)) {
            $container = $factory->createFromFile($file);
        }

        if ($container instanceof PrivateKeyReadableInterface) {
            return $this->createFromPrivateKeyReadable($container, $challenge, $password);
        } elseif ($container instanceof LockedContainer) {
            return $this->createFromPrivateKeyContainer($container($password), $challenge);
        } elseif ($container instanceof PrivateKeyContainer) {
            return $this->createFromPrivateKeyContainer($container, $challenge);
        } else
            return $this->createFromPrivateKeyString(file_get_contents($file), $challenge, $password);
    }

}