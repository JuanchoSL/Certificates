<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Repositories\DkimContainer;
use JuanchoSL\Certificates\Repositories\PublicKeyContainer;

class DnsDkimFactory
{


    public function createFromPublicKeyString(string $public_key, ?string $selector = null): DkimContainer
    {
        $key_content = explode("\n", trim($public_key));
        $key_content = array_filter($key_content, fn($val) => !preg_match("/^-+/", $val));
        $key_content = str_split(implode("", $key_content), 218);
        $retval = ($selector) ? "{$selector}._domainkey" : "@";
        $retval .= "\tIN\tTXT\t\"v=DKIM1; k=rsa; p=" . implode('" "', array_filter($key_content)) . "\"";
        return new DkimContainer($retval);
    }
    public function createFromPublicKeyContainer(PublicKeyContainer $public_key, ?string $selector = null): DkimContainer
    {
        return $this->createFromPublicKeyString($public_key->getDetail('key'), $selector);
    }
    public function createFromPublicKeyReadable(PublicKeyReadableInterface $public_key_parent, ?string $selector = null): DkimContainer
    {
        return $this->createFromPublicKeyContainer($public_key_parent->getPublicKey(), $selector);
    }
    public function createFromFile(string $file, ?string $selector = null): DkimContainer
    {
        $factory = new ContainerFactory;
        if (is_file($file) && file_exists($file)) {
            $container = $factory->createFromFile($file);
        }
        if ($container instanceof PublicKeyReadableInterface) {
            return $this->createFromPublicKeyReadable($container, $selector);
        } elseif ($container instanceof PublicKeyContainer) {
            return $this->createFromPublicKeyContainer($container, $selector);
        } else
            return $this->createFromPublicKeyString(file_get_contents($file), $selector);
    }

}