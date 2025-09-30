<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Repositories\PublicSshKeyContainer;
use JuanchoSL\Certificates\Repositories\PublicKeyContainer;
use JuanchoSL\Exceptions\UnprocessableEntityException;

class PublicSshFactory
{

    public function createFromPublicKeyString(string $public_key, ?string $comment = null): PublicSshKeyContainer
    {
        return $this->createFromPublicKeyContainer(new PublicKeyContainer($public_key), $comment);
    }

    public function createFromPublicKeyContainer(PublicKeyContainer $public_key, ?string $comment = null): PublicSshKeyContainer
    {
        $public = $public_key->getDetails();
        if (array_key_exists('dsa', $public)) {
            $key = $this->sshEncodePublicKeyDsa($public) . " {$comment}";
        } elseif (array_key_exists('rsa', $public)) {
            $key = $this->sshEncodePublicKeyRsa($public) . " {$comment}";
        } else {
            throw new UnprocessableEntityException("The public key needs to be RSA or DSA");
        }
        return new PublicSshKeyContainer($key);
    }

    public function createFromPublicKeyReadable(PublicKeyReadableInterface $public_key_parent, ?string $comment = null): PublicSshKeyContainer
    {
        return $this->createFromPublicKeyContainer($public_key_parent->getPublicKey(), $comment);
    }
    public function createFromFile(string $file, ?string $comment = null): PublicSshKeyContainer
    {
        $factory = new ContainerFactory;
        if (is_file($file) && file_exists($file)) {
            $container = $factory->createFromFile($file);
        }
        if ($container instanceof PublicKeyReadableInterface) {
            return $this->createFromPublicKeyReadable($container, $comment);
        } elseif ($container instanceof PublicKeyContainer) {
            return $this->createFromPublicKeyContainer($container, $comment);
        } else
            return $this->createFromPublicKeyString(file_get_contents($file), $comment);
    }

    /**
     * https://stackoverflow.com/questions/37606189/how-can-i-convert-dsa-public-key-from-openssl-to-openssh-format-in-php
     * @param mixed $privKey
     * @return string
     */
    protected function sshEncodePublicKeyDsa($keyInfo)
    {
        //$keyInfo = openssl_pkey_get_details($keyInfo);
        $buffer = pack("N", 7) . "ssh-dss" .
            $this->sshEncodeBuffer($keyInfo['dsa']['p']) .
            $this->sshEncodeBuffer($keyInfo['dsa']['q']) .
            $this->sshEncodeBuffer($keyInfo['dsa']['g']) .
            $this->sshEncodeBuffer($keyInfo['dsa']['pub_key']);

        return "ssh-dss " . base64_encode($buffer);
    }

    protected function sshEncodePublicKeyRsa($keyInfo)
    {
        //$keyInfo = openssl_pkey_get_details($keyInfo);

        $buffer = pack("N", 7) . "ssh-rsa" .
            $this->sshEncodeBuffer($keyInfo['rsa']['e']) .
            $this->sshEncodeBuffer($keyInfo['rsa']['n']);

        return "ssh-rsa " . base64_encode($buffer);
    }

    protected function sshEncodeBuffer($buffer)
    {
        $len = strlen($buffer);
        if (ord($buffer[0]) & 0x80) {
            $len++;
            $buffer = "\x00" . $buffer;
        }

        return pack("Na*", $len, $buffer);
    }

}