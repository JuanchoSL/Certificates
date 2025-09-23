<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Interfaces\StandarizableInterface;
use JuanchoSL\Certificates\Traits\DetailableTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Certificates\Traits\StringableTrait;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use Stringable;

class PublicKeyContainer implements
    DetailableInterface,
    ExportableInterface,
    Stringable,
    SaveableInterface,
    StandarizableInterface,
    FormateableInterface
{

    use DetailableTrait, StringableTrait, SaveableTrait;

    protected $data = null;

    public function __construct(#[\SensitiveParameter] OpenSSLAsymmetricKey|OpenSSLCertificate|string $cert_content)
    {
        if (is_string($cert_content) && is_file($cert_content) && file_exists($cert_content)) {
            $cert_content = file_get_contents($cert_content);
        }
        $this->data = openssl_pkey_get_public($cert_content);
    }

    public function getDetails(): array|false
    {
        return $this->details ??= openssl_pkey_get_details($this->data);
    }

    public function export(): string
    {
        return $this->getDetail('key');
    }

    public function __invoke(): mixed
    {
        return $this->data;
    }

    public function getDkim(?string $selector = NULL)
    {
        // convert a public key into a BIND TXT entry for DKIM
        $public_key = $this->getDetail('key');
        $key_content = explode("\n", trim($public_key));
        $key_content = array_filter($key_content, fn($val) => !preg_match("/^-+/", $val));
        $key_content = str_split(implode("", $key_content), 218);
        $retval = ($selector) ? "{$selector}._domainkey" : "@";
        $retval .= "\tIN\tTXT\t\"v=DKIM1; k=rsa; p=" . implode('" "', array_filter($key_content)) . "\"";
        return new DkimContainer($retval);
    }

    public function getOpenSSH(?string $comment = null)
    {
        $public = $this->getDetails();
        if (array_key_exists('dsa', $public)) {
            $key = $this->sshEncodePublicKeyDsa($public) . " {$comment}";
        } elseif (array_key_exists('rsa', $public)) {
            $key = $this->sshEncodePublicKeyRsa($public) . " {$comment}";
        } else {
            return null;
        }
        return new PublicSshKeyContainer($key);
    }
    /*
        public function getFingerprint(string $hash = '')
        {
            if (!empty($this->getOpenSSH())) {
                preg_match('~ssh-(\w+)\s([\w=/+]+)\s*~m', $this->getOpenSSH(), $matches);
                $key = base64_decode($matches[2]);
                $fingerprint = [];
                foreach (openssl_get_md_methods() as $algo) {
                    $fingerprint[$algo] = openssl_digest($key, $algo);
                    if (!in_array($algo, ['md5'])) {
                        if (($digest = openssl_digest($key, $algo, true)) !== false) {
                            $fingerprint[$algo . "-B64"] = base64_encode($digest);
                        }
                    }
                }
                return $fingerprint;
            }
            return null;
        }
    */
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

    public function getExtension(): string
    {
        return 'pub';
    }

    public function getMediaType(): string
    {
        return 'text/plain';
    }
}