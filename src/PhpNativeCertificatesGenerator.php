<?php

declare(strict_types=1);

namespace JuanchoSL\Certificates;

use DateTimeImmutable;

class PhpNativeCertificatesGenerator
{

    protected \OpenSSLCertificate|string|null $ca = null;

    protected string $folder;
    protected string $name;

    public function __construct(string $folder, string $name)
    {
        $this->folder = $folder;
        $this->name = $name;
    }

    public function setCa(\OpenSSLCertificate|string $ca)
    {
        $this->ca = $ca;
    }

    public function createKeysOpenSSH(?array $config = null, ?string $passphrase = null): \OpenSSLAsymmetricKey|string
    {
        $result = openssl_pkey_new($config);
        if (!$result) {
            throw new \Exception(openssl_error_string());
        }
        openssl_pkey_export_to_file($result, $this->folder . DIRECTORY_SEPARATOR . $this->name . DIRECTORY_SEPARATOR . "{$this->name}", $passphrase, $config);
        //$publickey = openssl_pkey_get_private($result);
        $public = openssl_pkey_get_details($result);
        $openssh = (array_key_exists('dsa', $public)) ?
            $this->sshEncodePublicKeyDsa($result) :
            $this->sshEncodePublicKeyRsa($result);
        file_put_contents($this->folder . DIRECTORY_SEPARATOR . $this->name . DIRECTORY_SEPARATOR . "{$this->name}.pub", $openssh);
        /*
        $public_key = $publickey["key"];
        file_put_contents($this->folder . DIRECTORY_SEPARATOR . $this->name . DIRECTORY_SEPARATOR . "{$this->name}.pub", $public_key);*/
        openssl_pkey_export($result, $result2, $passphrase, $config);
        return $result2;
    }

    public function createKeys(?array $config = null): \OpenSSLAsymmetricKey
    {
        $result = openssl_pkey_new($config);
        if (!$result) {
            throw new \Exception(openssl_error_string());
        }
        //openssl_pkey_export_to_file($result, $this->folder . DIRECTORY_SEPARATOR . $this->name . DIRECTORY_SEPARATOR . "{$this->name}.key", null, $config);
        return $result;
    }

    public function createSigningRequest(array $dn, \OpenSSLAsymmetricKey &$privkey, ?array $config = null, ?string $passphrase = null): \OpenSSLCertificateSigningRequest
    {
        $csr = openssl_csr_new($dn, $privkey, $config);
        if (!$csr) {
            throw new \Exception(openssl_error_string());
        }
        openssl_pkey_export_to_file($privkey, $this->folder . DIRECTORY_SEPARATOR . $this->name . DIRECTORY_SEPARATOR . "{$this->name}.key", $passphrase, $config);
        openssl_csr_export_to_file($csr, $this->folder . DIRECTORY_SEPARATOR . $this->name . DIRECTORY_SEPARATOR . "{$this->name}.csr", false);
        return $csr;
    }

    public function signSigningRequest(\OpenSSLCertificateSigningRequest|string $csr, \OpenSSLAsymmetricKey|\OpenSSLCertificate|string $private, DateTimeImmutable|int $days = 365, ?array $config = null, int $serial = 0): \OpenSSLCertificate
    {
        $output = $this->folder . DIRECTORY_SEPARATOR . $this->name . DIRECTORY_SEPARATOR . "{$this->name}.crt";
        if ($days instanceof DateTimeImmutable) {
            $days = intval(ceil(floatval(($days->getTimestamp() - time()) / 86400)));
        } elseif (file_exists($output)) {
            $old = openssl_x509_parse('file://' . $output);
            $serial = $old['serialNumber'];
            //$serial = max([intval($old['serialNumber']), 0]) + 1;
            if ($old['validTo_time_t'] > time()) {
                //$serial = max([intval($old['serialNumber']), 0]);
                $expires = new \DateTime(date("Y-m-d H:i:s", $old['validTo_time_t']));
                $expires = $expires->add(new \DateInterval("P{$days}D"));
                $days = intval(ceil(floatval(($expires->getTimestamp() - time()) / 86400)));
            }
        }
        $cert = openssl_csr_sign($csr, $this->ca, $this->ca ?? $private, $days, $config, $serial);
        if (!$cert) {
            throw new \Exception(openssl_error_string());
        }
        if (file_exists($output)) {
            rename($output, $output . '_' . date("YmdHis") . '.old');
        }

        openssl_x509_export_to_file($cert, $output, true);
        openssl_x509_export($this->ca ?? $cert, $ca, true);
        file_put_contents($this->folder . DIRECTORY_SEPARATOR . $this->name . DIRECTORY_SEPARATOR . "{$this->name}.chained.crt", implode(PHP_EOL, [file_get_contents($output), $ca]));
        file_put_contents($this->folder . DIRECTORY_SEPARATOR . $this->name . DIRECTORY_SEPARATOR . "{$this->name}.pem", implode(PHP_EOL, [file_get_contents($output), file_get_contents(str_replace('.crt', '.key', $output))]));
        return $cert;
    }

    public function extractPublicKey(\OpenSSLCertificate $certificate): string
    {
        $publickey = openssl_pkey_get_public($certificate);
        $publickey = openssl_pkey_get_details($publickey);
        $public_key = $publickey["key"];
        file_put_contents($this->folder . DIRECTORY_SEPARATOR . $this->name . DIRECTORY_SEPARATOR . "{$this->name}.pub", $public_key);
        return $public_key;
    }

    public function parseCertificate(\OpenSSLCertificate $certificate): array
    {
        return openssl_x509_parse($certificate);
    }


    /**
     * https://stackoverflow.com/questions/37606189/how-can-i-convert-dsa-public-key-from-openssl-to-openssh-format-in-php
     * @param mixed $privKey
     * @return string
     */
    protected function sshEncodePublicKeyDsa($privKey)
    {
        $keyInfo = openssl_pkey_get_details($privKey);
        $buffer = pack("N", 7) . "ssh-dss" .
            $this->sshEncodeBuffer($keyInfo['dsa']['p']) .
            $this->sshEncodeBuffer($keyInfo['dsa']['q']) .
            $this->sshEncodeBuffer($keyInfo['dsa']['g']) .
            $this->sshEncodeBuffer($keyInfo['dsa']['pub_key']);

        return "ssh-dss " . base64_encode($buffer);
    }

    protected function sshEncodePublicKeyRsa($privKey)
    {
        $keyInfo = openssl_pkey_get_details($privKey);

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