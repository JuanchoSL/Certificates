<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use Exception;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\ChainContainer;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use Stringable;

class Pkcs7Creator implements Stringable, SaveableInterface
{

    use SaveableTrait;

    protected $encoding = OPENSSL_ENCODING_DER;
    protected $private = null;
    protected $certificate = null;
    protected $extracerts;

    public function setPrivateKey(#[\SensitiveParameter] PrivateKeyContainer $private): static
    {
        $this->private = $private;
        return $this;
    }
    public function setCertificate(CertificateContainer $certificate): static
    {
        $this->certificate = $certificate;
        return $this;
    }
    public function setExtraCertificates(ChainContainer $certificates): static
    {
        $this->extracerts = $certificates;
        return $this;
    }

    public function export()
    {
        if (empty($this->certificate) or empty($this->private)) {
            throw new Exception("The Private Key and the user Certificate are required");
        }
        if (!$this->certificate->checkSubjectPrivateKey($this->private)) {
            throw new Exception("The Certificated is not valid for the Private key");
        }
        if ($this->extracerts->count() > 0) {
            $this->extracerts->save($xtra);
        }
        $in = tempnam(sys_get_temp_dir(), 'p7b');
        $out = tempnam(sys_get_temp_dir(), 'p7b');
        openssl_cms_sign($in, $out, (string) $this->certificate, (string) $this->private, [], OPENSSL_CMS_BINARY, $this->encoding, $xtra ?? null);
        $key = file_get_contents($out);
        if (isset($xtra)) {
            unlink($xtra);
        }
        unlink($in);
        unlink($out);
        return $key;
    }
    public function __tostring(): string
    {
        return implode("\n", ['-----BEGIN PKCS7-----', base64_encode($this->export()), '-----END PKCS7-----']);
    }
}