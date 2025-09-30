<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use Exception;
use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use Stringable;

class Pkcs8Creator extends Pkcs7Creator implements Stringable, SaveableInterface
{
    protected $message = '';

    public function setMessage(Stringable $message)
    {
        $this->message = $message;
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
        if (!empty($this->extracerts) && $this->extracerts->count() > 0) {
            $this->extracerts->save($xtra);
        }

        //$this->private->save($priv);
        $in = tempnam(sys_get_temp_dir(), 'p8b');
        $message = (empty($this->message)) ? implode(PHP_EOL, [(string) $this->certificate, (string) $this->extracerts, (string) $this->private]) : (string) $this->message;
        file_put_contents($in, $message);
        $out = tempnam(sys_get_temp_dir(), 'p8b');
        openssl_cms_sign($in, $out, $this->certificate->__invoke(), $this->private->__invoke(), [], OPENSSL_CMS_BINARY, $this->encoding, $xtra ?? null);
        $key = file_get_contents($out);
        //unlink($priv);
        if (isset($xtra)) {
            unlink($xtra);
        }
        unlink($in);
        unlink($out);
        return $key;
    }

    public function __tostring(): string
    {
        if ($this->encoding == OPENSSL_ENCODING_SMIME) {
            return implode("\n", ['-----BEGIN PKCS8-----', base64_encode($this->export()), '-----END PKCS8-----']);
        } elseif ($this->encoding == OPENSSL_ENCODING_PEM) {
            return (new ConverterFactory())->convertFromBinaryToPem($this->export(), ContentTypesEnum::CONTENTTYPE_CMS);
        } elseif ($this->encoding == OPENSSL_ENCODING_DER) {
            return (new ConverterFactory())->convertFromBinaryToDer($this->export(), ContentTypesEnum::CONTENTTYPE_PKCS8);
            return implode("\n", ['-----BEGIN PKCS8-----', base64_encode($this->export()), '-----END PKCS8-----']);
            return $this->export();
        } else {
            return base64_encode($this->export());
        }

    }
}