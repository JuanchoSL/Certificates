<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use Countable;
use DateTime;
use Iterator;
use JuanchoSL\Certificates\Traits\DetailableTrait;
use Stringable;
use JuanchoSL\Certificates\Enums\RevokeReasonsEnum;
use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Factories\ConverterFactory;
use JuanchoSL\Certificates\Traits\IterableTrait;
use JuanchoSL\Certificates\Traits\StringableTrait;
use Ukrbublik\openssl_x509_crl\X509;
use vakata\asn1\structures\CRL;

class CrlContainer implements Iterator, Countable, Stringable
{
    use IterableTrait, StringableTrait, DetailableTrait;
    protected array $certs = [];
    protected int $number = 1;
    protected bool $updated = false;

    public function __construct(string $cert_content)
    {
        $this->certs = [];
        if (is_string($cert_content)) {
            if (is_file($cert_content) && file_exists($cert_content)) {
                $cert_content = file_get_contents($cert_content);
            }
            if (str_contains($cert_content, chr(0)) === false) {
                $cert_content = (new ConverterFactory())->convertFromPemToBinary($cert_content, ContentTypesEnum::CONTENTTYPE_CRL);
            }
            $this->certs = CRL::fromString($cert_content)->toArray();//['tbsCertList']['revokedCertificates'];
            foreach ($this->certs['tbsCertList']['extensions'] as $extension) {
                if ($extension['extnID'] == '2.5.29.20') {
                    $this->number = bindec($extension['extnValue'][0]);
                }
            }
        }

        foreach ($this->certs['tbsCertList']['revokedCertificates'] as $cert) {
            $reason = isset($cert['extensions'][0]['extnValue'][0]) ? $cert['extensions'][0]['extnValue'][0] : 4;
            $this->iterable[] = [
                'cert' => $cert['userCertificate'],
                'rev_date' => new DateTime(date("Y-m-d H:i:s", $cert['revocationDate'])),
                'reason' => RevokeReasonsEnum::tryFrom(X509::getRevokeReasonNameByCode($reason ?? 4))
            ];
        }
    }

    public function getNumber()
    {
        return $this->number;
    }

    public function getExtension(): string
    {
        return 'crl';
    }

    public function getMediaType(): string
    {
        return 'application/pkix-crl';
    }
}