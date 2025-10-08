<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Interfaces\Complex\CertificateInterface;
use JuanchoSL\Certificates\Interfaces\Complex\PrivateKeyInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Repositories\RevokedCertsContainer;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Exceptions\PreconditionFailedException;
use JuanchoSL\Exceptions\PreconditionRequiredException;
use Stringable;
use Ukrbublik\openssl_x509_crl\X509;
use Ukrbublik\openssl_x509_crl\X509_CRL;

class CrlCreator implements Stringable, SaveableInterface
{

    use SaveableTrait;

    protected ?PrivateKeyInterface $private = null;
    protected ?CertificateInterface $certificate = null;
    protected RevokedCertsContainer $revoked_certs;
    protected int $crl_number = 1;
    protected ?int $days_next_crl = null;

    public function __construct(int $crl_number, ?int $days_next_crl = null)
    {
        $this->crl_number = $crl_number;
        $this->days_next_crl = $days_next_crl;
    }

    public function setPrivateKey(#[\SensitiveParameter] PrivateKeyInterface $private): static
    {
        $this->private = $private;
        return $this;
    }

    public function setCertificate(CertificateInterface $certificate): static
    {
        $this->certificate = $certificate;
        return $this;
    }

    public function setCertificates(RevokedCertsContainer $revoked_certs): static
    {
        $this->revoked_certs = $revoked_certs;
        return $this;
    }

    public function export()
    {
        if (empty($this->private) or empty($this->certificate)) {
            throw new PreconditionRequiredException("THe CA pirvate key and his referred certificate are required");
        }
        if (!$this->certificate->checkSubjectPrivateKey($this->private)) {
            throw new PreconditionFailedException("The private key is not referred to this certificate");
        }
        $ci = [
            'no' => $this->crl_number,
            'version' => 2,
            'alg' => OPENSSL_ALGO_SHA1,
            'revoked' => []
        ];
        if (!is_null($this->days_next_crl) && is_int($this->days_next_crl)) {
            $ci['days'] = $this->days_next_crl;
        }
        if (!empty($this->revoked_certs) && $this->revoked_certs->count() > 0) {
            foreach ($this->revoked_certs as $revoked_cert) {
                $temp = array(
                    'serial' => $revoked_cert['cert']->getDetail('serialNumber'),
                    'rev_date' => $revoked_cert['rev_date']->getTimestamp(),
                    'compr_date' => strtotime("-1 day"),
                    'reason' => null,
                    'hold_instr' => null
                );
                if (!empty($revoked_cert['reason'])) {
                    $temp['reason'] = X509::getRevokeReasonCodeByName($revoked_cert['reason']);
                }
                $ci['revoked'][] = $temp;
            }
        }
        return X509_CRL::create($ci, $this->private->__invoke(), $this->certificate->export());
    }
    public function __tostring(): string
    {
        return (new ConverterFactory())->convertFromBinaryToPem($this->export(), ContentTypesEnum::CONTENTTYPE_CRL);
    }
}