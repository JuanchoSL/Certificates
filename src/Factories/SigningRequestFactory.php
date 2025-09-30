<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use DateTimeImmutable;
use JuanchoSL\Certificates\Interfaces\CertificateReadableInterface;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use JuanchoSL\Certificates\Repositories\SigningRequestContainer;

class SigningRequestFactory
{

    public function createFromConfig(array $distinguised_names, array $config, #[\SensitiveParameter] PrivateKeyContainer $private): SigningRequestContainer
    {
        $result = openssl_csr_new($distinguised_names, $private, $config);
        if (!$result) {
            throw new \Exception(openssl_error_string());
        }
        return new SigningRequestContainer($result);
    }

    public function signSigningRequest(SigningRequestContainer $csr, PrivateKeyContainer|CertificateReadableInterface $ca_signer, DateTimeImmutable|int $days = 365, ?array $config = null, int $serial = 0): CertificateContainer
    {
        if ($days instanceof DateTimeImmutable) {
            $days = intval(ceil(floatval(($days->getTimestamp() - time()) / 86400)));
        }

        $certificate = null;
        if ($ca_signer instanceof PrivateKeyReadableInterface) {
            $certificate = (string) $ca_signer->getCertificate();
            $ca_signer = $ca_signer->getPrivateKey();
        }
        $cert = openssl_csr_sign((string) $csr, $certificate, (string) $ca_signer, $days, $config, $serial);
        if (!$cert) {
            throw new \Exception(openssl_error_string());
        }
        return new CertificateContainer($cert);
    }
}