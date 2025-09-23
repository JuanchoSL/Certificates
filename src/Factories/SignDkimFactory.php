<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

/**
 * https://www.the-art-of-web.com/php/dkim-mail-signature/#google_vignette
 */
class SignDkimFactory
{

    const HASHING_ALGORITHM = "rsa-sha256";        // rsa-sha1
    const SIGNING_ALGORITHM = OPENSSL_ALGO_SHA256; // OPENSSL_ALGO_SHA1
    const DIGEST_ALGORITHM = "sha1";            // sha1

    const CANONICALIZATION = "relaxed/simple";
    const QUERY_METHOD = "dns/txt";

    private $domain;
    private $private_key;
    private $selector;

    public function __construct(string $domain, string $key, string $selector)
    {
        $this->private_key = $key;
        $this->domain = $domain;
        //$key_file = stream_resolve_include_path("dkim-keys/{$key}") or die(__METHOD__ . ": failed to locate key file dkim-keys/{$key}");
        //$this->private_key = file_get_contents($key_file) or die(__METHOD__ . ": could not read private key {$key_file}");
        $this->selector = $selector;
    }

    private function quote_string(string $input): string
    {
        $retval = "";
        foreach (str_split($input) as $char) {
            $ord = ord($char);
            switch (TRUE) {
                case (0x21 <= $ord) && ($ord <= 0x3A):
                case (0x3E <= $ord) && ($ord <= 0x7E):
                case 0x3C == $ord:
                    $retval .= $char;
                    break;

                default:
                    $retval .= "=" . dechex($ord);
            }
        }
        return $retval;
    }

    private function compact_header(array $input): string
    {
        return preg_replace_callback(
            "/(\S+):\s*([^\r\n]+)/",
            fn($m) => strtolower($m[1]) . ":" . trim($m[2]),
            implode("\r\n", $input)
        );
    }

    private function generate_signature(array $input): string|false
    {
        $input = $this->compact_header($input);
        if (openssl_sign($input, $signature, $this->private_key, self::SIGNING_ALGORITHM)) {
            return base64_encode($signature);
        }
        return FALSE;
    }

    public function sign(array $headers, string $to, string $subject, string $body): string
    {
        $encoded = $tosign = [];
        $body = preg_replace("/\r?\n/", "\r\n", rtrim($body));
        $signing_values = [
            'Subject' => $subject,
            'To' => $to,
        ];
        foreach ($headers as $key => $header) {
            if (is_numeric($key)) {
                if (preg_match("/^(To|From): (.+)/", $header, $regs)) {
                    $signing_values[$regs[1]] = $regs[2];
                }
            } elseif (in_array($key, ["To", "From"])) {
                $signing_values[$key] = $header;
            }
        }
        foreach ($signing_values as $key => $val) {
            $tosign[] = "{$key}: {$val}";
            $encoded[$key] = $this->quote_string("{$key}: {$val}");
        }
        $dkim_header = implode("; ", [
            "v=1",
            "a=" . self::HASHING_ALGORITHM,
            "q=" . self::QUERY_METHOD,
            "l=" . strlen($body),
            "s=" . $this->selector,
            "t=" . time(),
            "c=" . self::CANONICALIZATION,
            "h=" . implode(":", array_keys($signing_values)),
            "d=" . $this->domain,
            "i=" . preg_replace("/(.+\<|\>$)/", "", $signing_values['From']),
            "z=" . implode("|", $encoded),
            "bh=" . base64_encode(pack("H*", openssl_digest($body, self::DIGEST_ALGORITHM))),
            "b=",
        ]);
        $tosign[] = "DKIM-Signature: {$dkim_header}";
        return $this->formated($dkim_header . $this->generate_signature($tosign));
    }

    protected function formated($str)
    {
        return $str;
        $line = $result = '';
        $parts = explode('; ', $str);
        //echo "<pre>" . print_r($parts, true);exit;
        foreach ($parts as $part) {
            if (strlen($part) > 64) {
                $part = chunk_split($part."; ", 64);
                $result .= $part;
            } elseif (strlen($line) + strlen($part) > 64) {
                $result .= "{$line}\r\n";
                $line = $part . "; ";
            } else {
                $line .= "{$part}; ";
            }
        }
        return rtrim($result, "; \s\r\n");
    }
}