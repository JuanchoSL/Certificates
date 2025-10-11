<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Enums;

enum RevokeReasonsEnum: string
{
    case REVOKE_REASON_UNESPECIFIED = 'unspecified';
    case REVOKE_REASON_KEY_COMPROMISED = 'keyCompromise';
    case REVOKE_REASON_CA_COMPROMISED = 'CACompromise';
    case REVOKE_REASON_AFFILIATION_CHANGED = 'affiliationChanged';
    case REVOKE_REASON_SUPERSEDED = 'superseded';
    case REVOKE_REASON_CESSATION_OF_OPERATION = 'cessationOfOperation';
    case REVOKE_REASON_CERTICATE_HOLD = 'certificateHold';
    case REVOKE_REASON_REMOVE_FROM_CRL = 'removeFromCRL';
    case REVOKE_REASON_PRIVILEGE_WITH_DRAW = 'privilegeWithdrawn';
    case REVOKE_REASON_PRIVILEGE_AA_COMPROMISE = 'aACompromise';
}