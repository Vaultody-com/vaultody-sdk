<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The preview of a UTXO transfer (validateUtxoTransfer); nothing is created. */
final class UtxoTransferValidation extends Model
{
    protected const LISTS = [
        'recipients' => TransferRecipient::class,
        'senders' => UtxoSender::class,
    ];

    /**
     * @param ?string $error Why the transfer would fail, for example `MAX_FEE_EXCEEDED`.
     * @param ?string $feeInNative The calculated fee, in the coin's own unit.
     * @param ?string $inputAmount The total amount of the inputs.
     * @param ?string $inputSize The size of the inputs, in virtual bytes.
     * @param ?string $outputAmount The total amount of the outputs, recipients and change included.
     * @param ?string $outputSize The size of the outputs, in virtual bytes.
     * @param list<TransferRecipient> $recipients The recipients of the transfer: 1 to 150, each with an address and an amount.
     * @param ?bool $recipientsValid `true` when every recipient is valid.
     * @param list<UtxoSender> $senders The UTXOs the transfer would spend.
     * @param ?bool $sendersValid `true` when every sender UTXO is valid and can be spent.
     * @param ?string $size The size of the whole transaction, in virtual bytes.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $error = null,
        public readonly ?string $feeInNative = null,
        public readonly ?string $inputAmount = null,
        public readonly ?string $inputSize = null,
        public readonly ?string $outputAmount = null,
        public readonly ?string $outputSize = null,
        public readonly array $recipients = [],
        public readonly ?bool $recipientsValid = null,
        public readonly array $senders = [],
        public readonly ?bool $sendersValid = null,
        public readonly ?string $size = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
