<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Api;

use Vaultody\Sdk\Attribute\Operation;
use Vaultody\Sdk\Exception\RequestOutcomeUnknownError;
use Vaultody\Sdk\Exception\VaultodyError;
use Vaultody\Sdk\Model\BatchTransactionRequest;
use Vaultody\Sdk\Model\FeeEstimate;
use Vaultody\Sdk\Model\GasSponsorshipTransferRequest;
use Vaultody\Sdk\Model\MultipleTransferRequest;
use Vaultody\Sdk\Model\Page;
use Vaultody\Sdk\Model\SingleTransferRequest;
use Vaultody\Sdk\Model\TransactionDetails;
use Vaultody\Sdk\Model\TransactionRequestDetails;
use Vaultody\Sdk\Model\TronContractInteractionRequest;
use Vaultody\Sdk\Model\Utxo;
use Vaultody\Sdk\Model\UtxoTransferRequest;
use Vaultody\Sdk\Model\UtxoTransferValidation;

/**
 * Transactions: `$vaultody->transactions`.
 *
 * Every method takes its parameters in one flat array (path, query and body fields by their documented
 * names) and call options in a second one: `context`, a string of your own the API returns unchanged.
 * Params are checked against the documented contract before anything is sent: a param with a documented
 * list of values (blockchain, network, feePriority, ...) takes exactly one of them, as Operations::ALL
 * lists them for this operation; anything else is a ParameterError.
 *
 * A transfer is never created twice by a retry: a write is never signed again once it may have reached the
 * API. When its answer is lost and the API can't be asked for it again, the method throws
 * RequestOutcomeUnknownError (with the request's nonce): look the transfer up with
 * getTransactionRequestDetails or in the Dashboard before sending it again.
 *
 * @phpstan-type FeeInput array{acknowledgeHighFee?: bool, computeUnitPrice?: string, fee?: string, feeLimit?: string,
 *     feeRate?: string, gasPrice?: string, maxFeePerGas?: string, maxPriorityFeePerGas?: string, total?: string}
 * @phpstan-type UtxoRecipients list<array{address: string, amount: string}>
 * @phpstan-type UtxoSenders list<array{utxoId: string}>
 * @phpstan-type UtxoChangeData array{address?: string, vaultAccountId?: string}
 */
final class Transactions extends Group
{
    /**
     * Creates a transaction request that sends a coin or token from one address of a Vault Account to one
     * recipient address.
     *
     * @param array{vaultId: string, vaultAccountId: string, assetId: string, fromAddress: string, toAddress: string,
     *        amount: string, note: string, feePriority?: 'slow'|'standard'|'fast', feeInput?: FeeInput,
     *        feeOptimization?: bool, gross?: bool, maxFee?: string} $params
     * @param array{context?: string} $options
     * @throws RequestOutcomeUnknownError the transfer may have been created
     * @throws VaultodyError
     */
    #[Operation('createSingleTransfer')]
    public function createSingleTransfer(array $params, array $options = []): SingleTransferRequest
    {
        return $this->item('createSingleTransfer', SingleTransferRequest::class, $params, $options);
    }

    /**
     * Creates a transaction request on a UTXO-based blockchain that pays one or more recipients from a
     * Vault Account, with the inputs to spend selected automatically.
     *
     * @param array{vaultId: string, vaultAccountId: string, assetId: string, recipients: UtxoRecipients, note: string,
     *        feePriority: 'slow'|'standard'|'fast', prepareStrategy: 'minimize-dust'|'optimize-size',
     *        feeInput?: FeeInput, gross?: bool, maxFee?: string} $params
     * @param array{context?: string} $options
     * @throws RequestOutcomeUnknownError the transfer may have been created
     * @throws VaultodyError
     */
    #[Operation('createMultipleTransfer')]
    public function createMultipleTransfer(array $params, array $options = []): MultipleTransferRequest
    {
        return $this->item('createMultipleTransfer', MultipleTransferRequest::class, $params, $options);
    }

    /**
     * Creates a transaction request on a UTXO-based blockchain that spends exactly the UTXOs you choose.
     *
     * @param array{vaultId: string, assetId: string, senders: UtxoSenders, recipients: UtxoRecipients, note: string,
     *        feePriority: string, changeData?: UtxoChangeData, feeInput?: FeeInput, feePayer?: string, gross?: bool,
     *        maxFee?: string} $params
     * @param array{context?: string} $options
     * @throws RequestOutcomeUnknownError the transfer may have been created
     * @throws VaultodyError
     */
    #[Operation('createUtxoTransfer')]
    public function createUtxoTransfer(array $params, array $options = []): UtxoTransferRequest
    {
        return $this->item('createUtxoTransfer', UtxoTransferRequest::class, $params, $options);
    }

    /**
     * A dry run of createUtxoTransfer: it takes the same parameters and returns a complete transaction
     * preview without creating anything. It changes nothing, so it is retried like a read.
     *
     * @param array{vaultId: string, assetId: string, senders: UtxoSenders, recipients: UtxoRecipients,
     *        feePriority: string, note?: string, changeData?: UtxoChangeData, feePayer?: string, gross?: bool,
     *        maxFee?: string} $params
     * @param array{context?: string} $options
     * @throws VaultodyError
     */
    #[Operation('validateUtxoTransfer')]
    public function validateUtxoTransfer(array $params, array $options = []): UtxoTransferValidation
    {
        return $this->item('validateUtxoTransfer', UtxoTransferValidation::class, $params, $options);
    }

    /**
     * Creates one transaction request that sends several asset transfers from a single sender, with a
     * designated fee payer covering the fee.
     *
     * @param array{vaultId: string, fromAddress: string, feePayer: array{address: string, assetId: string},
     *        recipients: list<array{address: string, amount: string, assetId: string}>, note: string,
     *        feePriority?: 'slow'|'standard'|'fast', vaultAccountId?: string} $params
     * @param array{context?: string} $options
     * @throws RequestOutcomeUnknownError the batch may have been created
     * @throws VaultodyError
     */
    #[Operation('createBatchTransactionRequest')]
    public function createBatchTransactionRequest(array $params, array $options = []): BatchTransactionRequest
    {
        return $this->item('createBatchTransactionRequest', BatchTransactionRequest::class, $params, $options);
    }

    /**
     * Creates a transaction request that sends a coin or token to one recipient while a separate fee payer
     * address pays the network fee.
     *
     * @param array{vaultId: string, vaultAccountId: string, assetId: string, fromAddress: string, toAddress: string,
     *        feePayer: string, amount: string, note: string, feePriority?: 'slow'|'standard'|'fast',
     *        feeInput?: FeeInput, maxFee?: string} $params
     * @param array{context?: string} $options
     * @throws RequestOutcomeUnknownError the transfer may have been created
     * @throws VaultodyError
     */
    #[Operation('gasSponsorshipTransfer')]
    public function gasSponsorshipTransfer(array $params, array $options = []): GasSponsorshipTransferRequest
    {
        return $this->item('gasSponsorshipTransfer', GasSponsorshipTransferRequest::class, $params, $options);
    }

    /**
     * Creates a transaction request that calls a TRC-20 token contract on Tron, so a fee payer address can
     * cover the TRX fee of a token transfer.
     *
     * @param array{vaultId: string, vaultAccountId: string, assetId: string, fromAddress: string, feePayer: string,
     *        method: 'approve'|'transfer-from', note: string, amount?: string, toAddress?: string,
     *        feeInput?: FeeInput, feeOptimization?: bool, maxFee?: string} $params
     * @param array{context?: string} $options
     * @throws RequestOutcomeUnknownError the request may have been created
     * @throws VaultodyError
     */
    #[Operation('createTronContractInteractionRequest')]
    public function createTronContractInteractionRequest(array $params, array $options = []): TronContractInteractionRequest
    {
        return $this->item('createTronContractInteractionRequest', TronContractInteractionRequest::class, $params, $options);
    }

    /**
     * Calculates an approximate fee for a planned transaction before it is submitted, by the asset you
     * send. It changes nothing, so it is retried like a read.
     *
     * @param array{vaultId: string, vaultAccountId: string, transactionType: string, assetId?: string, amount?: string,
     *        fromAddress?: string, toAddress?: string, recipients?: list<array{address?: string, amount?: string, assetId?: string}>,
     *        feePriority?: 'slow'|'standard'|'fast', feePayer?: string, feePayerAssetId?: string,
     *        feeOptimization?: bool, method?: 'approve'|'transfer-from',
     *        prepareStrategy?: 'minimize_dust'|'optimize_size'} $params
     *        prepareStrategy takes the values this operation documents, written with underscores
     *        (createMultipleTransfer documents them with hyphens)
     * @param array{context?: string} $options
     * @throws VaultodyError
     */
    #[Operation('estimateTransactionFeeByAssetId')]
    public function estimateTransactionFeeByAssetId(array $params, array $options = []): FeeEstimate
    {
        return $this->item('estimateTransactionFeeByAssetId', FeeEstimate::class, $params, $options);
    }

    /**
     * Returns one transaction of a Vault on the blockchain: its direction, status, senders, recipients,
     * fee, token transfers and internal transfers.
     *
     * @param array{vaultId: string, blockchain: string, transactionId: string} $params
     * @param array{context?: string} $options
     * @throws VaultodyError
     */
    #[Operation('getTransactionDetails')]
    public function getTransactionDetails(array $params, array $options = []): TransactionDetails
    {
        return $this->item('getTransactionDetails', TransactionDetails::class, $params, $options);
    }

    /**
     * Returns the details and current status of one transaction request.
     *
     * @param array{transactionRequestId: string} $params
     * @param array{context?: string} $options
     * @throws VaultodyError
     */
    #[Operation('getTransactionRequestDetails')]
    public function getTransactionRequestDetails(array $params, array $options = []): TransactionRequestDetails
    {
        return $this->item('getTransactionRequestDetails', TransactionRequestDetails::class, $params, $options);
    }

    /**
     * Returns the UTXOs of a Vault, one page at a time, with optional filters by Vault Account, asset,
     * address and spend status.
     *
     * @param array{vaultId: string, vaultAccountId?: string, assetId?: string, address?: string, isSpent?: bool,
     *        limit?: int, startingAfter?: string} $params
     * @param array{context?: string} $options
     * @return Page<Utxo>
     * @throws VaultodyError
     */
    #[Operation('listUtxos')]
    public function listUtxos(array $params, array $options = []): Page
    {
        return $this->page('listUtxos', Utxo::class, $params, $options);
    }
}
