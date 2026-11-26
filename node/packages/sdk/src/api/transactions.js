'use strict';

/**
 * Transactions: create transaction requests (single, multiple, UTXO, batch, gas-sponsored, Tron contract
 * interaction), estimate and validate them, read transactions and requests, and list UTXOs.
 *
 * The `transactions` namespace of the client: `vaultody.transactions.<operationId>(params, options)`. Each method
 * takes its fields in one flat `params` object (path, query and body together), checks them against the API
 * reference before anything is sent, and goes through the client's whole pipeline: signed, verified, retried by its
 * class.
 */

const { bindOperations } = require('./common');

/** @typedef {import('./common').Blockchain} Blockchain */
/** @typedef {import('./common').FeePriority} FeePriority */
/** @typedef {import('./common').FeeInput} FeeInput */
/** @typedef {import('./common').CallOptions} CallOptions */

/**
 * @typedef {Object} CreateBatchTransactionRequestFeePayerInput The fee payer. In the request, an object with the address that pays the fee and the asset it pays with; the blockchain and network are resolved from it. In the response, the fee payer's address.
 * @property {string} address The address that pays the transaction fee.
 * @property {string} assetId The ID of the asset the fee is paid in, normally the blockchain's native coin.
 */

/**
 * @typedef {Object} CreateBatchTransactionRequestRecipientInput
 * @property {string} address The recipient's address.
 * @property {string} amount The amount the recipient receives, as a string in the asset's own unit.
 * @property {string} assetId The ID of the coin or token this recipient receives.
 */

/**
 * @typedef {Object} CreateBatchTransactionRequestParams The params of createBatchTransactionRequest: Create Batch Transaction Request.
 * @property {CreateBatchTransactionRequestFeePayerInput} feePayer The fee payer. In the request, an object with the address that pays the fee and the asset it pays with; the blockchain and network are resolved from it. In the response, the fee payer's address.
 * @property {FeePriority} [feePriority] How fast the transaction should confirm: `slow`, `standard` or `fast`. Required on EVM blockchains. Solana accepts it but does not use it to calculate the fee. The response returns the priority used.
 * @property {string} fromAddress The address that sends every transfer in the batch. It must belong to the Vault Account.
 * @property {string} note A free-text note that describes the transaction request, for your own records. The response returns it.
 * @property {Array<CreateBatchTransactionRequestRecipientInput>} recipients The transfers in the batch, one entry per recipient, each with its own asset and amount.
 * @property {string} [vaultAccountId] The ID of the Vault Account that holds `fromAddress`.
 * @property {string} vaultId The ID of the Vault that sends the funds.
 */

/**
 * @typedef {Object} CreateBatchTransactionRequestRecipient
 * @property {string} [address] The recipient's address.
 * @property {string} [amount] The amount the recipient receives, as a string in the asset's own unit.
 * @property {string} [amountUnit] The unit of the amount the recipient receives, for example ETH or USDC.
 * @property {string} [assetId] The ID of the coin or token this recipient receives.
 * @property {string} [convertedAmountToUSD] The amount the recipient receives, converted to USD.
 */

/**
 * @typedef {Object} CreateBatchTransactionRequestSenders The sender of the transaction.
 * @property {string} [address] The sender's address.
 */

/**
 * @typedef {Object} CreateBatchTransactionRequestResult data.item of createBatchTransactionRequest.
 * @property {string} [amountUnit] The unit of the transaction amount, for example ETH.
 * @property {string} [feePayer] The fee payer. In the request, an object with the address that pays the fee and the asset it pays with; the blockchain and network are resolved from it. In the response, the fee payer's address.
 * @property {string} [feePriority] How fast the transaction should confirm: `slow`, `standard` or `fast`. Required on EVM blockchains. Solana accepts it but does not use it to calculate the fee. The response returns the priority used.
 * @property {string} [note] A free-text note that describes the transaction request, for your own records. The response returns it.
 * @property {Array<CreateBatchTransactionRequestRecipient>} [recipients] The transfers in the batch, one entry per recipient, each with its own asset and amount.
 * @property {CreateBatchTransactionRequestSenders} [senders] The sender of the transaction.
 * @property {string} [totalTransactionAmountInUsd] The total value of all transfers in the batch, in USD.
 * @property {string} [transactionRequestId] The ID of the new transaction request. Use it with Get Transaction Request Details and to match the webhook events for this request.
 * @property {string} [transactionRequestStatus] The status of the transaction request. A new request is `created`.
 */

/**
 * @typedef {Object} CreateMultipleTransferRecipientInput
 * @property {string} address The recipient's address.
 * @property {string} amount The amount the recipient receives, as a string in the coin's own unit.
 */

/**
 * @typedef {Object} CreateMultipleTransferParams The params of createMultipleTransfer: Create Multiple Transfer.
 * @property {string} assetId The ID of the coin to send, for example BTC on Bitcoin testnet. Every asset has its own ID on each blockchain and network.
 * @property {FeeInput} [feeInput] Optional. A fee you set yourself, instead of the fee Vaultody calculates from `feePriority`, which is still required.
 * @property {FeePriority} feePriority How fast the transaction should confirm: `slow`, `standard` or `fast`. A faster priority pays a higher fee. The response returns the priority used.
 * @property {boolean} [gross] Optional. When `true`, the recipient amounts include the fee, so the fee is deducted from them. Defaults to `false`, where the fee is paid on top of the amounts. The response returns the value used.
 * @property {string} [maxFee] The highest fee you accept for the transaction. If the actual fee is higher, the transaction is not processed. The response returns the limit you set.
 * @property {string} note A free-text note that describes the transaction request, for your own records. The response returns it.
 * @property {'minimize-dust'|'optimize-size'} prepareStrategy How Vaultody selects the UTXOs to spend: `optimize-size` keeps the transaction small, which keeps the fee low; `minimize-dust` favours spending small outputs, so fewer of them are left behind.
 * @property {Array<CreateMultipleTransferRecipientInput>} recipients The recipients of the transaction, each with its own address and amount.
 * @property {string} vaultAccountId The ID of the Vault Account whose UTXOs pay for the transaction.
 * @property {string} vaultId The ID of the Vault that sends the funds.
 */

/**
 * @typedef {Object} CreateMultipleTransferRecipient
 * @property {string} [address] The recipient's address.
 * @property {string} [amount] The amount the recipient receives, as a string in the coin's own unit.
 * @property {string} [amountUnit] The unit of the amount the recipient receives, for example BTC or LTC.
 * @property {string} [convertedAmountToUSD] The amount the recipient receives, converted to USD.
 */

/**
 * @typedef {Object} CreateMultipleTransferResult data.item of createMultipleTransfer.
 * @property {string} [amountUnit] The unit of the amounts, for example BTC.
 * @property {string} [feePriority] How fast the transaction should confirm: `slow`, `standard` or `fast`. A faster priority pays a higher fee. The response returns the priority used.
 * @property {boolean} [gross] Optional. When `true`, the recipient amounts include the fee, so the fee is deducted from them. Defaults to `false`, where the fee is paid on top of the amounts. The response returns the value used.
 * @property {string} [maxFee] The highest fee you accept for the transaction. If the actual fee is higher, the transaction is not processed. The response returns the limit you set.
 * @property {string} [note] A free-text note that describes the transaction request, for your own records. The response returns it.
 * @property {string} [prepareStrategy] How Vaultody selects the UTXOs to spend: `optimize-size` keeps the transaction small, which keeps the fee low; `minimize-dust` favours spending small outputs, so fewer of them are left behind.
 * @property {Array<CreateMultipleTransferRecipient>} [recipients] The recipients of the transaction, each with its own address and amount.
 * @property {string} [totalTransactionAmount] The total amount the transaction sends to all recipients.
 * @property {string} [transactionRequestId] The ID of the new transaction request. Use it with Get Transaction Request Details and to match the webhook events for this request.
 * @property {string} [transactionRequestStatus] The status of the transaction request. A new request is `created`.
 */

/**
 * @typedef {Object} CreateSingleTransferParams The params of createSingleTransfer: Create Single Transfer.
 * @property {string} amount The amount to send, as a string in the asset's own unit, for example ETH.
 * @property {string} assetId The ID of the coin or token to send. Every asset has its own ID on each blockchain and network.
 * @property {FeeInput} [feeInput] Optional. A fee you set yourself, instead of the fee Vaultody calculates from `feePriority`. Send either `total` or the fee parameters your blockchain takes, not both: a request with both is refused.
 * @property {boolean} [feeOptimization] Optional, Tron only.
 * @property {FeePriority} [feePriority] How fast the transaction should confirm: `slow`, `standard` or `fast`. A faster priority pays a higher fee. Required on every blockchain except Tron and Solana. The response returns the priority used.
 * @property {string} fromAddress The address that sends the funds. It must belong to the Vault Account.
 * @property {boolean} [gross] Optional. When `true`, `amount` includes the fee: the fee is deducted from it and the recipient receives less. Supported only for coin transfers without a fee payer.
 * @property {string} [maxFee] The highest fee you accept for the transaction. If the actual fee is higher, the transaction is not processed. The response returns the limit you set.
 * @property {string} note A free-text note that describes the transaction request, for your own records. The response returns it.
 * @property {string} toAddress The address that receives the funds.
 * @property {string} vaultAccountId The ID of the Vault Account that holds `fromAddress`.
 * @property {string} vaultId The ID of the Vault that sends the funds.
 */

/**
 * @typedef {Object} CreateSingleTransferRecipient
 * @property {string} [address] The recipient's address.
 * @property {number} [addressTag] Set only when the recipient is an XRP X-address: the destination tag encoded in it, which identifies the recipient behind a shared address.
 * @property {string} [amount] The amount the recipient receives.
 * @property {string} [amountUnit] The unit of the amount the recipient receives, for example ETH, TRX or USDT.
 * @property {string} [classicAddress] Set only when the recipient is an XRP X-address: the classic address behind it.
 * @property {string} [convertedAmountToUSD] The amount the recipient receives, converted to USD.
 */

/**
 * @typedef {Object} CreateSingleTransferSenders The sender of the transaction.
 * @property {string} [address] The sender's address.
 * @property {number} [addressTag] Set only when the sender is an XRP X-address: the source tag encoded in it.
 * @property {string} [classicAddress] Set only when the sender is an XRP X-address: the classic address behind it.
 */

/**
 * @typedef {Object} CreateSingleTransferResult data.item of createSingleTransfer.
 * @property {string} [amountUnit] The unit of the amount, for example ETH or USDT.
 * @property {string} [feePriority] How fast the transaction should confirm: `slow`, `standard` or `fast`. A faster priority pays a higher fee. Required on every blockchain except Tron and Solana. The response returns the priority used.
 * @property {boolean} [gross] Optional. When `true`, `amount` includes the fee: the fee is deducted from it and the recipient receives less. Supported only for coin transfers without a fee payer.
 * @property {string} [maxFee] The highest fee you accept for the transaction. If the actual fee is higher, the transaction is not processed. The response returns the limit you set.
 * @property {string} [note] A free-text note that describes the transaction request, for your own records. The response returns it.
 * @property {Array<CreateSingleTransferRecipient>} [recipients] The recipient of the transaction, as a list with one entry.
 * @property {CreateSingleTransferSenders} [senders] The sender of the transaction.
 * @property {string} [totalTransactionAmount] The total amount the transaction sends.
 * @property {string} [transactionRequestId] The ID of the new transaction request. Use it with Get Transaction Request Details and to match the webhook events for this request.
 * @property {string} [transactionRequestStatus] The status of the transaction request. A new request is always `created`.
 */

/**
 * @typedef {Object} CreateTronContractInteractionRequestParams The params of createTronContractInteractionRequest: Create Tron Contract Interaction Request.
 * @property {string} [amount] The amount of tokens to move. Required when `method` is `transfer-from`.
 * @property {string} assetId The ID of the TRC-20 token. Native TRX is not allowed. The response returns it.
 * @property {FeeInput} [feeInput] Optional. A fee field you set yourself. On Tron the only one you can send is `feeLimit`: with any other fee field, including `total`, the transaction request fails when it is prepared.
 * @property {boolean} [feeOptimization] Optional.
 * @property {string} feePayer The address that pays the TRX energy and bandwidth fee. It must belong to the same Vault and hold a positive TRX balance. The response returns it.
 * @property {string} fromAddress The token holder's address, which must belong to the Vault. For `approve` it starts the transaction; for `transfer-from` it is the address the tokens leave.
 * @property {string} [maxFee] Optional. The highest TRX fee you accept for the transaction. The response returns the limit you set.
 * @property {'approve'|'transfer-from'} method The contract method to call. `approve` authorizes `feePayer` to spend the tokens of `fromAddress`, for the maximum uint256 amount.
 * @property {string} note A free-text note that describes the transaction request, at most 250 characters. The response returns it.
 * @property {string} [toAddress] The address that receives the tokens. Required when `method` is `transfer-from`.
 * @property {string} vaultAccountId The ID of the Vault Account that holds `fromAddress`.
 * @property {string} vaultId The ID of the Vault that holds the token holder and fee payer addresses.
 */

/**
 * @typedef {Object} CreateTronContractInteractionRequestContractInteractionData Details of the contract interaction.
 * @property {string} [contractAddress] The address of the TRC-20 token contract.
 */

/**
 * @typedef {Object} CreateTronContractInteractionRequestRecipient
 * @property {string} [address] The destination address: the token contract for `approve`, the recipient for `transfer-from`.
 * @property {string} [amount] The amount sent to the destination; 0 for `approve`.
 * @property {string} [amountUnit] The token's symbol.
 * @property {string} [convertedAmountToUSD] The amount sent, converted to USD.
 */

/**
 * @typedef {Object} CreateTronContractInteractionRequestSenders The source of the transaction: the token holder.
 * @property {string} [address] The token holder's address.
 */

/**
 * @typedef {Object} CreateTronContractInteractionRequestResult data.item of createTronContractInteractionRequest.
 * @property {string} [amountUnit] The token's symbol.
 * @property {string} [assetId] The ID of the TRC-20 token. Native TRX is not allowed. The response returns it.
 * @property {CreateTronContractInteractionRequestContractInteractionData} [contractInteractionData] Details of the contract interaction.
 * @property {string} [feePayer] The address that pays the TRX energy and bandwidth fee. It must belong to the same Vault and hold a positive TRX balance. The response returns it.
 * @property {string} [maxFee] Optional. The highest TRX fee you accept for the transaction. The response returns the limit you set.
 * @property {string} [method] The contract method to call. `approve` authorizes `feePayer` to spend the tokens of `fromAddress`, for the maximum uint256 amount.
 * @property {string} [note] A free-text note that describes the transaction request, at most 250 characters. The response returns it.
 * @property {Array<CreateTronContractInteractionRequestRecipient>} [recipients] The destination, as a list with one entry. For `approve` it is the token contract with an amount of 0; for `transfer-from` it is the recipient and the token amount.
 * @property {CreateTronContractInteractionRequestSenders} [senders] The source of the transaction: the token holder.
 * @property {string} [totalTransactionAmount] The token amount of the transaction; 0 for `approve`.
 * @property {string} [transactionRequestId] The ID of the new transaction request. Use it with Get Transaction Request Details and to match the webhook events for this request.
 * @property {string} [transactionRequestStatus] The status of the transaction request. A new request is `created`.
 */

/**
 * @typedef {Object} ChangeDataInput Optional. Where the change goes: the amount left from the spent UTXOs after the recipients and the fee are paid. Cannot be combined with `feePayer`.
 * @property {string} [address] An address of the Vault to receive the change. It is used as given, and no new address is derived.
 * @property {string} [vaultAccountId] A Vault Account of the same Vault to receive the change. Vaultody picks or derives a change address in it.
 */

/**
 * @typedef {Object} CreateUtxoTransferRecipientInput
 * @property {string} address The recipient's address.
 * @property {string} amount The amount the recipient receives, in the coin's own unit, for example BTC.
 */

/**
 * @typedef {Object} UtxoSenderInput
 * @property {string} utxoId The ID of a UTXO to spend, as returned by List UTXOs.
 */

/**
 * @typedef {Object} CreateUtxoTransferParams The params of createUtxoTransfer: Create UTXO Transfer.
 * @property {string} assetId The ID of the coin to send, on a UTXO-based blockchain.
 * @property {ChangeDataInput} [changeData] Optional. Where the change goes: the amount left from the spent UTXOs after the recipients and the fee are paid. Cannot be combined with `feePayer`.
 * @property {FeeInput} [feeInput] Not used by this endpoint: a fee you state here is ignored. The fee is calculated from `feePriority`, and `maxFee` limits it.
 * @property {string} [feePayer] Optional. An address of the Vault, on the same blockchain as the senders, that adds an input to cover the fee and receives the change. Cannot be combined with `changeData` or `gross`.
 * @property {string} feePriority How fast the transaction should confirm: `slow`, `standard` or `fast`. The response returns the priority used.
 * @property {boolean} [gross] When `true`, the recipient amounts include the fee, so the fee is deducted from them. Cannot be combined with `feePayer`.
 * @property {string} [maxFee] The highest fee you accept. If the fee is higher, the transfer fails with `MAX_FEE_EXCEEDED`.
 * @property {string} note A short free-text description of the transaction request, at most 250 characters. The response returns it.
 * @property {Array<CreateUtxoTransferRecipientInput>} recipients The recipients of the transfer: 1 to 150, each with an address and an amount.
 * @property {Array<UtxoSenderInput>} senders In the request, the UTXOs to spend: 1 to 150, from one or more Vault Accounts of the same Vault. In the response, each UTXO resolved, with its address, amount and Vault Account.
 * @property {string} vaultId The ID of the Vault that holds the UTXOs.
 */

/**
 * @typedef {Object} CreateUtxoTransferRecipient
 * @property {string} [address] The recipient's address.
 * @property {string} [amount] The amount the recipient receives, in the coin's own unit, for example BTC.
 * @property {string} [amountUnit] The unit of the amount the recipient receives, for example BTC or LTC.
 * @property {string} [assetId] The ID of the asset sent, which also sets the UTXO-based blockchain the transaction runs on.
 */

/**
 * @typedef {Object} CreateUtxoTransferSender
 * @property {string} [address] The address that holds the UTXO.
 * @property {string} [addressLabel] The label of that address, if it has one.
 * @property {string} [amount] The amount the UTXO holds, in the coin's own unit.
 * @property {string} [amountUnit] The unit of the amount, for example BTC.
 * @property {string} [assetId] The ID of the asset the UTXO holds.
 * @property {string} [utxoId] The ID of a UTXO to spend, as returned by List UTXOs.
 * @property {string} [vaultAccountId] The ID of the Vault Account that owns the UTXO. It tells the Vault Accounts apart when the inputs come from several of them.
 */

/**
 * @typedef {Object} CreateUtxoTransferResult data.item of createUtxoTransfer.
 * @property {string} [amountUnit] The unit of the amounts, for example BTC.
 * @property {string} [feePriority] How fast the transaction should confirm: `slow`, `standard` or `fast`. The response returns the priority used.
 * @property {string} [note] A short free-text description of the transaction request, at most 250 characters. The response returns it.
 * @property {Array<CreateUtxoTransferRecipient>} [recipients] The recipients of the transfer: 1 to 150, each with an address and an amount.
 * @property {Array<CreateUtxoTransferSender>} [senders] In the request, the UTXOs to spend: 1 to 150, from one or more Vault Accounts of the same Vault. In the response, each UTXO resolved, with its address, amount and Vault Account.
 * @property {string} [totalTransactionAmount] The total amount sent to the recipients, without the change and the fee.
 * @property {string} [transactionRequestId] The ID of the new transaction request. Use it with Get Transaction Request Details and to match the webhook events for this request.
 * @property {string} [transactionRequestStatus] The status of the transaction request. A new request is always `created`.
 * @property {string} [transactionType] The kind of transaction. For a UTXO transfer it is always `coin`.
 */

/**
 * @typedef {Object} EstimateTransactionFeeByAssetIdRecipientInput
 * @property {string} [address] The recipient's address. Required for multiple and batch transfers.
 * @property {string} [amount] The amount the recipient receives. Required for multiple and batch transfers.
 * @property {string} [assetId] The ID of the asset this recipient receives. Required for batch transfers, where each recipient names its own asset.
 */

/**
 * @typedef {Object} EstimateTransactionFeeByAssetIdParams The params of estimateTransactionFeeByAssetId: Estimate Transaction Fee by Asset ID.
 * @property {string} [amount] The amount to send. Required for single and Gas Sponsorship transfers.
 * @property {string} [assetId] The ID of the asset to send. Required for single, Gas Sponsorship and multiple transfers.
 * @property {boolean} [feeOptimization] Optional, Tron only.
 * @property {string} [feePayer] The address that pays the fee. Required for batch, Gas Sponsorship and Tron contract interaction transfers.
 * @property {string} [feePayerAssetId] The ID of the asset the fee payer pays with. Required for batch transfers.
 * @property {FeePriority} [feePriority] How fast the transaction should confirm: `slow`, `standard` or `fast`. Not used for Tron and Solana.
 * @property {string} [fromAddress] The address that sends the funds. Required for single, Gas Sponsorship and batch transfers.
 * @property {'approve'|'transfer-from'} [method] Required when `transactionType` is `contractInteraction`: the Tron contract method to call, `approve` or `transfer-from`.
 * @property {'minimize_dust'|'optimize_size'} [prepareStrategy] For UTXO-based transfers, how the UTXOs to spend are selected: `optimize_size` or `minimize_dust`. Optional.
 * @property {Array<EstimateTransactionFeeByAssetIdRecipientInput>} [recipients] The recipients and the amount each receives. Required for multiple and batch transfers.
 * @property {string} [toAddress] The recipient's address. Required for single and Gas Sponsorship transfers.
 * @property {string} transactionType The type of transaction to estimate: `single`, `multiple`, `batch` or `contractInteraction`. A Gas Sponsorship transfer uses `single`.
 * @property {string} vaultAccountId The ID of the Vault Account that sends the funds. Required for every transaction type.
 * @property {string} vaultId The ID of the Vault the transaction will be sent from.
 */

/**
 * @typedef {Object} EstimateTransactionFeeByAssetIdResult data.item of estimateTransactionFeeByAssetId.
 * @property {string} [errorMessage] Why the transaction would fail, for example `INSUFFICIENT_FUNDS`. Empty when the estimate succeeds.
 * @property {string} [feeInNative] The estimated fee, in the blockchain's native coin.
 * @property {boolean} [insufficientBalance] Tron only. Present and `true` when the sender's own TRX balance does not cover the estimated fee. `feeInNative` is still the estimate for the transaction as requested, and `errorMessage` is set too.
 * @property {string} [maxAmount] For UTXO-based transfers: the most the Vault Account can send.
 */

/**
 * @typedef {Object} GasSponsorshipTransferParams The params of gasSponsorshipTransfer: Gas Sponsorship Transfer.
 * @property {string} amount The amount to send, as a string in the asset's own unit, for example ETH.
 * @property {string} assetId The ID of the coin or token to send. Every asset has its own ID on each blockchain and network.
 * @property {FeeInput} [feeInput] Not supported for Gas Sponsorship transfers: if you state a fee here, the transaction request fails when it is prepared. Leave it out and let Vaultody calculate the fee.
 * @property {string} feePayer The address that pays the network fee instead of `fromAddress`. Supported on Ethereum, BNB Smart Chain, Base, Optimism, Arbitrum, Polygon and Solana. The response returns it.
 * @property {FeePriority} [feePriority] How fast the transaction should confirm: `slow`, `standard` or `fast`. A faster priority pays a higher fee. Required on every blockchain except Solana. The response returns the priority used.
 * @property {string} fromAddress The address that sends the funds. It must belong to the Vault Account.
 * @property {string} [maxFee] The highest fee you accept for the transaction. If the actual fee is higher, the transaction is not processed. The response returns the limit you set.
 * @property {string} note A free-text note that describes the transaction request, for your own records. The response returns it.
 * @property {string} toAddress The address that receives the funds.
 * @property {string} vaultAccountId The ID of the Vault Account that holds `fromAddress`.
 * @property {string} vaultId The ID of the Vault that sends the funds.
 */

/**
 * @typedef {Object} GasSponsorshipTransferRecipient
 * @property {string} [address] The recipient's address.
 * @property {number} [addressTag] Set only when the recipient is an XRP X-address: the destination tag encoded in it, which identifies the recipient behind a shared address.
 * @property {string} [amount] The amount the recipient receives.
 * @property {string} [amountUnit] The unit of the amount the recipient receives, for example ETH or USDT.
 * @property {string} [classicAddress] Set only when the recipient is an XRP X-address: the classic address behind it.
 * @property {string} [convertedAmountToUSD] The amount the recipient receives, converted to USD.
 */

/**
 * @typedef {Object} GasSponsorshipTransferSenders The sender of the transaction.
 * @property {string} [address] The sender's address.
 * @property {number} [addressTag] Set only when the sender is an XRP X-address: the source tag encoded in it.
 * @property {string} [classicAddress] Set only when the sender is an XRP X-address: the classic address behind it.
 */

/**
 * @typedef {Object} GasSponsorshipTransferResult data.item of gasSponsorshipTransfer.
 * @property {string} [amountUnit] The unit of the amount, for example ETH or USDT.
 * @property {string} [feePayer] The address that pays the network fee instead of `fromAddress`. Supported on Ethereum, BNB Smart Chain, Base, Optimism, Arbitrum, Polygon and Solana. The response returns it.
 * @property {string} [feePriority] How fast the transaction should confirm: `slow`, `standard` or `fast`. A faster priority pays a higher fee. Required on every blockchain except Solana. The response returns the priority used.
 * @property {string} [maxFee] The highest fee you accept for the transaction. If the actual fee is higher, the transaction is not processed. The response returns the limit you set.
 * @property {string} [note] A free-text note that describes the transaction request, for your own records. The response returns it.
 * @property {Array<GasSponsorshipTransferRecipient>} [recipients] The recipient of the transaction, as a list with one entry.
 * @property {GasSponsorshipTransferSenders} [senders] The sender of the transaction.
 * @property {string} [totalTransactionAmount] The total amount the transaction sends.
 * @property {string} [transactionRequestId] The ID of the new transaction request. Use it with Get Transaction Request Details and to match the webhook events for this request.
 * @property {string} [transactionRequestStatus] The status of the transaction request. A new request is `created`.
 */

/**
 * @typedef {Object} GetTransactionDetailsParams The params of getTransactionDetails: Get Transaction Details.
 * @property {Blockchain} blockchain The blockchain of the transaction, for example `bitcoin`, `ethereum`, `binance-smart-chain` or `tron`.
 * @property {string} transactionId The ID of the transaction on the blockchain: the transaction hash on account-based blockchains such as Ethereum.
 * @property {string} vaultId The ID of the Vault the transaction belongs to.
 */

/**
 * @typedef {Object} GetTransactionDetailsInternalTransfer
 * @property {string} [fromAddress] The address that sent the internal transfer.
 * @property {string} [operationId] The ID of the operation inside the transaction.
 * @property {string} [operationType] The type of the operation, for example `CALL`.
 * @property {string} [previousTxHash] The hash of the transaction recorded on the blockchain immediately before this one.
 * @property {number} [timestamp] When the internal transfer was recorded on the blockchain, as a Unix timestamp in seconds.
 * @property {string} [toAddress] The address that received the internal transfer.
 */

/**
 * @typedef {Object} GetTransactionDetailsRecipient
 * @property {string} [address] The recipient's address.
 * @property {string} [addressType] The type of the address, for example `deposit` or `smart`.
 * @property {string} [amount] The amount this address received.
 * @property {string} [amountUnit] The unit of the amount, for example BTC, ETH or TRX.
 * @property {string} [isVaultAddress] `true` when the address belongs to the Vault, `false` otherwise.
 * @property {string} [label] The label of the address in the Vault, if it has one.
 */

/**
 * @typedef {Object} GetTransactionDetailsSender
 * @property {string} [address] The sender's address.
 * @property {string} [addressType] The type of the address, for example `deposit`.
 * @property {string} [amount] The amount this address sent.
 * @property {string} [amountUnit] The unit of the amount, for example BTC, ETH or TRX.
 * @property {string} [isVaultAddress] `true` when the address belongs to the Vault, `false` otherwise.
 * @property {string} [label] The label of the address in the Vault, if it has one.
 */

/**
 * @typedef {Object} GetTransactionDetailsTokensTransfer
 * @property {string} [amount] The amount of tokens transferred.
 * @property {string} [amountUnit] The token's symbol, for example USDT or USDC.
 * @property {string} [contractAddress] The token's contract address.
 * @property {number} [decimals] The number of decimal places the token uses.
 * @property {string} [fromAddress] The address that sent the tokens.
 * @property {string} [toAddress] The address that received the tokens.
 * @property {string} [tokenName] The token's name, for example Tether USD.
 * @property {string} [type] The token standard, for example ERC-20, BEP-20 or TRC-20.
 */

/**
 * @typedef {Object} GetTransactionDetailsTransactionFee The fee paid for the transaction.
 * @property {string} [amount] The fee amount.
 * @property {string} [amountUnit] The unit of the fee, the blockchain's native coin, for example BTC, ETH or TRX.
 */

/**
 * @typedef {Object} GetTransactionDetailsResult data.item of getTransactionDetails.
 * @property {number} [dateTime] When the transaction was created, as a Unix timestamp in seconds.
 * @property {string} [direction] The direction of the transaction for the Vault: `incoming`, `outgoing`, `client-internal`, `vault-internal` or `internal`.
 * @property {Array<GetTransactionDetailsInternalTransfer>} [internalTransfers] The internal transfers inside the transaction: value moved by contract calls rather than by the transaction itself.
 * @property {string} [minedInBlockHeight] The height of the block in which the transaction was first mined.
 * @property {string} [network] The network of the transaction, for example `mainnet`, `testnet`, `sepolia` or `nile`.
 * @property {Array<GetTransactionDetailsRecipient>} [recipients] The addresses that received funds in the transaction.
 * @property {Array<GetTransactionDetailsSender>} [senders] The addresses that sent funds in the transaction.
 * @property {string} [status] The status of the transaction on the blockchain, for example `confirmed` or `failed`.
 * @property {Array<GetTransactionDetailsTokensTransfer>} [tokensTransfers] The token transfers in the transaction. Empty for a plain coin transfer.
 * @property {GetTransactionDetailsTransactionFee} [transactionFee] The fee paid for the transaction.
 */

/**
 * @typedef {Object} GetTransactionRequestDetailsParams The params of getTransactionRequestDetails: Get Transaction Request Details.
 * @property {string} transactionRequestId The ID of the transaction request, as returned when you created it.
 */

/**
 * @typedef {Object} GetTransactionRequestDetailsRecipient
 * @property {string} [address] The recipient's address.
 * @property {number} [addressTag] Set only when the recipient is an XRP X-address: the destination tag encoded in it, which identifies the recipient behind a shared address.
 * @property {string} [amount] The amount the recipient receives.
 * @property {string} [amountUnit] The unit of the amount the recipient receives.
 * @property {string} [classicAddress] Set only when the recipient is an XRP X-address: the classic address behind it.
 */

/**
 * @typedef {Object} GetTransactionRequestDetailsSenders The sender of the transaction.
 * @property {string} [address] The sender's address.
 * @property {number} [addressTag] Set only when the sender is an XRP X-address: the source tag encoded in it.
 * @property {string} [classicAddress] Set only when the sender is an XRP X-address: the classic address behind it.
 */

/**
 * @typedef {Object} GetTransactionRequestDetailsResult data.item of getTransactionRequestDetails.
 * @property {string} [amountUnit] The unit of the amount, for example XRP or USDT.
 * @property {string} [blockchain] The blockchain of the transaction, for example `ethereum` or `xrp`.
 * @property {string} [feePriority] The fee priority of the request: `slow`, `standard` or `fast`.
 * @property {string} [network] The network of the blockchain: `mainnet`, or a test network such as `testnet`, `sepolia` or `nile`.
 * @property {string} [note] The free-text note given when the request was created.
 * @property {Array<GetTransactionRequestDetailsRecipient>} [recipients] The recipients and the amount each receives. Account-based blockchains such as Ethereum have exactly one recipient.
 * @property {GetTransactionRequestDetailsSenders} [senders] The sender of the transaction.
 * @property {string} [totalTransactionAmount] The total amount the request sends to all recipients.
 * @property {string} [transactionId] The ID of the transaction on the blockchain (the transaction hash on account-based blockchains). It is set once the transaction exists.
 * @property {string} [transactionRequestStatus] Where the request stands, for example `await-approval`, `pending-signing`, `broadcasted`, `mined`, `failed` or `rejected`.
 * @property {string} [transactionType] The kind of transfer: `coin` for the blockchain's native coin, `token` for a token.
 * @property {string} [vaultAccountId] The ID of the Vault Account that sends the funds.
 * @property {string} [vaultId] The ID of the Vault that sends the funds.
 */

/**
 * @typedef {Object} ListUtxosParams The params of listUtxos: List UTXOs.
 * @property {string} [address] The address that received the UTXO. As a query parameter, it returns only the UTXOs of that address.
 * @property {string} [assetId] The ID of the asset of the UTXO. As a query parameter, it returns only the UTXOs of that asset.
 * @property {boolean} [isSpent] Whether the UTXO has been spent (`true`) or is still unspent (`false`). As a query parameter, it filters by spend status and defaults to `false`.
 * @property {number} [limit] How many UTXOs to return on one page.
 * @property {string} [startingAfter] The `utxoId` of the last UTXO of the previous page. The page starts after it.
 * @property {string} [vaultAccountId] The ID of the Vault Account that owns the UTXO. As a query parameter, it returns only the UTXOs of that Vault Account.
 * @property {string} vaultId The ID of the Vault whose UTXOs to list.
 */

/**
 * @typedef {Object} ListUtxosValue The value of the UTXO.
 * @property {string} [amount] The amount the UTXO holds.
 * @property {string} [assetUnit] The unit of the amount, for example BTC or LTC.
 */

/**
 * @typedef {Object} ListUtxosResult One item of a page of listUtxos.
 * @property {string} [address] The address that received the UTXO. As a query parameter, it returns only the UTXOs of that address.
 * @property {string} [assetId] The ID of the asset of the UTXO. As a query parameter, it returns only the UTXOs of that asset.
 * @property {number} [createdTimestamp] When the UTXO was created or confirmed, as a Unix timestamp in milliseconds.
 * @property {string} [index] The position of the output within that transaction.
 * @property {boolean} [isSpent] Whether the UTXO has been spent (`true`) or is still unspent (`false`). As a query parameter, it filters by spend status and defaults to `false`.
 * @property {string} [transactionId] The hash of the blockchain transaction that created the UTXO.
 * @property {string} [utxoId] The ID of the UTXO in Vaultody. Pass it in `senders` to spend this UTXO, or as `startingAfter` to get the next page.
 * @property {ListUtxosValue} [value] The value of the UTXO.
 * @property {string} [vaultAccountId] The ID of the Vault Account that owns the UTXO. As a query parameter, it returns only the UTXOs of that Vault Account.
 */

/**
 * @typedef {Object} ValidateUtxoTransferRecipientInput
 * @property {string} address The recipient's address.
 * @property {string} amount The amount the recipient receives, in the coin's own unit, for example BTC.
 */

/**
 * @typedef {Object} ValidateUtxoTransferParams The params of validateUtxoTransfer: Validate UTXO Transfer.
 * @property {string} assetId The ID of the coin to send, on a UTXO-based blockchain.
 * @property {ChangeDataInput} [changeData] Optional. Where the change goes: the amount left from the spent UTXOs after the recipients and the fee are paid. Cannot be combined with `feePayer`.
 * @property {string} [feePayer] Optional. An address of the Vault, on the same blockchain as the senders, that adds an input to cover the fee and receives the change. Cannot be combined with `changeData` or `gross`.
 * @property {string} feePriority How fast the transaction should confirm: `slow`, `standard` or `fast`.
 * @property {boolean} [gross] When `true`, the recipient amounts include the fee, so the fee is deducted from them. Cannot be combined with `feePayer`.
 * @property {string} [maxFee] The highest fee you accept. If the fee is higher, the transfer fails with `MAX_FEE_EXCEEDED`.
 * @property {string} [note] A short free-text description of the transfer, at most 250 characters.
 * @property {Array<ValidateUtxoTransferRecipientInput>} recipients The recipients of the transfer: 1 to 150, each with an address and an amount.
 * @property {Array<UtxoSenderInput>} senders In the request, the UTXOs to spend: 1 to 150, from one or more Vault Accounts of the same Vault. In the response, each UTXO resolved, with its address, amount and Vault Account.
 * @property {string} vaultId The ID of the Vault that holds the UTXOs.
 */

/**
 * @typedef {Object} ValidateUtxoTransferRecipient
 * @property {string} [address] The recipient's address.
 * @property {string} [amount] The amount the recipient receives, in the coin's own unit, for example BTC.
 */

/**
 * @typedef {Object} ValidateUtxoTransferSender
 * @property {string} [address] The address that holds the UTXO.
 * @property {string} [addressLabel] The label of that address, if it has one.
 * @property {string} [amount] The amount the UTXO holds, in the coin's own unit.
 * @property {string} [utxoId] The ID of a UTXO to spend, as returned by List UTXOs.
 * @property {string} [vaultAccountId] The ID of the Vault Account that owns the UTXO. It tells the Vault Accounts apart when the inputs come from several of them.
 */

/**
 * @typedef {Object} ValidateUtxoTransferResult data.item of validateUtxoTransfer.
 * @property {string} [error] Why the transfer would fail, for example `MAX_FEE_EXCEEDED`. Empty when it would succeed.
 * @property {string} [feeInNative] The calculated fee, in the coin's own unit.
 * @property {string} [inputAmount] The total amount of the inputs.
 * @property {string} [inputSize] The size of the inputs, in virtual bytes.
 * @property {string} [outputAmount] The total amount of the outputs, recipients and change included.
 * @property {string} [outputSize] The size of the outputs, in virtual bytes.
 * @property {Array<ValidateUtxoTransferRecipient>} [recipients] The recipients of the transfer: 1 to 150, each with an address and an amount.
 * @property {boolean} [recipientsValid] `true` when every recipient is valid.
 * @property {Array<ValidateUtxoTransferSender>} [senders] In the request, the UTXOs to spend: 1 to 150, from one or more Vault Accounts of the same Vault. In the response, each UTXO resolved, with its address, amount and Vault Account.
 * @property {boolean} [sendersValid] `true` when every sender UTXO is valid and can be spent.
 * @property {string} [size] The size of the whole transaction, in virtual bytes.
 */

class Transactions {
    #invoke;

    /** @param {function(string, Object, Object): Promise<Object>} invoke the client's call */
    constructor(invoke) {
        this.#invoke = invoke;
    }

    /**
     * Create Single Transfer: `POST /vaults/{vaultId}/transaction-requests/single-transfer`.
     *
     * A write: never sent again with a new signature once it may have reached the API; when its outcome
     * can't be learned, RequestOutcomeUnknownError.
     *
     * @param {CreateSingleTransferParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<CreateSingleTransferResult>>}
     */
    createSingleTransfer(params, options) {
        return this.#invoke('createSingleTransfer', params, options);
    }

    /**
     * Create Multiple Transfer: `POST /vaults/{vaultId}/transaction-requests/multiple-transfer`.
     *
     * A write: never sent again with a new signature once it may have reached the API; when its outcome
     * can't be learned, RequestOutcomeUnknownError.
     *
     * @param {CreateMultipleTransferParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<CreateMultipleTransferResult>>}
     */
    createMultipleTransfer(params, options) {
        return this.#invoke('createMultipleTransfer', params, options);
    }

    /**
     * Create UTXO Transfer: `POST /vaults/{vaultId}/transaction-requests/utxo-transfer`.
     *
     * A write: never sent again with a new signature once it may have reached the API; when its outcome
     * can't be learned, RequestOutcomeUnknownError.
     *
     * @param {CreateUtxoTransferParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<CreateUtxoTransferResult>>}
     */
    createUtxoTransfer(params, options) {
        return this.#invoke('createUtxoTransfer', params, options);
    }

    /**
     * Validate UTXO Transfer: `POST /vaults/{vaultId}/transaction-requests/utxo-transfer/validate`.
     *
     * Changes nothing, so it is retried like a read.
     *
     * @param {ValidateUtxoTransferParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<ValidateUtxoTransferResult>>}
     */
    validateUtxoTransfer(params, options) {
        return this.#invoke('validateUtxoTransfer', params, options);
    }

    /**
     * Create Batch Transaction Request: `POST /vaults/{vaultId}/transaction-requests/batch`.
     *
     * A write: never sent again with a new signature once it may have reached the API; when its outcome
     * can't be learned, RequestOutcomeUnknownError.
     *
     * @param {CreateBatchTransactionRequestParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<CreateBatchTransactionRequestResult>>}
     */
    createBatchTransactionRequest(params, options) {
        return this.#invoke('createBatchTransactionRequest', params, options);
    }

    /**
     * Gas Sponsorship Transfer: `POST /vaults/{vaultId}/transaction-requests/gas-sponsorship-transfer`.
     *
     * A write: never sent again with a new signature once it may have reached the API; when its outcome
     * can't be learned, RequestOutcomeUnknownError.
     *
     * @param {GasSponsorshipTransferParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<GasSponsorshipTransferResult>>}
     */
    gasSponsorshipTransfer(params, options) {
        return this.#invoke('gasSponsorshipTransfer', params, options);
    }

    /**
     * Create Tron Contract Interaction Request: `POST /vaults/{vaultId}/transaction-requests/contract-interaction`.
     *
     * A write: never sent again with a new signature once it may have reached the API; when its outcome
     * can't be learned, RequestOutcomeUnknownError.
     *
     * @param {CreateTronContractInteractionRequestParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<CreateTronContractInteractionRequestResult>>}
     */
    createTronContractInteractionRequest(params, options) {
        return this.#invoke('createTronContractInteractionRequest', params, options);
    }

    /**
     * Estimate Transaction Fee by Asset ID: `POST /vaults/{vaultId}/approximate-fee`.
     *
     * Changes nothing, so it is retried like a read.
     *
     * @param {EstimateTransactionFeeByAssetIdParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<EstimateTransactionFeeByAssetIdResult>>}
     */
    estimateTransactionFeeByAssetId(params, options) {
        return this.#invoke('estimateTransactionFeeByAssetId', params, options);
    }

    /**
     * Get Transaction Details: `GET /vaults/{vaultId}/{blockchain}/transactions/{transactionId}`.
     *
     * @param {GetTransactionDetailsParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<GetTransactionDetailsResult>>}
     */
    getTransactionDetails(params, options) {
        return this.#invoke('getTransactionDetails', params, options);
    }

    /**
     * Get Transaction Request Details: `GET /transaction-requests/{transactionRequestId}`.
     *
     * @param {GetTransactionRequestDetailsParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<GetTransactionRequestDetailsResult>>}
     */
    getTransactionRequestDetails(params, options) {
        return this.#invoke('getTransactionRequestDetails', params, options);
    }

    /**
     * List UTXOs: `GET /vaults/{vaultId}/utxos`.
     *
     * A list: the promise gives the first page; iterating it gives every item, page after page (the next page starts
     * after the last item's `utxoId`).
     *
     * @param {ListUtxosParams} params
     * @param {CallOptions} [options]
     * @returns {import('./common').PageRequest<ListUtxosResult>}
     */
    listUtxos(params, options) {
        return this.#invoke('listUtxos', params, options);
    }
}

module.exports = {
    Transactions: bindOperations(Transactions),
};
