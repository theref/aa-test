/**
 * ERC-1271 × Rhinestone Safe × TACo Signing × Pimlico — EP v0.7
 * ──────────────────────────────────────────────────────────────
 * End-to-end proof that a Rhinestone Safe account can use TACo's
 * threshold signing network (lynx testnet) for UserOp authorization.
 *
 * On-chain architecture:
 *
 *   Safe proxy (Base Sepolia)
 *     ├─ singleton: SafeL2 v1.4.1 (stock)
 *     ├─ fallbackHandler: Safe7579 Adapter V2
 *     └─ modules:
 *          └─ OwnableValidator (owners=[TACo ThresholdSigningMultisig], threshold=1)
 *
 * Signing flow:
 *
 *   1. Pimlico prepares UserOp (gas estimation uses ECDSA-path mock)
 *   2. Client computes standard v0.7 userOpHash
 *   3. Client sends UserOp to TACo lynx nodes via Porter
 *   4. Nodes compute v0.7 hash + eth_sign wrapping, sign with threshold ECDSA
 *   5. Client wraps aggregated signature in Safe v=0 contract-sig format
 *   6. Pimlico submits to Base Sepolia
 *
 * Key insight: OwnableValidator applies eth_sign wrapping before calling
 * isValidSignature on the 1271 contract. TACo's '0.7.0' aaVersion also
 * applies EIP-191 wrapping (sign_message_eip191), so the hashes match.
 *
 * Usage: npm run rhinestone-taco-test
 */

import "dotenv/config";
import {
  createPublicClient,
  createWalletClient,
  http,
  type Address,
  type Chain,
  type Hex,
  type LocalAccount,
  concat,
  concatHex,
  encodeFunctionData,
  encodeAbiParameters,
  getAddress,
  hashMessage,
  pad,
  parseEther,
  toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia, sepolia } from "viem/chains";
import {
  createBundlerClient,
  createPaymasterClient,
  entryPoint07Address,
  getUserOperationHash,
  toSmartAccount,
} from "viem/account-abstraction";
import { RhinestoneSDK } from "@rhinestone/sdk";
import { ethers } from "ethers";
import { createRequire } from "module";
const require = createRequire(import.meta.url);
const { initialize, signUserOp } = require("@nucypher/taco") as typeof import("@nucypher/taco");
type UserOperationToSign = {
  sender: `0x${string}`;
  nonce: bigint | number;
  callData: `0x${string}` | Uint8Array;
  callGasLimit: bigint | number;
  verificationGasLimit: bigint | number;
  preVerificationGas: bigint | number;
  maxFeePerGas: bigint | number;
  maxPriorityFeePerGas: bigint | number;
  factory?: `0x${string}`;
  factoryData?: `0x${string}` | Uint8Array;
  paymaster?: `0x${string}`;
  paymasterVerificationGasLimit?: bigint | number;
  paymasterPostOpGasLimit?: bigint | number;
  paymasterData?: `0x${string}` | Uint8Array;
  signature?: `0x${string}` | Uint8Array;
};

// ───────────────────────────────────────────────────────────────────────────────
// Config
// ───────────────────────────────────────────────────────────────────────────────

const env = (key: string): string => {
  const v = process.env[key];
  if (!v) throw new Error(`Missing env var: ${key}`);
  return v;
};

const hexEnv = (key: string): Hex => {
  const v = env(key);
  return (v.startsWith("0x") ? v : `0x${v}`) as Hex;
};

// Base Sepolia for the Safe + UserOp
const CHAIN: Chain = baseSepolia;
const RPC_URL = "https://sepolia.base.org";
const PIMLICO_KEY = env("PIMLICO_API_KEY");
const BUNDLER_URL = `https://api.pimlico.io/v2/${CHAIN.id}/rpc?apikey=${PIMLICO_KEY}`;

// TACo cohort 1 ThresholdSigningMultisig on Base Sepolia
const TACO_MULTISIG: Address = getAddress("0xDdBb4c470C7BFFC97345A403aC7FcA77844681D9");

// TACo config
const TACO_DOMAIN = "lynx";
const TACO_COHORT_ID = 1;

// Sepolia provider for reading the SigningCoordinator contract
const COORDINATOR_RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com";

// Funder key (needs Base Sepolia ETH)
const funder = privateKeyToAccount(hexEnv("FUNDER_PRIVATE_KEY"));

// Rhinestone OwnableValidator module address
const OWNABLE_VALIDATOR: Address = "0x000000000013fdB5234E4E3162a810F54d9f7E98";

// Default Rhinestone mock signature for gas estimation.
// Must use ECDSA-path (v=27/28) so gas estimation doesn't revert.
const MOCK_ECDSA_SIG: Hex =
  "0x81d4b4981670cb18f99f0b4a66446df1bf5b204d24cfcb659bf38ba27a4359b5711649ec2423c5e1247245eba2964679b6a1dbb85c992ae40b9b00c6935b02ff1b";

// ───────────────────────────────────────────────────────────────────────────────
// Signing helpers
// ───────────────────────────────────────────────────────────────────────────────

/**
 * Wrap a signature as a Safe-style v=0 contract signature.
 * When CheckNSignatures sees v=0, it calls IERC1271(r).isValidSignature(hash, data).
 *
 *   static (65 bytes): [r=signer_addr padded to 32] [s=65, offset] [v=0]
 *   dynamic:           [uint256 length] [signature bytes]
 */
const wrapAsContractSig = (signer: Address, innerSig: Hex): Hex =>
  concat([
    pad(signer as Hex, { size: 32 }),                            // r
    pad(toHex(65n), { size: 32 }),                               // s = offset to dynamic
    "0x00",                                                       // v = contract sig
    pad(toHex(BigInt((innerSig.length - 2) / 2)), { size: 32 }), // length
    innerSig,                                                     // data
  ]);

// ───────────────────────────────────────────────────────────────────────────────
// ERC-7579 execute() encoding
// ───────────────────────────────────────────────────────────────────────────────

const EXECUTE_ABI = [{
  type: "function",
  name: "execute",
  inputs: [
    { name: "execMode", type: "bytes32" },
    { name: "executionCalldata", type: "bytes" },
  ],
  outputs: [],
  stateMutability: "payable",
}] as const;

const SINGLE_CALL_MODE: Hex = pad("0x00", { size: 32, dir: "right" });
const BATCH_CALL_MODE: Hex = pad("0x01", { size: 32, dir: "right" });

const encode7579Calls = (calls: Array<{ to: Address; value?: bigint; data?: Hex }>): Hex => {
  if (calls.length === 1) {
    const c = calls[0];
    return encodeFunctionData({
      abi: EXECUTE_ABI,
      functionName: "execute",
      args: [
        SINGLE_CALL_MODE,
        concatHex([c.to, toHex(c.value ?? 0n, { size: 32 }), c.data ?? "0x"]),
      ],
    });
  }
  return encodeFunctionData({
    abi: EXECUTE_ABI,
    functionName: "execute",
    args: [
      BATCH_CALL_MODE,
      encodeAbiParameters(
        [{
          name: "executionBatch",
          type: "tuple[]",
          components: [
            { name: "target", type: "address" },
            { name: "value", type: "uint256" },
            { name: "callData", type: "bytes" },
          ],
        }],
        [calls.map((c) => ({ target: c.to, value: c.value ?? 0n, callData: c.data ?? "0x" }))]
      ),
    ],
  });
};

// ───────────────────────────────────────────────────────────────────────────────
// Convert viem UserOp params to TACo UserOperationToSign
// ───────────────────────────────────────────────────────────────────────────────

function viemParamsToTacoUserOp(params: any, sender: Address): UserOperationToSign {
  return {
    sender,
    nonce: BigInt(params.nonce),
    callData: params.callData as `0x${string}`,
    callGasLimit: BigInt(params.callGasLimit),
    verificationGasLimit: BigInt(params.verificationGasLimit),
    preVerificationGas: BigInt(params.preVerificationGas),
    maxFeePerGas: BigInt(params.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(params.maxPriorityFeePerGas),
    factory: params.factory as `0x${string}` | undefined,
    factoryData: params.factoryData as `0x${string}` | undefined,
    paymaster: params.paymaster as `0x${string}` | undefined,
    paymasterVerificationGasLimit: params.paymasterVerificationGasLimit
      ? BigInt(params.paymasterVerificationGasLimit) : undefined,
    paymasterPostOpGasLimit: params.paymasterPostOpGasLimit
      ? BigInt(params.paymasterPostOpGasLimit) : undefined,
    paymasterData: params.paymasterData as `0x${string}` | undefined,
    signature: "0x",
  };
}

// ───────────────────────────────────────────────────────────────────────────────
// Main
// ───────────────────────────────────────────────────────────────────────────────

async function main() {
  console.log("\n══════════════════════════════════════════════════");
  console.log("  ERC-1271 × Rhinestone Safe × TACo × Pimlico");
  console.log("══════════════════════════════════════════════════");
  console.log(`  Chain            : ${CHAIN.name} (${CHAIN.id})`);
  console.log(`  TACo multisig    : ${TACO_MULTISIG}`);
  console.log(`  TACo domain      : ${TACO_DOMAIN}`);
  console.log(`  TACo cohort      : ${TACO_COHORT_ID}`);
  console.log(`  OwnableValidator : ${OWNABLE_VALIDATOR}`);
  console.log("══════════════════════════════════════════════════\n");

  // Initialize TACo WASM
  console.log("Initializing TACo...");
  await initialize();

  // Ethers provider for SigningCoordinator reads (lives on Sepolia)
  const ethersProvider = new ethers.providers.JsonRpcProvider(COORDINATOR_RPC_URL);

  const publicClient = createPublicClient({ chain: CHAIN, transport: http(RPC_URL) });
  const bundlerClient = createBundlerClient({
    client: publicClient,
    chain: CHAIN,
    transport: http(BUNDLER_URL),
    // Paymaster disabled — ECDSA stub sig underestimates verification gas
    // for the contract signature path (v=0 → isValidSignature external call).
    // Safe pays gas from its own balance instead.
    userOperation: {
      estimateFeesPerGas: async () => {
        const resp = await fetch(BUNDLER_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0", id: 1,
            method: "pimlico_getUserOperationGasPrice",
            params: [],
          }),
        });
        const { result } = (await resp.json()) as any;
        return {
          maxFeePerGas: BigInt(result.fast.maxFeePerGas),
          maxPriorityFeePerGas: BigInt(result.fast.maxPriorityFeePerGas),
        };
      },
    },
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 1. Create the Rhinestone account with TACo multisig as owner
  // ──────────────────────────────────────────────────────────────────────────

  const ownerAsAccount = {
    type: "local" as const,
    address: TACO_MULTISIG,
    source: "custom" as const,
    publicKey: "0x04" as Hex,
    signMessage: async () => "0x" as Hex,
    signTypedData: async () => "0x" as Hex,
    signTransaction: async () => "0x" as Hex,
  } satisfies Partial<LocalAccount> as unknown as LocalAccount;

  const rhinestone = new RhinestoneSDK({
    apiKey: "not-needed-for-address-computation",
    bundler: { type: "pimlico", apiKey: PIMLICO_KEY },
    paymaster: { type: "pimlico", apiKey: PIMLICO_KEY },
  });

  const rhAccount = await rhinestone.createAccount({
    account: { type: "safe" },
    owners: { type: "ecdsa", accounts: [ownerAsAccount], threshold: 1 },
  });

  const accountAddress = rhAccount.getAddress();
  const initData = rhAccount.getInitData();
  console.log(`Safe address: ${accountAddress}`);

  // ──────────────────────────────────────────────────────────────────────────
  // 2. Fund the Safe
  // ──────────────────────────────────────────────────────────────────────────

  const balance = await publicClient.getBalance({ address: accountAddress });
  console.log(`Safe balance: ${balance} wei`);
  if (balance < parseEther("0.0001")) {
    console.log(`Funding Safe with 0.001 ETH from ${funder.address}...`);
    const walletClient = createWalletClient({ account: funder, chain: CHAIN, transport: http(RPC_URL) });
    const tx = await walletClient.sendTransaction({ to: accountAddress, value: parseEther("0.001") });
    await publicClient.waitForTransactionReceipt({ hash: tx });
    console.log(`Funded: ${tx}`);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // 3. Build viem smart account with TACo signing
  // ──────────────────────────────────────────────────────────────────────────

  const isDeployed = async () => {
    const code = await publicClient.getCode({ address: accountAddress });
    return !!code && code !== "0x";
  };

  const smartAccount = await toSmartAccount({
    client: publicClient,
    entryPoint: { abi: [] as any, address: entryPoint07Address, version: "0.7" },

    async getAddress() { return accountAddress; },

    async getFactoryArgs() {
      return (await isDeployed())
        ? {}
        : { factory: initData.factory, factoryData: initData.factoryData };
    },

    async getNonce() {
      const key = concat([OWNABLE_VALIDATOR, "0x00000000"]) as Hex;
      return publicClient.readContract({
        address: entryPoint07Address,
        abi: [{
          name: "getNonce",
          type: "function",
          stateMutability: "view",
          inputs: [{ type: "address" }, { type: "uint192" }],
          outputs: [{ type: "uint256" }],
        }],
        functionName: "getNonce",
        args: [accountAddress, BigInt(key)],
      });
    },

    async encodeCalls(calls) {
      return encode7579Calls(calls as any);
    },

    async getStubSignature() {
      return MOCK_ECDSA_SIG;
    },

    async signUserOperation(params: any) {
      // Compute the standard v0.7 userOpHash for logging
      const userOpHash = getUserOperationHash({
        userOperation: { ...params, sender: accountAddress, signature: "0x" },
        entryPointAddress: entryPoint07Address,
        entryPointVersion: "0.7",
        chainId: params.chainId ?? CHAIN.id,
      });
      console.log(`\nuserOpHash (v0.7): ${userOpHash}`);
      console.log(`ethSignedHash:     ${hashMessage({ raw: userOpHash })}`);

      // Convert viem params to TACo UserOperationToSign format
      const tacoUserOp = viemParamsToTacoUserOp(params, accountAddress);

      console.log(`\nSending to TACo ${TACO_DOMAIN} cohort ${TACO_COHORT_ID}...`);

      // Call TACo threshold signing network
      const signResult = await signUserOp(
        ethersProvider,
        TACO_DOMAIN as any,
        TACO_COHORT_ID,
        CHAIN.id,           // Base Sepolia chain ID for hash computation
        tacoUserOp,
        "0.7.0",
        undefined,           // No condition context for now
      );

      console.log(`TACo messageHash:  ${signResult.messageHash}`);
      console.log(`TaCo signers:      ${Object.keys(signResult.signingResults).length}`);
      Object.entries(signResult.signingResults).forEach(([ursula, sig]) =>
        console.log(`  ${ursula}: ${sig.signerAddress} -> ${sig.signature.slice(0, 20)}...`));

      // Wrap TaCo's aggregated signature in Safe v=0 contract-sig format
      return wrapAsContractSig(TACO_MULTISIG, signResult.aggregatedSignature as Hex);
    },

    async signMessage() { throw new Error("not used"); },
    async signTypedData() { throw new Error("not used"); },
    async decodeCalls() { throw new Error("not implemented"); },
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 4. Send a UserOp (1 wei transfer)
  // ──────────────────────────────────────────────────────────────────────────

  console.log(`\nSending 1 wei from Safe to ${funder.address}...`);

  // Override verificationGasLimit: the ECDSA mock sig used during estimation
  // produces a much lower gas figure than the real contract sig path
  // (v=0 → external call to isValidSignature on the 1271 contract).
  const userOpHash = await bundlerClient.sendUserOperation({
    account: smartAccount,
    calls: [{ to: funder.address, value: 1n, data: "0x" }],
    verificationGasLimit: 500_000n,
  });
  console.log(`UserOp hash: ${userOpHash}`);

  const receipt = await bundlerClient.waitForUserOperationReceipt({
    hash: userOpHash,
    timeout: 120_000,
  });

  console.log("\n──────────────────────────────────────────────────");
  if (!receipt.success) {
    console.error(`UserOp FAILED: ${receipt.reason}`);
    process.exit(1);
  }
  console.log("SUCCESS - Rhinestone Safe + TACo Signing (v0.7.0)");
  console.log(`  Tx hash   : ${receipt.receipt.transactionHash}`);
  console.log(`  Block     : ${receipt.receipt.blockNumber}`);
  console.log(`  Gas used  : ${receipt.receipt.gasUsed}`);
  console.log(`  Safe      : ${accountAddress}`);
  console.log(`  1271 owner: ${TACO_MULTISIG} (TACo cohort ${TACO_COHORT_ID})`);
  console.log("──────────────────────────────────────────────────\n");
}

main().catch((err) => {
  console.error("\n", err);
  process.exit(1);
});
