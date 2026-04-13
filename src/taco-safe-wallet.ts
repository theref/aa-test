/**
 * TACo × Safe (ERC-7579) — User Wallet Deployment
 * ─────────────────────────────────────────────────
 * Creates a Safe smart account owned by a TACo cohort's ThresholdSigningMultisig.
 *
 * Architecture:
 *   Every user gets a Safe whose sole owner is the SAME 1271 contract.
 *   Unique wallet addresses come from different saltNonce values.
 *   Cohort rotation = one on-chain tx to update the 1271 contract → all wallets update.
 *
 * Requirements:
 *   - Safe v1.5.0 (v1.4.1 has issues with contract signature validation)
 *   - EntryPoint v0.7
 *   - Pimlico bundler (private RPC bypasses EIP-7562 global storage restrictions)
 *
 * To integrate with real TACo signing:
 *   Replace the local EOA signing in `signThresholdSignature` with
 *   signUserOp() from @nucypher/taco. TACo will need a new aaVersion
 *   for Safe's EIP-712 SafeOp hash format.
 *
 * Usage:
 *   cp .env.example .env   # fill in values
 *   npm install && npm run taco-safe
 */

import "dotenv/config";
import {
  createPublicClient,
  createWalletClient,
  http,
  type Address,
  type Hex,
  type Chain,
  concat,
  concatHex,
  getAddress,
  hashTypedData,
  encodePacked,
  parseEther,
  toHex,
  pad,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
import type { LocalAccount } from "viem";
import { createSmartAccountClient } from "permissionless";
import { toSafeSmartAccount } from "permissionless/accounts";
import { createPimlicoClient } from "permissionless/clients/pimlico";

// ─── Constants ──────────────────────────────────────────────────────────────────

const ENTRY_POINT_V07: Address = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const SAFE_4337_MODULE: Address = "0x75cf11467937ce3F2f357CE24ffc3DBF8fD5c226";

/** SafeOp EIP-712 types — must match Safe4337Module's on-chain SAFE_OP_TYPEHASH */
const SAFE_OP_TYPES = {
  SafeOp: [
    { type: "address", name: "safe" },
    { type: "uint256", name: "nonce" },
    { type: "bytes", name: "initCode" },
    { type: "bytes", name: "callData" },
    { type: "uint128", name: "verificationGasLimit" },
    { type: "uint128", name: "callGasLimit" },
    { type: "uint256", name: "preVerificationGas" },
    { type: "uint128", name: "maxPriorityFeePerGas" },
    { type: "uint128", name: "maxFeePerGas" },
    { type: "bytes", name: "paymasterAndData" },
    { type: "uint48", name: "validAfter" },
    { type: "uint48", name: "validUntil" },
    { type: "address", name: "entryPoint" },
  ],
} as const;

// ─── Safe contract signature encoding ───────────────────────────────────────────
//
// Safe's checkNSignatures supports v=0 (contract signature / ERC-1271):
//   Static part (65 bytes):  {32-byte signer address} {32-byte offset} {0x00}
//   Dynamic part:            {32-byte length} {signature data}
//
// Safe calls: IERC1271(signer).isValidSignature(safeOpHash, signatureData)

function encodeSafeContractSignature(signer: Address, sigData: Hex): Hex {
  return concat([
    pad(signer as Hex, { size: 32 }),             // r: signer address
    pad(toHex(65n), { size: 32 }),                 // s: offset to dynamic part
    "0x00",                                        // v: contract signature type
    pad(toHex(BigInt((sigData.length - 2) / 2)), { size: 32 }), // length
    sigData,                                       // the actual threshold signature
  ]);
}

// ─── Threshold signature encoding ───────────────────────────────────────────────
// Sort by signer address ascending, concatenate raw 65-byte ECDSA signatures.
// Must match ThresholdSigningMultisig's expected format.

function encodeMultiSigSignature(
  sigs: { address: Address; sig: Hex }[]
): Hex {
  const sorted = [...sigs].sort((a, b) =>
    a.address.toLowerCase().localeCompare(b.address.toLowerCase())
  );
  return concat(sorted.map(({ sig }) => sig));
}

// ─── Config from env ────────────────────────────────────────────────────────────

function requireEnv(key: string): string {
  const v = process.env[key];
  if (!v) throw new Error(`Missing env var: ${key}`);
  return v;
}

function ensureHexPrefix(key: string): Hex {
  const v = requireEnv(key);
  return (v.startsWith("0x") ? v : `0x${v}`) as Hex;
}

// ─── createTacoSafeWallet ───────────────────────────────────────────────────────

interface TacoSafeConfig {
  rpcUrl: string;
  pimlicoApiKey: string;
  chain: Chain;
  /** Address of the TACo ThresholdSigningMultisig (ERC-1271).
   *  Same for ALL user wallets. */
  tacoMultisigAddress: Address;
  /** Number of 65-byte ECDSA sigs in the threshold signature (= cohort threshold). */
  cohortThreshold: number;
  /** Signs a hash with the TACo cohort. Returns concatenated sorted ECDSA sigs.
   *  In production: replace with signUserOp() from @nucypher/taco. */
  signThresholdSignature: (hash: Hex) => Promise<Hex>;
}

async function createTacoSafeWallet(config: TacoSafeConfig, userId: string) {
  const {
    rpcUrl, pimlicoApiKey, chain,
    tacoMultisigAddress, cohortThreshold,
    signThresholdSignature,
  } = config;

  const bundlerUrl = `https://api.pimlico.io/v2/${chain.name.toLowerCase()}/rpc?apikey=${pimlicoApiKey}`;

  const publicClient = createPublicClient({ chain, transport: http(rpcUrl) });
  const bundlerClient = createPimlicoClient({
    transport: http(bundlerUrl),
    entryPoint: { address: ENTRY_POINT_V07, version: "0.7" },
  });

  // Fake LocalAccount whose address = the 1271 contract.
  // permissionless.js uses this to set the Safe's owner.
  const tacoOwner = {
    type: "local" as const,
    address: tacoMultisigAddress,
    source: "custom" as const,
    publicKey: "0x04" as Hex,
    async signMessage(): Promise<Hex> { throw new Error("Use signUserOperation"); },
    async signTypedData(): Promise<Hex> { throw new Error("Use signUserOperation"); },
    async signTransaction(): Promise<Hex> { throw new Error("Not supported"); },
  };

  // Deterministic address from userId
  const saltNonce = BigInt("0x" + Buffer.from(userId).toString("hex"));

  const safeAccount = await toSafeSmartAccount({
    client: publicClient,
    owners: [tacoOwner as unknown as LocalAccount],
    threshold: 1n,
    version: "1.5.0", // Must be 1.5.0 — v1.4.1 has contract sig issues
    entryPoint: { address: ENTRY_POINT_V07, version: "0.7" },
    saltNonce,
  });

  // ── Stub signature for gas estimation ───────────────────────────────────────

  safeAccount.getStubSignature = async () => {
    const dummySigs = concat(
      Array.from({ length: cohortThreshold }, () =>
        "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c" as Hex
      )
    );
    const contractSig = encodeSafeContractSignature(tacoMultisigAddress, dummySigs);
    return encodePacked(["uint48", "uint48", "bytes"], [0, 0, contractSig]);
  };

  // ── Sign UserOps with TACo cohort ───────────────────────────────────────────

  safeAccount.signUserOperation = async (params: any) => {
    const chainId = params.chainId ?? chain.id;

    // Build SafeOp EIP-712 message from the UserOp
    const message: Record<string, any> = {
      safe: params.sender,
      nonce: params.nonce,
      initCode: params.factory && params.factoryData
        ? concatHex([params.factory, params.factoryData])
        : "0x",
      callData: params.callData,
      verificationGasLimit: params.verificationGasLimit,
      callGasLimit: params.callGasLimit,
      preVerificationGas: params.preVerificationGas,
      maxPriorityFeePerGas: params.maxPriorityFeePerGas,
      maxFeePerGas: params.maxFeePerGas,
      paymasterAndData: params.paymaster
        ? concat([
            params.paymaster,
            pad(toHex(BigInt(params.paymasterVerificationGasLimit || 0)), { size: 16 }),
            pad(toHex(BigInt(params.paymasterPostOpGasLimit || 0)), { size: 16 }),
            (params.paymasterData as Hex) || "0x",
          ])
        : "0x",
      validAfter: 0,
      validUntil: 0,
      entryPoint: ENTRY_POINT_V07,
    };

    // Hash — same EIP-712 hash Safe's module computes on-chain
    const safeOpHash = hashTypedData({
      domain: { chainId: BigInt(chainId), verifyingContract: SAFE_4337_MODULE },
      types: SAFE_OP_TYPES,
      primaryType: "SafeOp",
      message,
    });

    // Sign with TACo cohort
    const thresholdSig = await signThresholdSignature(safeOpHash);

    // Wrap in Safe contract signature (v=0) + validAfter/validUntil
    const contractSig = encodeSafeContractSignature(tacoMultisigAddress, thresholdSig);
    return encodePacked(["uint48", "uint48", "bytes"], [0, 0, contractSig]);
  };

  // ── Smart account client ────────────────────────────────────────────────────

  const client = createSmartAccountClient({
    account: safeAccount,
    bundlerTransport: http(bundlerUrl),
    paymaster: createPimlicoClient({
      transport: http(bundlerUrl),
      entryPoint: { address: ENTRY_POINT_V07, version: "0.7" },
    }),
    userOperation: {
      estimateFeesPerGas: async () =>
        (await bundlerClient.getUserOperationGasPrice()).fast,
    },
  });

  return { address: safeAccount.address, account: safeAccount, client };
}

// ─── Main — end-to-end test ─────────────────────────────────────────────────────

async function main() {
  const RPC_URL = process.env.ALCHEMY_RPC_URL || "https://ethereum-sepolia-rpc.publicnode.com";
  const PIMLICO_API_KEY = requireEnv("PIMLICO_API_KEY");
  const TACO_MULTISIG = getAddress(requireEnv("ERC1271_CONTRACT_ADDRESS"));

  // Local EOA keys simulating TACo cohort threshold signers
  const signer1 = privateKeyToAccount(ensureHexPrefix("SIGNER1_PRIVATE_KEY"));
  const signer2 = privateKeyToAccount(ensureHexPrefix("SIGNER2_PRIVATE_KEY"));
  const allSigners = [signer1, signer2];

  console.log("\n══════════════════════════════════════════════════");
  console.log("  TACo × Safe (7579) — End-to-End Test");
  console.log("══════════════════════════════════════════════════");
  console.log(`  Chain          : Sepolia`);
  console.log(`  TACo multisig  : ${TACO_MULTISIG}`);
  console.log(`  Cohort signers : ${allSigners.length}`);
  allSigners.forEach((s, i) => console.log(`    [${i + 1}] ${s.address}`));
  console.log("══════════════════════════════════════════════════\n");

  // ── Create wallet for a user ──────────────────────────────────────────────

  const userId = `test-user-${Date.now()}`;
  console.log(`Creating wallet for "${userId}"…`);

  const wallet = await createTacoSafeWallet(
    {
      rpcUrl: RPC_URL,
      pimlicoApiKey: PIMLICO_API_KEY,
      chain: sepolia,
      tacoMultisigAddress: TACO_MULTISIG,
      cohortThreshold: allSigners.length,
      signThresholdSignature: async (hash: Hex) => {
        console.log(`\n🔐  Signing SafeOp hash: ${hash}`);
        const collected = await Promise.all(
          allSigners.map(async (s) => ({
            address: s.address,
            sig: await s.sign({ hash }),
          }))
        );
        collected.forEach(({ address, sig }, i) =>
          console.log(`    [${i + 1}] ${address}: ${sig.slice(0, 20)}…`)
        );
        return encodeMultiSigSignature(collected);
      },
    },
    userId
  );

  console.log(`📬  Safe address: ${wallet.address}`);

  // ── Fund the Safe so it can send value ─────────────────────────────────────

  const FUNDER_PK = ensureHexPrefix("FUNDER_PRIVATE_KEY");
  const funder = privateKeyToAccount(FUNDER_PK);
  console.log(`\n💰  Funder: ${funder.address}`);

  const publicClient = createPublicClient({ chain: sepolia, transport: http(RPC_URL) });
  const safeBalance = await publicClient.getBalance({ address: wallet.address });
  console.log(`    Safe balance: ${safeBalance} wei`);

  if (safeBalance < parseEther("0.0001")) {
    console.log("    Funding Safe with 0.001 ETH…");
    const walletClient = createWalletClient({
      account: funder,
      chain: sepolia,
      transport: http(RPC_URL),
    });
    const fundTx = await walletClient.sendTransaction({
      to: wallet.address,
      value: parseEther("0.001"),
    });
    console.log(`    Funding tx: ${fundTx}`);
    await publicClient.waitForTransactionReceipt({ hash: fundTx });
    console.log("    Funded ✓");
  }

  // ── Send 1 wei to the funder address ───────────────────────────────────────

  console.log(`\n🚀  Sending UserOp (1 wei to 0x3B42…c600)…`);

  let userOpHash: Hex;
  try {
    userOpHash = await wallet.client.sendUserOperation({
      account: wallet.account,
      calls: [{ to: "0x3B42d26E19FF860bC4dEbB920DD8caA53F93c600" as Address, value: 1n, data: "0x" }],
    });
    console.log(`    UserOp hash: ${userOpHash}`);
  } catch (err) {
    console.error("\n❌  Failed to submit UserOp:");
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  }

  // ── Wait for on-chain confirmation ──────────────────────────────────────────

  console.log("\n⏳  Waiting for on-chain confirmation (up to 2 min)…");

  const bundlerUrl = `https://api.pimlico.io/v2/sepolia/rpc?apikey=${PIMLICO_API_KEY}`;
  const bundlerClient = createPimlicoClient({
    transport: http(bundlerUrl),
    entryPoint: { address: "0x0000000071727De22E5E9d8BAf0edAc6f37da032", version: "0.7" },
  });

  try {
    const receipt = await bundlerClient.waitForUserOperationReceipt({
      hash: userOpHash,
      timeout: 120_000,
    });

    console.log("\n──────────────────────────────────────────────────");
    if (receipt.success) {
      console.log("🎉  SUCCESS — UserOp confirmed on-chain");
      console.log(`    Tx hash  : ${receipt.receipt.transactionHash}`);
      console.log(`    Block    : ${receipt.receipt.blockNumber}`);
      console.log(`    Gas used : ${receipt.receipt.gasUsed}`);
      console.log(`\n    Safe     : ${wallet.address}`);
      console.log(`    Owner    : ${TACO_MULTISIG} (shared 1271 contract)`);
      console.log(`    User     : ${userId}`);
    } else {
      console.error("💥  UserOp FAILED on-chain");
      console.error(`    Reason: ${receipt.reason}`);
      process.exit(1);
    }
    console.log("──────────────────────────────────────────────────\n");
  } catch (err) {
    console.error("\n❌  Receipt error:", err instanceof Error ? err.message : err);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("\n💀  Unhandled:", err);
  process.exit(1);
});
