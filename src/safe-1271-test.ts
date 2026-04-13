/**
 * ERC-1271 × Safe (7579) × Pimlico — EP v0.7
 * ─────────────────────────────────────────────
 * Proves: a Safe smart account can use a global ERC-1271 signer contract
 * (ThresholdSigningMultisig) as its owner. All Safe wallets share the same
 * 1271 contract — cohort rotation = one on-chain tx, all wallets update.
 *
 * Safe natively supports contract signatures (v=0) via checkNSignatures(),
 * which calls owner.isValidSignature(hash, sig) when v == 0.
 *
 * NOTE: Requires Safe v1.5.0 — v1.4.1 has a subtle issue with contract
 * signature validation during first-deploy UserOps on Sepolia.
 *
 * Usage:
 *   npm run safe-test
 */

import "dotenv/config";
import {
  createPublicClient,
  http,
  type Address,
  type Hex,
  concat,
  concatHex,
  getAddress,
  hashTypedData,
  zeroAddress,
  encodePacked,
  toHex,
  pad,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
import type { LocalAccount } from "viem";
import { createSmartAccountClient } from "permissionless";
import { toSafeSmartAccount } from "permissionless/accounts";
import { createPimlicoClient } from "permissionless/clients/pimlico";
import { createPaymasterClient } from "viem/account-abstraction";

// ─── Constants ──────────────────────────────────────────────────────────────────

const ENTRY_POINT_V07: Address =
  "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

// Safe 4337 module for Safe v1.4.1 + EntryPoint v0.7
const SAFE_4337_MODULE: Address =
  "0x75cf11467937ce3F2f357CE24ffc3DBF8fD5c226";

// SafeOp EIP-712 types (v0.7)
const SafeOpTypes = {
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
};

// ─── Config ─────────────────────────────────────────────────────────────────────

function requireEnv(key: string): string {
  const v = process.env[key];
  if (!v) throw new Error(`Missing env var: ${key}`);
  return v;
}

const ALCHEMY_RPC_URL = requireEnv("ALCHEMY_RPC_URL");
const PIMLICO_API_KEY = requireEnv("PIMLICO_API_KEY");
const ERC1271_ADDRESS = getAddress(requireEnv("ERC1271_CONTRACT_ADDRESS"));

function ensureHexPrefix(key: string): Hex {
  const v = requireEnv(key);
  return (v.startsWith("0x") ? v : `0x${v}`) as Hex;
}

const SIGNER1_PK = ensureHexPrefix("SIGNER1_PRIVATE_KEY");
const SIGNER2_PK = ensureHexPrefix("SIGNER2_PRIVATE_KEY");

const chain = sepolia;
const bundlerUrl = `https://api.pimlico.io/v2/${chain.name.toLowerCase()}/rpc?apikey=${PIMLICO_API_KEY}`;

// ─── Multi-sig encoding ─────────────────────────────────────────────────────────
// Sort by address ascending, concatenate raw 65-byte ECDSA signatures.
// Must match ThresholdSigningMultisig's expected format.

function encodeMultiSigSignature(
  sigs: { address: Address; sig: Hex }[]
): Hex {
  const sorted = [...sigs].sort((a, b) =>
    a.address.toLowerCase().localeCompare(b.address.toLowerCase())
  );
  return concat(sorted.map(({ sig }) => sig));
}

// ─── Safe contract signature encoding ───────────────────────────────────────────
//
// Safe's checkNSignatures reads the v byte to determine signature type:
//   v = 0   → contract signature (ERC-1271)
//   v = 1   → pre-approved hash
//   v >= 27 → standard ECDSA
//
// For v=0, the encoding is:
//   Static part (65 bytes):
//     r = signer address, left-padded to 32 bytes
//     s = byte offset to dynamic data (from start of all signatures)
//     v = 0x00
//   Dynamic part (at offset s):
//     uint256 length of contract signature data
//     bytes   contract signature data
//
// Safe calls: IERC1271(signer).isValidSignature(dataHash, contractSignatureData)

function encodeSafeContractSignature(
  signerAddress: Address,
  contractSigData: Hex
): Hex {
  const STATIC_PART_SIZE = 65; // 32 (r) + 32 (s) + 1 (v)

  // Static part
  const r = pad(signerAddress as Hex, { size: 32 });
  const s = pad(toHex(BigInt(STATIC_PART_SIZE)), { size: 32 }); // offset to dynamic part
  const v = "0x00" as Hex;

  // Dynamic part
  const dataLen = (contractSigData.length - 2) / 2;
  const lengthPrefix = pad(toHex(BigInt(dataLen)), { size: 32 });

  return concat([r, s, v, lengthPrefix, contractSigData]);
}

// ─── SafeOp message builder ─────────────────────────────────────────────────────
// Constructs the EIP-712 message from a UserOp (v0.7 unpacked format).

function buildSafeOpMessage(userOp: Record<string, any>): Record<string, any> {
  // initCode: v0.7 uses factory + factoryData, v0.6 uses initCode
  let initCode: Hex = "0x";
  if (userOp.factory && userOp.factoryData) {
    initCode = concatHex([userOp.factory, userOp.factoryData]);
  } else if (userOp.initCode) {
    initCode = userOp.initCode;
  }

  // paymasterAndData: v0.7 has separate paymaster fields
  let paymasterAndData: Hex = "0x";
  if (userOp.paymaster) {
    paymasterAndData = concat([
      userOp.paymaster,
      pad(toHex(userOp.paymasterVerificationGasLimit || 0n), { size: 16 }),
      pad(toHex(userOp.paymasterPostOpGasLimit || 0n), { size: 16 }),
      userOp.paymasterData || "0x",
    ]);
  } else if (userOp.paymasterAndData) {
    paymasterAndData = userOp.paymasterAndData;
  }

  return {
    safe: userOp.sender,
    nonce: userOp.nonce,
    initCode,
    callData: userOp.callData,
    verificationGasLimit: userOp.verificationGasLimit,
    callGasLimit: userOp.callGasLimit,
    preVerificationGas: userOp.preVerificationGas,
    maxPriorityFeePerGas: userOp.maxPriorityFeePerGas,
    maxFeePerGas: userOp.maxFeePerGas,
    paymasterAndData,
    validAfter: 0,
    validUntil: 0,
    entryPoint: ENTRY_POINT_V07,
  };
}

// ─── Main ───────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("\n══════════════════════════════════════════════════");
  console.log("  ERC-1271 × Safe (7579) × Pimlico — EP v0.7");
  console.log("══════════════════════════════════════════════════");

  const signer1 = privateKeyToAccount(SIGNER1_PK);
  const signer2 = privateKeyToAccount(SIGNER2_PK);
  const allSigners = [signer1, signer2];

  console.log(`  Chain       : ${chain.name} (id ${chain.id})`);
  console.log(`  EntryPoint  : ${ENTRY_POINT_V07}`);
  console.log(`  Safe4337Mod : ${SAFE_4337_MODULE}`);
  console.log(`  1271 Owner  : ${ERC1271_ADDRESS}`);
  console.log(`  Signers     : ${allSigners.length}`);
  allSigners.forEach((s, i) => console.log(`    [${i + 1}] ${s.address}`));
  console.log("══════════════════════════════════════════════════\n");

  // ── Clients ─────────────────────────────────────────────────────────────────

  const publicClient = createPublicClient({
    chain,
    transport: http(ALCHEMY_RPC_URL),
  });

  const bundlerClient = createPimlicoClient({
    transport: http(bundlerUrl),
    entryPoint: { address: ENTRY_POINT_V07, version: "0.7" },
  });

  // ── Fake LocalAccount for the ERC-1271 contract ─────────────────────────────
  //
  // permissionless.js's toSafeSmartAccount needs an "owner" that looks like a
  // LocalAccount. We set address = the 1271 contract. The sign* stubs won't
  // be called because we override signUserOperation below.

  // signTypedData receives the EIP-712 params from permissionless.js's Safe
  // signing flow. We compute the hash and sign with threshold keys here.
  // The resulting signature will be further processed by signUserOperation.
  let lastTypedDataHash: Hex = "0x";

  const erc1271Owner = {
    type: "local" as const,
    address: ERC1271_ADDRESS,
    source: "custom" as const,
    publicKey: "0x04" as Hex, // minimal valid prefix
    async signMessage(): Promise<Hex> {
      throw new Error("signMessage: should use signUserOperation override");
    },
    async signTypedData(params: {
      domain: any;
      types: any;
      primaryType: string;
      message: any;
    }): Promise<Hex> {
      // permissionless.js calls this with the SafeOp EIP-712 params.
      // Compute hash and sign with threshold keys.
      console.log("\n🔍  signTypedData called by permissionless.js:");
      console.log(`    domain.chainId: ${params.domain?.chainId}`);
      console.log(`    domain.verifyingContract: ${params.domain?.verifyingContract}`);
      console.log(`    primaryType: ${params.primaryType}`);

      const typedHash = hashTypedData({
        domain: params.domain,
        types: params.types,
        primaryType: params.primaryType,
        message: params.message,
      });
      lastTypedDataHash = typedHash;
      console.log(`    EIP-712 hash: ${typedHash}`);

      // Sign with threshold keys
      const collected = await Promise.all(
        allSigners.map(async (s) => ({
          address: s.address,
          sig: await s.sign({ hash: typedHash }),
        }))
      );
      collected.forEach(({ address, sig }, i) =>
        console.log(`    [${i + 1}] ${address}: ${sig.slice(0, 20)}…`)
      );

      // Return concatenated threshold signature
      return encodeMultiSigSignature(collected);
    },
    async signTransaction(): Promise<Hex> {
      throw new Error("signTransaction: not supported");
    },
  };

  // ── Build Safe account ──────────────────────────────────────────────────────

  console.log("⚙️   Building Safe with ERC-1271 contract owner…");

  const safeAccount = await toSafeSmartAccount({
    client: publicClient,
    owners: [erc1271Owner as unknown as LocalAccount],
    threshold: 1n,
    version: "1.5.0",
    entryPoint: { address: ENTRY_POINT_V07, version: "0.7" },
    saltNonce: 42n,
  });

  console.log(`📬  Safe address: ${safeAccount.address}`);

  // ── Override getStubSignature ───────────────────────────────────────────────
  //
  // The stub signature is used for gas estimation. It must match the format
  // of the real signature (contract sig, v=0) so gas estimates are accurate.

  safeAccount.getStubSignature = async () => {
    // Two dummy 65-byte ECDSA sigs = 130 bytes
    const dummyThresholdSig = concat([
      "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c",
      "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c",
    ]);
    const contractSig = encodeSafeContractSignature(
      ERC1271_ADDRESS,
      dummyThresholdSig
    );
    return encodePacked(["uint48", "uint48", "bytes"], [0, 0, contractSig]);
  };

  // ── Override signUserOperation ──────────────────────────────────────────────
  //
  // Strategy: let permissionless.js's default flow call our signTypedData
  // (which does the threshold signing), then re-encode the result as a
  // Safe contract signature (v=0, dynamic format) instead of EOA format.

  safeAccount.signUserOperation = async (params: any) => {
    const chainId = params.chainId ?? chain.id;

    // permissionless.js's signUserOperation for Safe iterates owners and
    // calls signTypedData on each. We replicate that logic here but with
    // contract signature encoding.

    // Import the SafeOp types from permissionless.js (same as our SafeOpTypes)
    const message: Record<string, any> = {
      safe: params.sender,
      nonce: params.nonce,
      initCode: "0x" as Hex,
      callData: params.callData,
      verificationGasLimit: params.verificationGasLimit,
      callGasLimit: params.callGasLimit,
      preVerificationGas: params.preVerificationGas,
      maxPriorityFeePerGas: params.maxPriorityFeePerGas,
      maxFeePerGas: params.maxFeePerGas,
      paymasterAndData: "0x" as Hex,
      validAfter: 0,
      validUntil: 0,
      entryPoint: ENTRY_POINT_V07,
    };

    // Handle v0.7 format: factory+factoryData → initCode
    if (params.factory && params.factoryData) {
      message.initCode = concatHex([params.factory, params.factoryData]);
    }

    // Handle v0.7 format: separate paymaster fields → paymasterAndData
    if (params.paymaster) {
      message.paymasterAndData = concat([
        params.paymaster,
        pad(toHex(BigInt(params.paymasterVerificationGasLimit || 0)), {
          size: 16,
        }),
        pad(toHex(BigInt(params.paymasterPostOpGasLimit || 0)), { size: 16 }),
        (params.paymasterData as Hex) || "0x",
      ]);
    }

    // Call signTypedData on our fake owner — this does the threshold signing
    const thresholdSig = await erc1271Owner.signTypedData({
      domain: {
        chainId: BigInt(chainId),
        verifyingContract: SAFE_4337_MODULE,
      },
      types: SafeOpTypes,
      primaryType: "SafeOp",
      message,
    });

    console.log(
      `    Threshold sig: ${(thresholdSig.length - 2) / 2} bytes`
    );

    // Encode as Safe contract signature (v=0, dynamic)
    const contractSig = encodeSafeContractSignature(
      ERC1271_ADDRESS,
      thresholdSig
    );
    console.log(
      `    Contract sig total: ${(contractSig.length - 2) / 2} bytes`
    );

    // Pack with validAfter=0, validUntil=0
    return encodePacked(["uint48", "uint48", "bytes"], [0, 0, contractSig]);
  };

  // ── Check balance ───────────────────────────────────────────────────────────

  const balance = await publicClient.getBalance({
    address: safeAccount.address,
  });
  console.log(`💰  Balance: ${balance} wei`);
  if (balance === 0n) {
    console.warn(
      `\n⚠️   Safe has no ETH. Fund ${safeAccount.address} or enable paymaster.\n`
    );
  }

  // ── Smart account client ────────────────────────────────────────────────────

  const smartAccountClient = createSmartAccountClient({
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

  // ── Send a 0-ETH no-op (exercises the full validation path) ─────────────────

  const TARGET: Address = zeroAddress;
  console.log(`\n📋  UserOp: 0 ETH to ${TARGET} (no-op)`);

  let userOpHash: Hex;
  try {
    console.log("\n🚀  Submitting UserOp to Pimlico…");
    userOpHash = await smartAccountClient.sendUserOperation({
      account: safeAccount,
      calls: [{ to: TARGET, value: 0n, data: "0x" }],
    });
    console.log(`    UserOp hash: ${userOpHash}`);
  } catch (err) {
    console.error("\n❌  Failed to submit UserOp:");
    if (err instanceof Error) {
      console.error(`    ${err.message}`);
      const e = err as Record<string, unknown>;
      if (e.details) console.error("    details:", e.details);
    } else {
      console.error(err);
    }
    process.exit(1);
  }

  // ── Wait for on-chain confirmation ──────────────────────────────────────────

  console.log("\n⏳  Waiting for confirmation (up to 2 min)…");
  try {
    const receipt = await bundlerClient.waitForUserOperationReceipt({
      hash: userOpHash,
      timeout: 120_000,
    });

    console.log("\n──────────────────────────────────────────────────");
    if (receipt.success) {
      console.log("🎉  UserOp SUCCEEDED");
      console.log(`    Tx hash  : ${receipt.receipt.transactionHash}`);
      console.log(`    Block    : ${receipt.receipt.blockNumber}`);
      console.log(`    Gas used : ${receipt.receipt.gasUsed}`);
      console.log("\n✅  PROOF: Safe (7579) + global ERC-1271 signer works.");
      console.log("    All Safe wallets can share one 1271 contract as owner.");
      console.log("    Cohort rotation = one tx to update the 1271 contract.");
    } else {
      console.error("💥  UserOp FAILED on-chain");
      console.error(`    Reason : ${receipt.reason}`);
      console.error(`    Tx hash: ${receipt.receipt.transactionHash}`);
      process.exit(1);
    }
    console.log("──────────────────────────────────────────────────\n");
  } catch (err) {
    console.error("\n❌  Receipt error:");
    if (err instanceof Error) {
      console.error(`    ${err.message}`);
    } else {
      console.error(err);
    }
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("\n💀  Unhandled error:");
  console.error(err);
  process.exit(1);
});
