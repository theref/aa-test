/**
 * ERC-1271 × Rhinestone SDK × Pimlico — EP v0.7
 * ────────────────────────────────────────────────
 * Same proof as safe-1271-test.ts but using @rhinestone/sdk.
 * Creates a Rhinestone smart account with TACo's global 1271 signer as owner.
 *
 * Usage:
 *   npm run rhinestone-test
 */

import "dotenv/config";
import {
  type Address,
  type Hex,
  concat,
  getAddress,
  pad,
  toHex,
  encodePacked,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
import { RhinestoneSDK, type RhinestoneAccount } from "@rhinestone/sdk";

// ─── Config ─────────────────────────────────────────────────────────────────────

function requireEnv(key: string): string {
  const v = process.env[key];
  if (!v) throw new Error(`Missing env var: ${key}`);
  return v;
}

const PIMLICO_API_KEY = requireEnv("PIMLICO_API_KEY");
const ERC1271_ADDRESS = getAddress(requireEnv("ERC1271_CONTRACT_ADDRESS"));

function ensureHexPrefix(key: string): Hex {
  const v = requireEnv(key);
  return (v.startsWith("0x") ? v : `0x${v}`) as Hex;
}

const signer1 = privateKeyToAccount(ensureHexPrefix("SIGNER1_PRIVATE_KEY"));
const signer2 = privateKeyToAccount(ensureHexPrefix("SIGNER2_PRIVATE_KEY"));
const allSigners = [signer1, signer2];

const chain = sepolia;

// ─── Helpers ────────────────────────────────────────────────────────────────────

function encodeMultiSigSignature(
  sigs: { address: Address; sig: Hex }[]
): Hex {
  const sorted = [...sigs].sort((a, b) =>
    a.address.toLowerCase().localeCompare(b.address.toLowerCase())
  );
  return concat(sorted.map(({ sig }) => sig));
}

/** Safe contract signature (v=0): tells Safe to call isValidSignature on signer */
function encodeSafeContractSignature(signer: Address, sigData: Hex): Hex {
  return concat([
    pad(signer as Hex, { size: 32 }),
    pad(toHex(65n), { size: 32 }),
    "0x00",
    pad(toHex(BigInt((sigData.length - 2) / 2)), { size: 32 }),
    sigData,
  ]);
}

// ─── Main ───────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("\n══════════════════════════════════════════════════");
  console.log("  ERC-1271 × Rhinestone SDK × Pimlico — EP v0.7");
  console.log("══════════════════════════════════════════════════");
  console.log(`  Chain      : ${chain.name} (id ${chain.id})`);
  console.log(`  1271 Owner : ${ERC1271_ADDRESS}`);
  console.log(`  Signers    : ${allSigners.length}`);
  allSigners.forEach((s, i) => console.log(`    [${i + 1}] ${s.address}`));
  console.log("══════════════════════════════════════════════════\n");

  // ── Init Rhinestone SDK ─────────────────────────────────────────────────────

  const rhinestone = new RhinestoneSDK({
    apiKey: process.env.RHINESTONE_API_KEY || "test", // optional for testnet
    bundler: { type: "pimlico", apiKey: PIMLICO_API_KEY },
    paymaster: { type: "pimlico", apiKey: PIMLICO_API_KEY },
  });

  // ── Fake owner pointing at the 1271 contract ───────────────────────────────
  //
  // The SDK expects Account objects in the owners array.
  // We create a fake one whose address is our 1271 contract.
  // signMessage/signTypedData sign with threshold keys.

  const tacoOwner = {
    type: "local" as const,
    address: ERC1271_ADDRESS,
    source: "custom" as const,
    publicKey: "0x04" as Hex,
    async signMessage({ message }: { message: any }): Promise<Hex> {
      const rawHash: Hex =
        typeof message === "string" ? (message as Hex) : message.raw;
      console.log(`\n🔐  signMessage called, hash: ${rawHash}`);
      const collected = await Promise.all(
        allSigners.map(async (s) => ({
          address: s.address,
          sig: await s.sign({ hash: rawHash }),
        }))
      );
      return encodeMultiSigSignature(collected);
    },
    async signTypedData(params: any): Promise<Hex> {
      // Rhinestone SDK may call this for EIP-712 signing
      const { hashTypedData } = await import("viem");
      const typedHash = hashTypedData({
        domain: params.domain,
        types: params.types,
        primaryType: params.primaryType,
        message: params.message,
      });
      console.log(`\n🔐  signTypedData called, hash: ${typedHash}`);
      const collected = await Promise.all(
        allSigners.map(async (s) => ({
          address: s.address,
          sig: await s.sign({ hash: typedHash }),
        }))
      );
      return encodeMultiSigSignature(collected);
    },
    async signTransaction(): Promise<Hex> {
      throw new Error("Not supported");
    },
  };

  // ── Create Rhinestone account ───────────────────────────────────────────────

  console.log("⚙️   Creating Rhinestone account with 1271 owner…");

  let rhinestoneAccount: RhinestoneAccount;
  try {
    rhinestoneAccount = await rhinestone.createAccount({
      account: { type: "safe" },
      owners: {
        type: "ecdsa",
        accounts: [tacoOwner as any],
        threshold: 1,
      },
    });
  } catch (err) {
    console.error("❌  createAccount failed:");
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  }

  const accountAddress = rhinestoneAccount.getAddress();
  console.log(`📬  Account address: ${accountAddress}`);

  // ── Check deployment & deploy if needed ──────────────────────────────────

  const isDeployed = await rhinestoneAccount.isDeployed(chain);
  console.log(`    Deployed: ${isDeployed}`);

  if (!isDeployed) {
    console.log("\n📦  Deploying account…");
    try {
      const deployed = await rhinestoneAccount.deploy(chain, { sponsored: true });
      console.log(`    Deploy result: ${deployed}`);
    } catch (err: any) {
      console.log(`    Deploy via SDK failed: ${err.message?.slice(0, 150)}`);
      console.log("    Will include initCode in UserOp instead.");
    }
  }

  // ── Get init data for debugging ─────────────────────────────────────────

  try {
    const initData = rhinestoneAccount.getInitData();
    console.log(`    Factory: ${initData.factory}`);
    console.log(`    FactoryData: ${initData.factoryData.slice(0, 60)}…`);
  } catch (err: any) {
    console.log(`    getInitData: ${err.message?.slice(0, 100)}`);
  }

  // ── Send via ERC-4337 UserOp with manual signing ────────────────────────

  console.log("\n📋  Sending via ERC-4337 UserOp…");

  try {
    // Step 1: Prepare
    const prepared = await rhinestoneAccount.prepareUserOperation({
      chain,
      calls: [
        {
          to: "0x0000000000000000000000000000000000000001" as Address,
          value: 0n,
          data: "0x",
        },
      ],
    });

    // Inject factory data if account isn't deployed
    const deployedNow = await rhinestoneAccount.isDeployed(chain);
    if (!deployedNow) {
      const initData = rhinestoneAccount.getInitData();
      (prepared.userOperation as any).factory = initData.factory;
      (prepared.userOperation as any).factoryData = initData.factoryData;
      console.log(`    Injected initCode: factory=${initData.factory}`);
    }

    console.log(`    UserOp hash to sign: ${prepared.hash}`);

    // Step 2: Sign with threshold keys
    const collected = await Promise.all(
      allSigners.map(async (s) => ({
        address: s.address,
        sig: await s.sign({ hash: prepared.hash }),
      }))
    );
    const thresholdSig = encodeMultiSigSignature(collected);

    // Step 3: Encode as Safe contract signature (v=0)
    const contractSig = encodeSafeContractSignature(
      ERC1271_ADDRESS,
      thresholdSig
    );
    const fullSig = encodePacked(
      ["uint48", "uint48", "bytes"],
      [0, 0, contractSig]
    );

    console.log(`    Contract sig: ${(fullSig.length - 2) / 2} bytes`);

    // Step 4: Submit
    const result = await rhinestoneAccount.submitUserOperation({
      ...prepared,
      signature: fullSig,
    });

    console.log(`\n🎉  UserOp submitted!`);
    console.log(`    Result: ${JSON.stringify(result).slice(0, 300)}`);
  } catch (err: any) {
    console.error(`\n❌  UserOp failed: ${err.message?.slice(0, 300)}`);

    // Try with SDK's built-in signing as comparison
    console.log("\n📋  Trying SDK's built-in signUserOperation for comparison…");
    try {
      const prepared = await rhinestoneAccount.prepareUserOperation({
        chain,
        calls: [
          {
            to: "0x0000000000000000000000000000000000000001" as Address,
            value: 0n,
            data: "0x",
          },
        ],
      });
      const signed = await rhinestoneAccount.signUserOperation(prepared);
      console.log(`    Built-in sig: ${(signed.signature as string).slice(0, 80)}…`);
      const result = await rhinestoneAccount.submitUserOperation(signed);
      console.log(`    Result: ${JSON.stringify(result).slice(0, 200)}`);
    } catch (err2: any) {
      console.error(`    Built-in also failed: ${err2.message?.slice(0, 200)}`);
    }
  }
}

main().catch((err) => {
  console.error("\n💀  Unhandled:", err);
  process.exit(1);
});
