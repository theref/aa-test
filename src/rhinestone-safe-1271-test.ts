/**
 * ERC-1271 × Rhinestone Safe × Pimlico — EP v0.7
 * ────────────────────────────────────────────────
 * End-to-end proof that a Rhinestone Safe account accepts a global
 * ERC-1271 multisig as its "owner" via the v=0 contract signature path.
 *
 * On-chain architecture (produced by @rhinestone/sdk):
 *
 *   Safe proxy
 *     ├─ singleton: SafeL2 v1.4.1 (stock)
 *     ├─ fallbackHandler: Safe7579 Adapter V2
 *     └─ modules:
 *          ├─ OwnableValidator (owners=[1271_contract], threshold=1)
 *          └─ IntentExecutor (chain-abstraction, unused here)
 *
 * Validation flow for a UserOp:
 *
 *   EntryPoint → Safe → fallback(Safe7579Adapter).validateUserOp
 *     → OwnableValidator.validateUserOp
 *       → CheckNSignatures.recoverNSignatures(eth_sign(userOpHash), sig)
 *         → IERC1271(1271_contract).isValidSignature(hash, inner_sig)
 *
 * Usage: npm run rhinestone-safe-test
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
  encodePacked,
  getAddress,
  hashMessage,
  pad,
  parseEther,
  toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
import {
  createBundlerClient,
  createPaymasterClient,
  entryPoint07Address,
  getUserOperationHash,
  toSmartAccount,
} from "viem/account-abstraction";
import { RhinestoneSDK } from "@rhinestone/sdk";

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

const RPC_URL = process.env.ALCHEMY_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com";
const PIMLICO_KEY = env("PIMLICO_API_KEY");
const ERC1271 = getAddress(env("ERC1271_CONTRACT_ADDRESS"));
const CHAIN: Chain = sepolia;
const BUNDLER_URL = `https://api.pimlico.io/v2/${CHAIN.id}/rpc?apikey=${PIMLICO_KEY}`;

const thresholdSigners: LocalAccount[] = [
  privateKeyToAccount(hexEnv("SIGNER1_PRIVATE_KEY")),
  privateKeyToAccount(hexEnv("SIGNER2_PRIVATE_KEY")),
];
const funder = privateKeyToAccount(hexEnv("FUNDER_PRIVATE_KEY"));

// Addresses from @rhinestone/sdk's Safe account setup (v2)
const OWNABLE_VALIDATOR: Address = "0x000000000013fdB5234E4E3162a810F54d9f7E98";

// Default Rhinestone mock signature for gas estimation.
// Goes through the v=27/28 ECDSA path in CheckNSignatures → returns
// SIG_VALIDATION_FAILED gracefully (no revert), so Pimlico can estimate gas.
// Using the v=0 contract-sig format here would cause `IERC1271.isValidSignature`
// to be called with random bytes and return 0xffffffff, triggering a revert.
const MOCK_ECDSA_SIG: Hex =
  "0x81d4b4981670cb18f99f0b4a66446df1bf5b204d24cfcb659bf38ba27a4359b5711649ec2423c5e1247245eba2964679b6a1dbb85c992ae40b9b00c6935b02ff1b";

// ───────────────────────────────────────────────────────────────────────────────
// Signing helpers
// ───────────────────────────────────────────────────────────────────────────────

/**
 * Encode threshold ECDSA sigs: sort by signer address, concatenate raw 65-byte sigs.
 * This is the format the 1271 contract's isValidSignature expects.
 */
const encodeThresholdSig = (sigs: Array<{ address: Address; sig: Hex }>): Hex =>
  concat(
    [...sigs]
      .sort((a, b) => a.address.toLowerCase().localeCompare(b.address.toLowerCase()))
      .map(({ sig }) => sig)
  );

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
// (inlined because @rhinestone/sdk doesn't export these utilities)
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

/** ExecMode = callType(1) | revertOnError(1) | unused(4) | selector(4) | context(22) */
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
// Main
// ───────────────────────────────────────────────────────────────────────────────

async function main() {
  console.log("\n══════════════════════════════════════════════════");
  console.log("  ERC-1271 × Rhinestone Safe × Pimlico — EP v0.7");
  console.log("══════════════════════════════════════════════════");
  console.log(`  Chain            : ${CHAIN.name}`);
  console.log(`  1271 contract    : ${ERC1271}   (real, deployed)`);
  console.log(`  OwnableValidator : ${OWNABLE_VALIDATOR}`);
  console.log(`  Threshold signers: ${thresholdSigners.length}`);
  thresholdSigners.forEach((s, i) => console.log(`    [${i + 1}] ${s.address}`));
  console.log("══════════════════════════════════════════════════\n");

  const publicClient = createPublicClient({ chain: CHAIN, transport: http(RPC_URL) });
  const bundlerClient = createBundlerClient({
    client: publicClient,
    chain: CHAIN,
    transport: http(BUNDLER_URL),
    paymaster: createPaymasterClient({ transport: http(BUNDLER_URL) }),
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
  // 1. Create the Rhinestone account (counterfactual; no deployment yet)
  //
  // Rhinestone's SDK expects an owners.accounts array of EOA-style Account
  // objects. Since our owner is actually a contract (the 1271 multisig), we
  // pass a bare "address-only" object. The SDK extracts .address and passes
  // it to OwnableValidator's onInstall as the owner address — that's the only
  // thing it does with this object. We handle all signing ourselves below,
  // so the sign* stubs are never called.
  // ──────────────────────────────────────────────────────────────────────────

  const ownerAsAccount = {
    type: "local" as const,
    address: ERC1271,
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
  console.log(`📬  Safe address: ${accountAddress}`);

  // ──────────────────────────────────────────────────────────────────────────
  // 2. Fund the Safe
  // ──────────────────────────────────────────────────────────────────────────

  const balance = await publicClient.getBalance({ address: accountAddress });
  if (balance < parseEther("0.0001")) {
    console.log(`💰  Funding Safe with 0.001 ETH from ${funder.address}…`);
    const walletClient = createWalletClient({ account: funder, chain: CHAIN, transport: http(RPC_URL) });
    const tx = await walletClient.sendTransaction({ to: accountAddress, value: parseEther("0.001") });
    await publicClient.waitForTransactionReceipt({ hash: tx });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // 3. Build a viem smart account with our custom signing
  //
  // Rhinestone's SDK uses its own signing flow (ECDSA assuming EOA owner).
  // We bypass it and implement signUserOperation to:
  //   a. Compute canonical v0.7 userOpHash
  //   b. Have threshold signers sign eth_sign(userOpHash)
  //   c. Wrap the threshold sig in Safe's v=0 contract-sig format
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
      // 7579 validator routing: top 20 bytes of the 192-bit nonce key
      // must equal the validator address.
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
      // See MOCK_ECDSA_SIG comment: must use ECDSA-path mock, not v=0 contract sig.
      return concat(thresholdSigners.map(() => MOCK_ECDSA_SIG));
    },

    async signUserOperation(params: any) {
      const userOpHash = getUserOperationHash({
        userOperation: { ...params, sender: accountAddress, signature: "0x" },
        entryPointAddress: entryPoint07Address,
        entryPointVersion: "0.7",
        chainId: params.chainId ?? CHAIN.id,
      });
      console.log(`\n🔐  userOpHash: ${userOpHash}`);

      // OwnableValidator applies eth_sign wrapping before passing to signature
      // validation. signMessage({raw}) produces the same digest and signs it.
      const ethSignedHash = hashMessage({ raw: userOpHash });
      console.log(`    ethSignedHash: ${ethSignedHash}`);

      // This is the TaCo integration point — in production, replace this with:
      //   const thresholdSig = await signUserOp(provider, domain, cohortId, chainId,
      //     userOp, "eth_sign_v0_7" /* new aaVersion */, context);
      const collected = await Promise.all(
        thresholdSigners.map(async (s) => ({
          address: s.address,
          sig: await s.signMessage({ message: { raw: userOpHash } }),
        }))
      );
      collected.forEach(({ address, sig }, i) =>
        console.log(`    [${i + 1}] ${address}: ${sig.slice(0, 20)}…`));

      const thresholdSig = encodeThresholdSig(collected);
      return wrapAsContractSig(ERC1271, thresholdSig);
    },

    async signMessage() { throw new Error("not used"); },
    async signTypedData() { throw new Error("not used"); },
    async decodeCalls() { throw new Error("not implemented"); },
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 4. Send a UserOp (1 wei transfer)
  // ──────────────────────────────────────────────────────────────────────────

  console.log(`\n🚀  Sending 1 wei from Safe to ${funder.address}…`);

  const userOpHash = await bundlerClient.sendUserOperation({
    account: smartAccount,
    calls: [{ to: funder.address, value: 1n, data: "0x" }],
  });
  console.log(`    UserOp hash: ${userOpHash}`);

  const receipt = await bundlerClient.waitForUserOperationReceipt({
    hash: userOpHash,
    timeout: 120_000,
  });

  console.log("\n──────────────────────────────────────────────────");
  if (!receipt.success) {
    console.error(`💥  UserOp FAILED: ${receipt.reason}`);
    process.exit(1);
  }
  console.log("🎉  SUCCESS — Rhinestone Safe + ERC-1271 owner");
  console.log(`    Tx hash   : ${receipt.receipt.transactionHash}`);
  console.log(`    Block     : ${receipt.receipt.blockNumber}`);
  console.log(`    Gas used  : ${receipt.receipt.gasUsed}`);
  console.log(`    Safe      : ${accountAddress}`);
  console.log(`    1271 owner: ${ERC1271}`);
  console.log("──────────────────────────────────────────────────\n");
}

main().catch((err) => {
  console.error("\n💀 ", err);
  process.exit(1);
});
