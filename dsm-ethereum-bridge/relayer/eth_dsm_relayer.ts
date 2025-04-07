import Web3 from 'web3';
import axios from 'axios';
import { keccak256 } from 'ethereum-cryptography/keccak';
import { RLP } from '@ethereumjs/rlp';
import { Buffer } from 'buffer';

const rlp = RLP;

const ETHEREUM_RPC_URL = 'https://mainnet.infura.io/v3/YOUR_API_KEY';
const DSM_NODE_API = 'http://localhost:8080/submit-anchor';

const web3 = new Web3(ETHEREUM_RPC_URL);

interface EthereumAnchorSubmission {
  block_number: number;
  tx_hash: string;      // hex-encoded
  event_root: string;   // hex-encoded
  inclusion_proof: string; // hex-encoded
  event_hash: string;   // hex-encoded
}

/**
 * Example function to generate a simplified inclusion proof
 * from transaction receipts/logs. In production you would
 * integrate a full MPT (Merkle Patricia Trie) proof approach
 * or rely on a known third-party library.
 */
async function generateInclusionProof(txHash: string) {
  const tx = await web3.eth.getTransaction(txHash);
  if (!tx || !tx.blockNumber) {
    throw new Error(`Transaction not found or not mined: ${txHash}`);
  }

  const receipt = await web3.eth.getTransactionReceipt(txHash);
  if (!receipt) {
    throw new Error(`No receipt for tx: ${txHash}`);
  }

  const block = await web3.eth.getBlock(tx.blockNumber, true);
  if (!block) {
    throw new Error(`Block not found: ${tx.blockNumber}`);
  }
  // This is a placeholder. Real proof requires more advanced logic.
  const receiptEncoded = rlp.encode([
    Buffer.from(receipt.status ? '1' : '0'),
    Buffer.from(receipt.cumulativeGasUsed.toString()),
    Buffer.from(receipt.logsBloom || '', 'hex'),
    // Convert logs to a simpler format that RLP can handle
    receipt.logs.map(log => [
      Buffer.from(log.address || ''),
      (log.topics || []).map(t => Buffer.from((t || '').slice(2), 'hex')),
      Buffer.from((log.data || '').slice(2), 'hex')
    ])
  ]);
  
  // Generate proof and hash (simplified for demonstration)
  const inclusionProof = '0x' + Buffer.from(receiptEncoded).toString('hex');
  const eventHash = '0x' + Buffer.from(keccak256(new Uint8Array(Buffer.from(receiptEncoded)))).toString('hex');
  
  return {
    blockNumber: Number(tx.blockNumber),
    txHash,
    eventRoot: block.receiptsRoot || '',
    inclusionProof,
    eventHash
  };
}

/**
 * Submits the anchor data to the DSM node's HTTP endpoint
 */
async function submitAnchorToDSM(anchor: EthereumAnchorSubmission) {
  await axios.post(DSM_NODE_API, anchor);
  console.log("Anchor submitted successfully to DSM:", anchor);
}

/**
 * Main relay function:
 * 1. Builds an inclusion proof
 * 2. Submits it to DSM
 */
export async function relayEthereumEvent(txHash: string) {
  try {
    const proof = await generateInclusionProof(txHash);

    const submission: EthereumAnchorSubmission = {
      block_number: proof.blockNumber,
      tx_hash: proof.txHash.replace(/^0x/, ""),      // remove '0x' for hex only
      event_root: proof.eventRoot.replace(/^0x/, ""),
      inclusion_proof: proof.inclusionProof.replace(/^0x/, ""),
      event_hash: proof.eventHash.replace(/^0x/, ""),
    };

    await submitAnchorToDSM(submission);
  } catch (err) {
    console.error("Failed to relay Ethereum event:", err);
  }
}

// Usage example:
// (Uncomment and replace with an actual transaction hash)
// relayEthereumEvent('0xYourTransactionHashHere').then(() => console.log("Done"));
