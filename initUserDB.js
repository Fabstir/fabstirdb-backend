import OrbitDB from "orbit-db";
import { create } from "ipfs";

import axios from "axios";
import { config } from "dotenv";
config();

const orbitDBPath = process.env.ORBITDB_PATH || './orbitdb';

export async function pinHashToPinningService(hash) {
  const pinataApiKey = process.env.PINATA_API_KEY;
  const pinataSecretApiKey = process.env.PINATA_API_SECRET;
  const pinataJwt = process.env.PINATA_JWT;
  const pinataBaseUrl = process.env.PINATA_BASE_URL;

  const url = `${pinataBaseUrl}/pinning/pinByHash`;

  const headers = {
    "Content-Type": "application/json",
    pinata_api_key: pinataApiKey,
    pinata_secret_api_key: pinataSecretApiKey,
    Authorization: `Bearer ${pinataJwt}`,
  };

  const data = {
    hashToPin: hash,
  };

  try {
    const response = await axios.post(url, data, { headers });
    return response.data;
  } catch (error) {
    console.error("Error pinning hash to Pinata:", error);
    throw error;
  }
}

/**
 * Initializes the User database.
 * @async
 * @returns {void}
 * @throws {Error} If there is an error while creating the IPFS instance.
 */
export async function initUserDB() {
  const ipfs = await create({
    repo: `${orbitDBPath}/repo`,
    // config: {
    //   Addresses: {
    //     Swarm: [
    //       "/ip4/0.0.0.0/tcp/4002",
    //       "/ip4/0.0.0.0/tcp/4003/ws", // Adjust the ports as necessary
    //     ],
    //     API: "/ip4/127.0.0.1/tcp/5002",
    //     Gateway: "/ip4/127.0.0.1/tcp/9090",
    //   },
    // },
    config: {
      Addresses: {
        Swarm: [
          "/ip4/0.0.0.0/tcp/4002",
          "/ip4/0.0.0.0/tcp/4003/ws",
          "/dns4/wrtc-star1.par.dwebops.pub/tcp/443/wss/p2p-webrtc-star",
          "/dns4/wrtc-star2.par.dwebops.pub/tcp/443/wss/p2p-webrtc-star",
          "/dns4/star-signal.cloud.ipfs.team/tcp/443/wss/p2p-webrtc-star",
          "/dns4/star-signal.cloud.ipfs.team/tcp/443/wss/p2p-webrtc-star",
        ],
      },
      Bootstrap: [
        "/ip4/104.131.131.82/tcp/4001/ipfs/QmSoLueR4xBeUbY9WZ9xGUUxunbKWcrNFTDAadQJmocnWm",
        "/ip4/104.236.179.241/tcp/4001/ipfs/QmSoLueR4xBeUbY9WZ9xGUUxunbKWcrNFTDAadQJmocnWm",
        "/ip4/128.199.219.111/tcp/4001/ipfs/QmSoLueR4xBeUbY9WZ9xGUUxunbKWcrNFTDAadQJmocnWm",
        "/ip4/178.62.158.247/tcp/4001/ipfs/QmSoLueR4xBeUbY9WZ9xGUUxunbKWcrNFTDAadQJmocnWm",
        "/ip4/178.62.61.185/tcp/4001/ipfs/QmSoLueR4xBeUbY9WZ9xGUUxunbKWcrNFTDAadQJmocnWm",
        "/ip4/192.241.194.197/tcp/4001/ipfs/QmSoLueR4xBeUbY9WZ9xGUUxunbKWcrNFTDAadQJmocnWm",
        "/ip4/46.101.197.175/tcp/4001/ipfs/QmSoLueR4xBeUbY9WZ9xGUUxunbKWcrNFTDAadQJmocnWm",
        "/ip6/2604:a880:1:20::203:d001/tcp/4001/ipfs/QmSoLueR4xBeUbY9WZ9xGUUxunbKWcrNFTDAadQJmocnWm",
        "/ip6/2604:a880:800:10::4a:5001/ipfs/QmSoLueR4xBeUbY9WZ9xGUUxunbKWcrNFTDAadQJmocnWm",
        "/ip6/2604:a880:800:10::4a:5001/ipfs/QmSoLueR4xBeUbY9WZ9xGUUxunbKWcrNFTDAadQJmocnWm",
      ],
    },
    EXPERIMENTAL: {
      pubsub: true,
    },
  });

  const orbitdb = await OrbitDB.createInstance(ipfs);

  const options = {
    accessController: {
      type: "orbitdb",
      options: {
        write: ["*"],
      },
    },
  };

  const db = await orbitdb.docstore("users", options);
  await db.load();
  console.log("Users Store initialized");

  // Start keep-alive mechanism
  startKeepAlive(db);

  return db;
}

function startKeepAlive(db) {
  setInterval(async () => {
    try {
      // Perform a simple query to keep the connection alive
      await db.get("");
      console.log("Keep-alive query executed");
    } catch (error) {
      console.error("Keep-alive query failed:", error);
    }
  }, 5 * 60 * 1000); // Adjust the interval as necessary (e.g., every 5 minutes)
}
