import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { initUserDB } from "./initUserDB.js";
import { initAclDB } from "./initAclDB.js";
import crypto from "crypto";
import Gun from "gun";
const SEA = Gun.SEA;

import { config } from "dotenv";
config();

import sodium from "libsodium-wrappers";

// Ensure libsodium is ready
await sodium.ready;

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";

let userDb, aclStore;

/**
 * Starts the server asynchronously.
 * @async
 * @function
 * @throws {Error} If the server fails to start.
 */
async function startServer() {
  try {
    aclStore = await initAclDB(); // Initializes the ACL store
    userDb = await initUserDB(); // Initializes the user database

    const app = express();
    app.use(cors());
    app.use(express.json());

    /**
     * Middleware function for authenticating a user.
     * @param {Object} req - The Express request object.
     * @param {Object} res - The Express response object.
     * @param {Function} next - The next middleware function.
     * @returns {void}
     * @throws {Error} If the token is invalid.
     */
    function authenticate(req, res, next) {
      const token = req.headers.authorization?.split(" ")[1]; // Assuming 'Bearer TOKEN_STRING'
      if (!token) {
        return res
          .status(401)
          .json({ err: "Access denied. No token provided." });
      }

      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Attaching user info to request object
        next(); // Pass control to the next middleware function
      } catch (ex) {
        res.status(400).json({ err: "Invalid token." });
      }
    }

    /**
     * Middleware function for checking write access of a user.
     * The check is only performed on paths that start with 'users/'.
     * If the allowedPublicKeys array for a path includes the user's public key or '*',
     * the user is granted write access. The '*' key represents access for any user.
     * If the path does not start with 'users/', the request is allowed to proceed without checking the user's public key.
     *
     * @async
     * @param {Object} req - The Express request object.
     * @param {Object} res - The Express response object.
     * @param {Function} next - The next middleware function.
     * @returns {void}
     * @throws {Error} If the access check fails.
     */
    async function checkWriteAccess(req, res, next) {
      let path = req.params.path + (req.params[0] ? req.params[0] : "") + "/";

      // If the path does not start with 'users/', allow the request to proceed
      if (!path.startsWith("users/")) {
        next();
        return;
      }

      const userPublicKey = req.user.pub;

      try {
        while (path !== "") {
          // Retrieve access rights for the path
          const accessRightsEntries = await aclStore.get(path); // This returns the access rights for the path
          const accessRights = accessRightsEntries.find(
            (ar) => ar._id === path
          ); // Find the specific entry for the path

          // Check if the user's public key (or '*') is allowed to write to this path
          if (
            accessRights &&
            (accessRights.owner === userPublicKey ||
              accessRights.allowedPublicKeys.includes(userPublicKey) ||
              accessRights.allowedPublicKeys.includes("*")) // Allow access if '*' is present
          ) {
            next(); // User has access, proceed to the next middleware or route handler
            return;
          }

          // Trim the last segment of the path if no direct access rights are found
          if (path.lastIndexOf("/") !== -1) {
            path = path.substring(0, path.lastIndexOf("/"));
          } else {
            break; // Exit if the path cannot be trimmed further
          }
        }

        // If no access is found, deny the request
        res.status(403).json({ err: "Access denied." });
      } catch (error) {
        console.error("Access check failed:", error);
        res.status(500).json({ err: "Server error during access check" });
      }
    }

    /**
     * Express route handler for adding write access to a user.
     * If the publicKey is '*', write access is granted to all users.
     *
     * @async
     * @param {Object} req - The Express request object.
     * @param {Object} req.body - The body of the request.
     * @param {string} req.body.path - The path to which write access is being added.
     * @param {string} req.body.publicKey - The public key of the user to whom write access is being added. If this is '*', write access is granted to all users.
     * @param {Object} res - The Express response object.
     * @returns {void}
     * @throws {Error} If there is an error while adding write access.
     */
    app.post("/add-write-access", authenticate, async (req, res) => {
      const { path, publicKey, signature } = req.body;
      const userPub = req.user.pub; // Owner's public key

      try {
        const accessRightsEntries = await aclStore.get(path);
        let accessRights = accessRightsEntries.find((ar) => ar._id === path);

        if (!accessRights) {
          accessRights = {
            _id: path,
            owner: userPub,
            allowedPublicKeys: [],
          };
        }

        // Verify the signature
        const msgToSign = `${path}-${publicKey}-grant`;
        const msgBytes = sodium.from_string(msgToSign);
        const signatureBytes = sodium.from_base64(signature);

        if (!accessRights.owner) {
          console.error("Owner public key is not set.");
          return res.status(500).json({ err: "Owner public key is not set." });
        }

        const publicKeyBytes = sodium.from_base64(accessRights.owner); // Convert base64 public key to bytes

        const isValid = sodium.crypto_sign_verify_detached(
          signatureBytes,
          msgBytes,
          publicKeyBytes
        );

        if (!isValid) {
          return res.status(403).json({ err: "Signature verification failed" });
        }

        if (publicKey === "*") {
          accessRights.allowedPublicKeys = ["*"];
          await aclStore.put(accessRights);
          return res.send({ message: "Write access granted to all users." });
        }

        if (!accessRights.allowedPublicKeys.includes(publicKey)) {
          accessRights.allowedPublicKeys.push(publicKey);
          await aclStore.put(accessRights);
          res.send({ message: "Write access granted successfully." });
        } else {
          res.send({ message: "Public key already has access." });
        }
      } catch (error) {
        console.error("Error adding write access:", error);
        res.status(500).json({ err: "Server error while adding write access" });
      }
    });

    /**
     * Express route handler for removing write access from a user.
     * @async
     * @param {Object} req - The Express request object.
     * @param {Object} req.body - The body of the request.
     * @param {string} req.body.path - The path from which write access is being removed.
     * @param {string} req.body.publicKey - The public key of the user from whom write access is being removed.
     * @param {string} req.body.signature - The cryptographic signature generated by the owner to authenticate the request.
     * @param {Object} res - The Express response object.
     * @returns {void}
     * @throws {Error} If there is an error while removing write access.
     */
    app.post("/remove-write-access", authenticate, async (req, res) => {
      const { path, publicKey, signature } = req.body;
      const userPub = req.user.pub; // Owner's public key

      try {
        // Retrieve all access rights entries for the path
        const accessRightsEntries = await aclStore.get(path);
        // Find the specific entry for the path
        let accessRights = accessRightsEntries.find((ar) => ar._id === path);

        // If no access rights entry exists for the path
        if (!accessRights) {
          return res.status(404).json({
            err: "Path does not exist.",
          });
        }

        // Verify the signature to ensure the request comes from the owner
        const msgToSign = `${path}-${publicKey}-revoke`;
        const msgBytes = sodium.from_string(msgToSign);
        const signatureBytes = sodium.from_base64(signature);
        const publicKeyBytes = sodium.from_base64(accessRights.owner);

        const isValid = sodium.crypto_sign_verify_detached(
          signatureBytes,
          msgBytes,
          publicKeyBytes
        );

        if (!isValid) {
          return res
            .status(403)
            .json({ error: "Signature verification failed" });
        }

        // Check if the public key is actually in the allowed list
        if (accessRights.allowedPublicKeys.includes(publicKey)) {
          // Filter out the public key to remove access
          accessRights.allowedPublicKeys =
            accessRights.allowedPublicKeys.filter((key) => key !== publicKey);

          // Update the access rights in the store
          await aclStore.put(accessRights);
          res.json({ message: "Write access removed successfully." });
        } else {
          res.status(404).json({
            err: "Public key does not have access or path does not exist.",
          });
        }
      } catch (error) {
        console.error("Error removing write access:", error);
        res
          .status(500)
          .json({ err: "Server error while removing write access" });
      }
    });

    /**
     * Express route handler for requesting a temporary token.
     * @param {Object} req - The Express request object.
     * @param {Object} req.body - The body of the request.
     * @param {string} req.body.alias - The alias of the user requesting the token.
     * @param {Object} res - The Express response object.
     * @returns {void}
     * @throws {Error} If the alias is not provided.
     */
    app.post("/request-token", (req, res) => {
      const { alias } = req.body;
      if (!alias) {
        return res.status(400).json({ err: "Alias is required" });
      }
      const token = jwt.sign({ alias, tempUser: true }, JWT_SECRET, {
        expiresIn: "5m",
      });
      res.json({ token });
    });

    /**
     * Endpoint for user registration. It authenticates the temporary token, registers the user,
     * creates a JWT token, sets up initial access control for the user, and sends a success response.
     * If an error occurs during this process, it sends a JSON error response.
     *
     * @async
     * @param {Object} req - The Express request object. The body should contain 'alias', 'publicKey', and 'hashedPassword'.
     * @param {Object} res - The Express response object.
     * @returns {void}
     * @throws {Error} If there's an error during the registration process.
     */
    app.post("/register", authenticateTempToken, async (req, res) => {
      const { alias, publicKey, hashedPassword } = req.body;

      try {
        await userDb.put({
          _id: alias,
          publicKey,
          hashedPassword,
        });

        // Create a more persistent JWT here if needed
        const token = jwt.sign({ alias, pub: publicKey }, JWT_SECRET, {
          expiresIn: "1h",
        });

        // Setting up initial access control for the user
        const userPath = `users/${publicKey}`; // Adjust path as needed

        console.log("Attempting to save ACL entry", {
          _id: userPath,
          owner: publicKey,
          allowedPublicKeys: [publicKey],
        });

        await aclStore.put({
          _id: userPath,
          owner: publicKey,
          allowedPublicKeys: [publicKey], // Initially allow only self
        });

        res.json({ message: "User registered successfully", token });
      } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ err: "Server error during registration" });
      }
    });

    /**
     * Middleware function for authenticating a temporary token.
     * @param {Object} req - The Express request object.
     * @param {Object} res - The Express response object.
     * @param {Function} next - The next middleware function.
     * @returns {void}
     * @throws {Error} If the token is invalid or expired.
     */
    function authenticateTempToken(req, res, next) {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) {
        return res
          .status(401)
          .json({ err: "Access denied. No token provided." });
      }

      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded.tempUser)
          throw new Error("Invalid temporary token usage.");
        req.user = decoded; // User information from token is now attached to the request
        next();
      } catch (error) {
        res.status(400).json({ err: "Invalid or expired token." });
      }
    }

    /**
     * Express route handler for authenticating a user.
     * @async
     * @param {Object} req - The Express request object.
     * @param {Object} req.body - The body of the request.
     * @param {string} req.body.alias - The alias of the user trying to authenticate.
     * @param {string} req.body.pass - The password of the user trying to authenticate.
     * @param {Object} res - The Express response object.
     * @returns {void}
     * @throws {Error} If there is an error during authentication.
     */
    app.post("/authenticate", async (req, res) => {
      const { alias, pass } = req.body;
      try {
        const userDataEntries = await userDb.get(alias);
        if (userDataEntries.length > 0) {
          const userData = userDataEntries[0]; // Assume the first entry is the user data
          const isMatch = await bcrypt.compare(pass, userData.hashedPassword);
          if (isMatch) {
            const token = jwt.sign(
              { alias: userData.alias, pub: userData.publicKey },
              JWT_SECRET,
              { expiresIn: "1h" }
            );
            res.json({ message: "Authentication successful", token });
          } else {
            res.status(401).json({ err: "Authentication failed" });
          }
        } else {
          res.status(404).json({ err: "User not found" });
        }
      } catch (error) {
        console.error("Authentication error:", error);
        res.status(500).json({ err: "Server error" });
      }
    });

    /**
     * Express route handler for retrieving the Access Control List (ACL) entry for a user.
     * @async
     * @param {Object} req - The Express request object.
     * @param {Object} req.body - The body of the request.
     * @param {string} req.body.alias - The alias of the user whose ACL entry is being retrieved.
     * @param {Object} res - The Express response object.
     * @returns {void}
     * @throws {Error} If there is an error while retrieving the ACL entry.
     */
    app.post("/acl", async (req, res) => {
      const { alias } = req.body;

      try {
        const userCredentialsEntries = await userDb.get(alias);

        const userCredentials = userCredentialsEntries.find(
          (uc) => uc.publicKey && uc.hashedPassword
        );

        if (userCredentials) {
          res.json({ exists: true });
        } else {
          res.status(404).json({
            exists: false,
            err: "No user credentials found for the user.",
          });
        }
      } catch (error) {
        console.error("Failed to retrieve ACL entry:", error);
        res.status(500).json({ err: "Server error" });
      }
    });

    /**
     * Express route handler for fetching data based on a path.
     * @async
     * @param {Object} req - The Express request object.
     * @param {Object} req.body - The body of the request.
     * @param {string} req.body.path - The path of the data to be fetched.
     * @param {Object} res - The Express response object.
     * @returns {void}
     * @throws {Error} If there is an error while fetching the data.
     */
    app.post("/fetch-data", async (req, res) => {
      const { path } = req.body; // Extract path from request body

      try {
        const items = await userDb.get(path);
        console.log("Fetched data:", items);
        res.json(items);
      } catch (error) {
        console.error("Failed to fetch data:", error);
        res.status(500).json({ err: "Server Error" });
      }
    });

    function encodeUriPathSegments(path) {
      return path.split("/").map(encodeURIComponent).join("/");
    }

    /**
     * Endpoint to save data at a specified path. If the path includes a hash,
     * the data is saved under the hash after verifying that the provided hash
     * matches the calculated hash of the data. If the path does not include a hash,
     * the data is saved directly under the path.
     *
     * @route POST /update-data
     * @group Data - Operations related to data
     * @param {object} request.body.required - The request body containing the path and data to save
     * @returns {object} 201 - An object containing a message and the full path where the data was saved
     * @returns {Error}  400 - Hash mismatch: The provided hash does not match the calculated hash of the data
     * @returns {Error}  409 - Data under this hash already exists
     * @returns {Error}  500 - Server error while saving hashed data or Server Error
     * @security JWT
     */
    app.post(
      "/update-data",
      authenticate,
      checkWriteAccess,
      async (req, res) => {
        const { path, value } = req.body;
        let data = value;

        // If data is an object with a value property, extract the value
        if (typeof data === "object" && data !== null && "value" in data) {
          data = data.value;
        }

        // Check if path includes a hash
        if (path.includes("%23")) {
          const segments = path.split(/(%23.*?)(\/)/); // Split on the first occurrence of '%23' followed by any characters up to but not including '/'

          const basePath = segments[1]; // This will capture '%23Fabstir214_users'
          const hashAndBeyond = segments[3]; // This will capture 'PbIlCHlizVLefyK7gr%2FFvB01Zf4sej6M2%2BQU8eqRjDw%3D'

          const hashSegments = hashAndBeyond.split(/\/(.+)/); // Split on the first '/'
          const providedHash = hashSegments[0];

          const calculatedHash = await SEA.work(data, null, null, {
            name: "SHA-256",
          });

          const calculatedHashParts = calculatedHash.split("/");
          const calculatedHashPrefix = calculatedHashParts[0];

          // Verify that the provided hash matches the calculated hash prefix
          if (providedHash !== calculatedHashPrefix) {
            return res.status(400).json({
              err: "Hash mismatch: The provided hash does not match the calculated hash of the data.",
            });
          }

          const fullPath = `${basePath}/${providedHash}/`;
          try {
            // Check if the data under this hash already exists to prevent duplicate entries under the same hash
            const existingData = await userDb.get(fullPath);
            if (existingData && existingData.length > 0) {
              return res
                .status(409)
                .json({ err: "Data under this hash already exists." });
            }

            await userDb.put({ _id: fullPath, data });
            res.status(201).json({
              message: "Data saved successfully under hash",
              path: fullPath,
            });
          } catch (error) {
            console.error("Error saving hashed data:", error);
            res
              .status(500)
              .json({ err: "Server error while saving hashed data" });
          }
        } else {
          // Regular data saving without hash
          try {
            const result = await userDb.put({ _id: path, data });
            res.json(result);
          } catch (error) {
            console.error("Failed to save data:", error);
            res.status(500).json({ err: "Server Error" });
          }
        }
      }
    );

    /**
     * Express route handler for deleting data at a specified path.
     * Ensures that data at paths containing hashes (immutable data) cannot be deleted.
     * @async
     * @param {Object} req - The Express request object.
     * @param {Object} req.params - The parameters of the request.
     * @param {string} req.params.path - The path of the data to be deleted.
     * @param {Object} res - The Express response object.
     * @returns {void}
     * @throws {Error} If there is an error while deleting the data.
     */
    app.delete("/update-data", authenticate, async (req, res) => {
      const { path } = req.body; // Extract path from the request body

      // Check if the path includes a hash segment, indicating immutable content
      if (path.includes("%23")) {
        return res
          .status(403)
          .json({ err: "Deletion of immutable hashed data is not allowed." });
      }

      try {
        await userDb.del(path);
        res.json({ message: "Data deleted successfully" });
      } catch (error) {
        console.error("Failed to delete data:", error);
        res.status(500).json({ err: "Server Error" });
      }
    });

    const PORT = process.env.PORT || 3001;
    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}`);
    });

    // Cleanup on process termination
    process.on("SIGINT", async () => {
      console.log("Shutting down server...");
      server.close(); // Close the HTTP server
      await aclStore.close(); // Close the OrbitDB store
      await userDb.close(); // Close the user database
      await ipfs.stop(); // Stop the IPFS instance
      process.exit();
    });
  } catch (error) {
    console.error("Failed to start the server:", error);
  }
}

startServer();
