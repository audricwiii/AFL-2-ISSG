const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let targetUsername = "";
let username = "";
const users = new Map();

const sha256 = (t) => crypto.createHash("sha256").update(t).digest("hex");

// [#2] perubahan 1: buat pasangan kunci RSA
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// [#2] perubahan 2: simpan public key, jangan menimpa key yang sudah ada
function saveKey(user, key) {
  if (!users.has(user)) {
    users.set(user, key);
  } else if (users.get(user) !== key) {
    console.log(`\n⚠️ Someone tries to register again as "${user}" with a different key`);
  }
}

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    console.log(`Welcome, ${username} to the chat`);

    users.set(username, publicKey); // [#2] perubahan 3: simpan key sendiri

    socket.emit("registerPublicKey", {
      username,
      publicKey: publicKey, // [#2] perubahan 3: kirim key asli
    });
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        if ((match = message.match(/^!secret (\w+)$/))) {
          targetUsername = match[1];
          console.log(`Now secretly chatting with ${targetUsername}`);
        } else if (message.match(/^!exit$/)) {
          console.log(`No more secretly chatting with ${targetUsername}`);
          targetUsername = "";
        } else {
          const payload = {
            text: message,
            hash: sha256(message), // #1
            // [#2] perubahan 4: tanda tangan pakai private key
            signature: crypto
              .sign("sha256", Buffer.from(message), privateKey)
              .toString("base64"),
          };
          socket.emit("message", { username, message: JSON.stringify(payload) });
        }
      }
      rl.prompt();
    });
  });
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => saveKey(user, key)); // [#2] pakai saveKey
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username: newName, publicKey: newKey } = data;
  if (newName === username) return; // [#2] abaikan gema dari diri sendiri
  saveKey(newName, newKey); // [#2] pakai saveKey
  console.log(`${newName} join the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const { username: senderUsername, message: raw } = data;
  if (senderUsername === username) return;

  let p;
  try {
    p = JSON.parse(raw);
  } catch {
    console.log("⚠️ the message may have been changed during transmission");
    console.log(`${senderUsername}: ${raw}`);
    rl.prompt();
    return;
  }

  // #1
  if (!p.hash || sha256(p.text) !== p.hash) {
    console.log("⚠️ the message may have been changed during transmission");
  }

  // [#2] perubahan 5: verifikasi tanda tangan dengan public key pengirim
  let valid = false;
  try {
    const pub = users.get(senderUsername);
    valid =
      !!pub &&
      !!p.signature &&
      crypto.verify("sha256", Buffer.from(p.text), pub, Buffer.from(p.signature, "base64"));
  } catch {
    valid = false;
  }
  if (!valid) console.log("⚠️ this user is fake");

  console.log(`${senderUsername}: ${p.text}`);
  rl.prompt();
});

socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});