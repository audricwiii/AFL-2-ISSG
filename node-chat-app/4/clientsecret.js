const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("node:crypto"); // "node:" memastikan memakai modul bawaan Node

const SHOW_CIPHERTEXT = true;

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let targetUsername = "";
let username = "";
const users = new Map();

// [#1] fungsi hash
const sha256 = (t) => crypto.createHash("sha256").update(t).digest("hex");

// [#2] pasangan kunci RSA milik client ini
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// [#3] opsi enkripsi RSA
const OAEP = {
  padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
  oaepHash: "sha256",
};

// [#2] simpan public key, jangan menimpa key yang sudah ada
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

    users.set(username, publicKey);

    socket.emit("registerPublicKey", {
      username,
      publicKey: publicKey,
    });
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        const m = message.match(/^!secret (\w+)$/);
        if (m) {
          targetUsername = m[1];
          console.log(`Now secretly chatting with ${targetUsername}`);
        } else if (message.match(/^!exit$/)) {
          console.log(`No more secretly chatting with ${targetUsername}`);
          targetUsername = "";
        } else {
          let text = message;
          let to = "";

          // [#3] mode !secret aktif: enkripsi dengan public key penerima
          if (targetUsername) {
            const targetKey = users.get(targetUsername);
            if (!targetKey) {
              console.log(`User ${targetUsername} not found`);
              rl.prompt();
              return;
            }
            text = crypto
              .publicEncrypt({ key: targetKey, ...OAEP }, Buffer.from(message))
              .toString("base64");
            to = targetUsername;
          }

          const payload = {
            text,
            to, // [#3] tujuan pesan
            hash: sha256(text), // [#1]
            signature: crypto // [#2]
              .sign("sha256", Buffer.from(text), privateKey)
              .toString("base64"),
          };

          socket.emit("message", { username, message: JSON.stringify(payload) });

          // konfirmasi untuk pengirim
          if (to) console.log(`(secret to ${to}) ${message}`);
        }
      }
      rl.prompt();
    });
  });
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => saveKey(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username: newName, publicKey: newKey } = data;
  if (newName === username) return; // abaikan gema dari diri sendiri
  saveKey(newName, newKey);
  console.log(`${newName} join the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const { username: senderUsername, message: raw } = data;
  if (senderUsername === username) return;

  // [#1] JSON rusak = pesan diubah di tengah jalan
  let p;
  try {
    p = JSON.parse(raw);
  } catch {
    console.log("⚠️ the message may have been changed during transmission");
    console.log(`${senderUsername}: ${raw}`);
    rl.prompt();
    return;
  }

  // [#3] pesan rahasia untuk orang lain
  if (p.to && p.to !== username) {
    if (SHOW_CIPHERTEXT) console.log(`${senderUsername}: ${p.text}`);
    rl.prompt();
    return;
  }

  // [#1] bandingkan hash
  if (!p.hash || sha256(p.text) !== p.hash) {
    console.log("⚠️ the message may have been changed during transmission");
  }

  // [#2] verifikasi tanda tangan dengan public key pengirim
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

  // [#3] dekripsi kalau pesan ini untuk kita
  if (p.to === username) {
    try {
      const plain = crypto
        .privateDecrypt({ key: privateKey, ...OAEP }, Buffer.from(p.text, "base64"))
        .toString();
      console.log(`${senderUsername} (secret): ${plain}`);
    } catch {
      console.log("⚠️ failed to decrypt the message");
    }
  } else {
    console.log(`${senderUsername}: ${p.text}`);
  }
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