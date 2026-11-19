const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("node:crypto"); // "node:" memastikan memakai modul bawaan Node

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

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    console.log(`Welcome, ${username} to the chat`);

    socket.emit("registerPublicKey", {
      username,
      publicKey: "public key",
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
          // [#1] kirim pesan beserta hash-nya
          const payload = { text: message, hash: sha256(message) };
          socket.emit("message", { username, message: JSON.stringify(payload) });
        }
      }
      rl.prompt();
    });
  });
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username: newName, publicKey } = data;
  users.set(newName, publicKey);
  console.log(`${newName} join the chat`);
  rl.prompt();
});

// [#1] terima pesan lalu cek hash
socket.on("message", (data) => {
  const { username: senderUsername, message: raw } = data;
  if (senderUsername === username) return;

  let p;
  let extra = ""; 

  try {
    p = JSON.parse(raw);
  } catch {
    const end = raw.lastIndexOf("}");
    try {
      p = JSON.parse(raw.slice(0, end + 1));
      extra = raw.slice(end + 1);
    } catch {
      console.log("⚠️ the message may have been changed during transmission");
      console.log(`${senderUsername}: ${raw}`);
      rl.prompt();
      return;
    }
  }

  const received = p.text + extra;

  // bandingkan hash dari pesan yang diterima dengan hash kiriman
  if (!p.hash || sha256(received) !== p.hash) {
    console.log("⚠️ the message may have been changed during transmission");
  }

  console.log(`${senderUsername}: ${received}`);
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