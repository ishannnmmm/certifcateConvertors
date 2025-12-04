const fs = require("fs");

const filePath = process.argv[2];
const data = fs.readFileSync(filePath);
fs.writeFileSync("output.b64", data.toString("base64"));
console.log("Saved Base64 → output.b64");
