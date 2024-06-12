import * as fs from "fs";
import axios from "axios";

// fetch root token
const rootToken: string = JSON.parse(
  fs.readFileSync("vault-seal-keys.json").toString()
).root_token;

// log 
console.log(`rootToken : ${rootToken}`);

// mount kv engine through POST
axios.post(
  "http://localhost:8200/v1/sys/mounts/secret",
  {
    type: "kv-v2",
    config: {
      force_no_cache: true
    }
  },
  {
    headers: {
      "X-Vault-Token": rootToken,
    },
  }
).then((res) => {
    // log mount response
    console.log(`mount kv engine : ${JSON.stringify(res.data)}`);
}).catch((err) => {
    console.log(`err : ${JSON.stringify(err)}`);
})
