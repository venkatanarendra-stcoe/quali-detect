import * as cp from "child_process";
import * as crypto from "crypto";

export function run(userInput: string): void {
  cp.execSync(`convert ${userInput} out.png`);
  const c = crypto.createCipher("aes192", "key");
  const f = new Function("a", userInput);
  f(c);
}
