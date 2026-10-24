import crypto from "crypto";
import { CMI_STORE_KEY } from "./config";

export function verifyCmi(body: string, signature: string): boolean {
  const expected = crypto.createHmac("sha512", CMI_STORE_KEY).update(body).digest("base64");
  return expected === signature;
}

export function verifyCmiV2(body: string, signature: string): boolean {
  const expected = Buffer.from(crypto.createHmac("sha512", CMI_STORE_KEY).update(body).digest("base64"));
  const given = Buffer.from(signature);
  return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}
