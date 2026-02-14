import type { IncomingMessage, ServerResponse } from "node:http";
import { renderQrPngBase64 } from "../web/qr-image.js";
import { authorizeGatewayConnect, isLocalDirectRequest, type ResolvedGatewayAuth } from "./auth.js";
import { sendJson, sendMethodNotAllowed, sendUnauthorized } from "./http-common.js";
import { getBearerToken } from "./http-utils.js";
import { pickPrimaryLanIPv4 } from "./net.js";

export async function handlePairingQrHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: {
    auth: ResolvedGatewayAuth;
    trustedProxies?: string[];
    bindHost: string;
    port: number;
    gatewayTls?: { enabled: boolean };
  },
): Promise<boolean> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  if (url.pathname !== "/api/pairing/qr") {
    return false;
  }

  if (req.method !== "GET") {
    sendMethodNotAllowed(res, "GET");
    return true;
  }

  if (!isLocalDirectRequest(req, opts.trustedProxies)) {
    const token = getBearerToken(req);
    const authResult = await authorizeGatewayConnect({
      auth: opts.auth,
      connectAuth: token ? { token, password: token } : null,
      req,
      trustedProxies: opts.trustedProxies,
    });
    if (!authResult.ok) {
      sendUnauthorized(res);
      return true;
    }
  }

  const host = resolveReachableHost(opts.bindHost);
  if (!host) {
    sendJson(res, 500, { error: "Cannot determine reachable host address" });
    return true;
  }

  const port = opts.port;
  const tls = opts.gatewayTls?.enabled ?? false;

  const params = new URLSearchParams();
  params.set("host", host);
  params.set("port", String(port));
  params.set("tls", String(tls));
  if (opts.auth.token) {
    params.set("token", opts.auth.token);
  }
  if (opts.auth.password) {
    params.set("password", opts.auth.password);
  }

  const deepLink = `openclaw://gateway?${params.toString()}`;
  const qrImageBase64 = await renderQrPngBase64(deepLink);

  sendJson(res, 200, {
    deepLink,
    qrImageBase64,
    host,
    port,
    tls,
  });

  return true;
}

function resolveReachableHost(bindHost: string): string | undefined {
  if (bindHost === "0.0.0.0" || bindHost === "::") {
    return pickPrimaryLanIPv4() ?? "127.0.0.1";
  }
  if (bindHost === "127.0.0.1" || bindHost === "::1" || bindHost === "localhost") {
    return "127.0.0.1";
  }
  return bindHost;
}
