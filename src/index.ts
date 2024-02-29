import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { config } from 'dotenv';
import { readFileSync, mkdirSync, existsSync, writeFileSync } from "node:fs";
import jwt from 'jsonwebtoken';

config();

import { OAuth2Client } from "google-auth-library";

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const SCOPES = [
  "https://www.googleapis.com/auth/spreadsheets",   // REQUIRED FOR SPREADHEETS
  "https://www.googleapis.com/auth/userinfo.email",  // REQURIED TO DIFFERENTIATE USER BY EMAIL
  "https://www.googleapis.com/auth/drive.file"  // REQUIRED FOR DRIVE PICKER
];

const oAuth2Client = new OAuth2Client(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
const app = new Hono()

type TUserToken = { email: string; refreshToken: string; };

app.get("/", async (context) => {
  const code = context.req.query('code');
  const clientId = context.req.query('state');

  if (!code || !clientId) {
    context.status(400);
    return context.text("Auth Code or clientId Missing");
  }

  const { res, tokens } = await oAuth2Client.getToken(code);

  if (!res || res.statusText !== "OK") {
    if (!res) {
      context.status(400);
      return context.text("no response from google api.");
    }

    console.error("Error exchanging code for tokens. ", res.statusText);
    context.status(res.status);
    return context.text(res.statusText);
  }

  const id_token = tokens.id_token;
  const refresh_token = tokens.refresh_token;

  if (res.statusText === 'OK' && id_token && refresh_token) {
    const decoded = jwt.decode(id_token, { complete: true });
    const google_email = decoded?.payload?.email;

    if (!refresh_token || !google_email) {
      context.status(500);
      return context.text("no token or no email");
    }

    const newUserToken: TUserToken = { email: google_email, refreshToken: refresh_token };
    saveRefreshToken(clientId, newUserToken);

    const htmlResponse = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authorization Success</title>
      </head>
      <body>
        <h1>Authorization Successful!</h1>

        <div style="display: flex; align-items: center; gap: 5px;">
          <div>Email: </div>
          <p id="email">${google_email} </p>
        </div>

        <div style="display: flex; align-items: center; gap: 5px;">
          <div>Access Token: </div>
          <p id="token">${refresh_token}</p>
        </div>
      </body>
      </html>
    `;
    return context.html(htmlResponse);
  }

  context.status(500);
  return context.text("Exhaustive Unhandled Error");
});

app.get('/authorize', (context) => {
  try {
    const clientId = context.req.query('clientId');

    if (!clientId) {
      throw new Error("Missing client ID");
    }

    const authorizeUrl = oAuth2Client.generateAuthUrl({
      access_type: "offline",
      scope: SCOPES,
      state: clientId,
    });

    return context.redirect(authorizeUrl);
  } catch (error) {
    console.error("Error in /authorize:", error);
    context.status(500);
  }

  return context.text("Internal Server Error");
});

app.post("/refreshToken", async (context) => {
  const clientId = context.req.query("clientId");

  if (!clientId) {
    context.status(400);
    return context.json({ error: "Client ID is required" });
  }

  const savedToken = getStoredRefreshToken(clientId);

  if (!savedToken) {
    context.status(404);
    return context.text("No token found");
  }

  const { refreshToken, email } = savedToken.userToken;

  if (!refreshToken) {
    context.status(404);
    return context.json({ error: "no token available" });
  }

  oAuth2Client.setCredentials({ refresh_token: refreshToken });

  const { res, token } = await oAuth2Client.getAccessToken();

  if (!res) {
    context.status(400);
    return context.text("no response form google api.");
  }

  if (res.statusText === "OK" && token) {
    context.status(res.status);
    return context.json({ token, email });
  }

  context.status(res.status);
  return context.text(res.statusText);
});

const port = 3000
console.log(`Server is running on port ${port}`)

serve({
  fetch: app.fetch,
  port
})

type TStoredToken = { userToken: TUserToken };
function getStoredRefreshToken(clientId: string): TStoredToken | null {
  try {
    const filePath = `./RefreshTokens/${clientId}.json`;
    const data = readFileSync(filePath, "utf-8");

    if (data) {
      return JSON.parse(data);
    }
    else
      return null;

  } catch (err) {
    if (err && typeof err === 'object' && "code" in err) {
      console.error(err.code);
    }

    return null;
  }
}

function saveRefreshToken(clientId: string, userToken: TUserToken) {
  console.log("saving token to server");

  try {
    if (!existsSync("./RefreshTokens")) {
      mkdirSync("./RefreshTokens");
    }

    const filePath = `./RefreshTokens/${clientId}.json`;
    const data = JSON.stringify({ userToken });
    writeFileSync(filePath, data, "utf-8");
    console.log("token saved sucessfully");
  } catch (err) {
    console.error("Error saving refresh token:", err);
  }
}

