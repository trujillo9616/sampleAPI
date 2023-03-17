import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import jwt from "jsonwebtoken";
import AWS from "aws-sdk";

const BINARY_ONE = "1";
const BINARY_ZERO = "0";
const MIN_CIDR = 0;
const MAX_CIDR = 32;
const N = 8;

exports.handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  const JWT_SECRET = await SecretsManager.getSecretValue(
    "JWT_SECRET",
    "us-east-2"
  );
  let response: APIGatewayProxyResult;
  try {
    const auth = getAuthToken(event);
    validateToken(auth, JWT_SECRET);
    const cidr = getValue(event);
    response = {
      statusCode: 200,
      body: JSON.stringify({
        function: "cidrToMask",
        input: cidr,
        output: cidrToMask(cidr),
      }),
    };
  } catch (error) {
    response = {
      statusCode: error.message.includes("Authorization") ? 401 : 400,
      body: JSON.stringify({
        error: error.message,
      }),
    };
  }
  return response;
};

function getAuthToken(event: APIGatewayProxyEvent): string {
  if (!event.headers || !event.headers.Authorization) {
    throw new Error(
      "Missing Authorization! Please login with valid credentials."
    );
  }
  const auth = event.headers.Authorization;
  if (!auth.startsWith("Bearer ")) {
    throw new Error("Invalid Authorization");
  }
  return auth.split(" ")[1];
}

function validateToken(token: string, JWT_SECRET: string) {
  const decoded = jwt.verify(token, JWT_SECRET);
  if (!decoded || typeof decoded === "string") {
    throw new Error("Invalid token");
  }
}

function getValue(event: APIGatewayProxyEvent): string {
  if (!event.queryStringParameters || !event.queryStringParameters.value) {
    throw new Error("Missing value");
  }
  return event.queryStringParameters.value;
}

function cidrToMask(cidr: string) {
  const cidrInt = parseInt(cidr);
  if (isNaN(cidrInt) || cidrInt < MIN_CIDR || cidrInt > MAX_CIDR) {
    throw new Error("Invalid CIDR");
  }
  const mask = [];
  const fullOctets =
    BINARY_ONE.repeat(cidrInt) + BINARY_ZERO.repeat(MAX_CIDR - cidrInt);
  for (let i = 0; i < MAX_CIDR; i += N) {
    mask.push(parseInt(fullOctets.slice(i, i + N), 2));
  }
  return mask.join(".");
}

class SecretsManager {
  static async getSecretValue(secretName: string, region: string) {
    const config = { region: region };
    const secretsManager = new AWS.SecretsManager(config);
    try {
      let secretValue = await secretsManager
        .getSecretValue({ SecretId: secretName })
        .promise();
      if ("SecretString" in secretValue) {
        return secretValue.SecretString || "";
      }
    } catch (err) {
      console.log(err);
      return err;
    }
  }
}
