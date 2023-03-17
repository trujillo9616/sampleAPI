import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import AWS from "aws-sdk";
import jwt from "jsonwebtoken";
const MASK_LENGTH = 4;
const MIN_MASK = 0;
const MAX_MASK = 255;
const BINARY_ONE = "1";
const BINARY_ZERO = "0";

exports.handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  let response: APIGatewayProxyResult;
  const JWT_SECRET = await SecretsManager.getSecretValue(
    "JWT_SECRET",
    "us-east-2"
  );
  try {
    const auth = getAuthToken(event);
    validateToken(auth, JWT_SECRET);
    const mask = getValue(event);
    response = {
      statusCode: 200,
      body: JSON.stringify({
        function: "cidrToMask",
        input: mask,
        output: maskToCidr(mask),
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

function maskToCidr(mask: string) {
  const maskOctets = mask.split(".");
  if (maskOctets.length !== MASK_LENGTH) {
    throw new Error("Invalid mask");
  }
  for (let i = 0; i < maskOctets.length; i++) {
    const octet = parseInt(maskOctets[i]);
    if (isNaN(octet) || octet < MIN_MASK || octet > MAX_MASK) {
      throw new Error("Invalid mask");
    }
    maskOctets[i] = decimalToBinary(octet);
  }
  return countOnes(maskOctets.join(""));
}

function decimalToBinary(decimal: number) {
  return (decimal >> 0).toString(2);
}

function countOnes(binary: string) {
  let count = 0;
  let seenZero = false;
  for (let i = 0; i < binary.length; i++) {
    if (seenZero && binary[i] === BINARY_ONE) {
      throw new Error("Invalid mask");
    }
    if (binary[i] === BINARY_ZERO) {
      seenZero = true;
    } else {
      count++;
    }
  }
  return count.toString();
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
