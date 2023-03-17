import { APIGatewayProxyResult, APIGatewayProxyEvent } from "aws-lambda";
const AWS = require("aws-sdk");
const nodeCrypto = require("crypto");
const dynamodb = new AWS.DynamoDB.DocumentClient();

const USERS_TABLE = process.env.USERS_TABLE || "";

exports.handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  let response: APIGatewayProxyResult;

  try {
    const [username, password, role] = getBodyParams(event);
    const user = await getUser(username);
    if (user) {
      throw new Error("User already exists");
    }
    const salt = generateSalt();
    const userData = {
      id: username,
      username,
      salt,
      password: hashPassword(password, salt),
      role,
    };
    const savedUser = await saveUser(userData);
    response = {
      statusCode: 200,
      body: JSON.stringify({
        function: "register",
        user: savedUser,
      }),
    };
  } catch (error) {
    response = {
      statusCode: 400,
      body: JSON.stringify({
        error: error.message,
      }),
    };
  }
  return response;
};

function getBodyParams(event: APIGatewayProxyEvent): string[] {
  if (!event.body) {
    throw new Error("Missing body");
  }
  const body = JSON.parse(event.body);
  if (!body.username || !body.password || !body.role) {
    throw new Error("Missing username, password or role");
  }
  return [body.username, body.password, body.role];
}

function generateSalt() {
  return nodeCrypto.randomBytes(16).toString("hex");
}

function hashPassword(password: string, salt: string) {
  return nodeCrypto
    .createHash("sha512")
    .update(password + salt)
    .digest("hex");
}

function getUser(username: string) {
  const params = {
    TableName: USERS_TABLE,
    Key: {
      id: username,
    },
  };
  return dynamodb
    .get(params)
    .promise()
    .then((result: any) => (result.Item ? result.Item : null));
}

function saveUser(user: any) {
  const params = {
    TableName: USERS_TABLE,
    Item: user,
  };
  return dynamodb
    .put(params)
    .promise()
    .then(() => user);
}
