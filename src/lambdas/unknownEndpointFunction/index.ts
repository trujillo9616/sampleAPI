import { APIGatewayProxyResult } from "aws-lambda";

exports.handler = async (): Promise<APIGatewayProxyResult> => {
  return {
    statusCode: 400,
    body: JSON.stringify({
      error: "Unknown endpoint",
    }),
  };
};
