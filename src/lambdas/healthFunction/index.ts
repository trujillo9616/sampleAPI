import { APIGatewayProxyResult } from "aws-lambda";

exports.handler = async (): Promise<APIGatewayProxyResult> => {
  return {
    statusCode: 200,
    body: JSON.stringify({
      status: "OK",
    }),
  };
};
