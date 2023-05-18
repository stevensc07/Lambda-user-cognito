"use strict";
require("dotenv").config();
const AWS = require("aws-sdk");
const cognito = new AWS.CognitoIdentityServiceProvider();
const ajvO = require("ajv");
const ajvRq = new ajvO();
const schemaAuthRq = require("./schemas/rqAuthSchema.json");
const validateAuthRq = ajvRq.compile(schemaAuthRq);

module.exports.loginUser = async (event) => {
  try {
    const { email, password } = JSON.parse(event.body);
    let valid = validateAuthRq({ email, password });

    if (!valid) {
      return {
        statusCode: 406,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Credentials": true,
        },
        body: JSON.stringify({
          message: "Empty fields are not accepted!",
          details: validateAuthRq.errors[0],
        }),
      };
    }
    const { user_pool_id, client_id } = process.env;
    const params = {
      AuthFlow: "ADMIN_NO_SRP_AUTH",
      UserPoolId: user_pool_id,
      ClientId: client_id,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password,
      },
    };
    const response = await cognito.adminInitiateAuth(params).promise();
    return {
      statusCode: 200,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": true,
      },
      body: JSON.stringify({
        message: "Success",
        token: response.AuthenticationResult.IdToken,
      }),
    };
  } catch (error) {
    const message = error.message ? error.message : "Internal server error";
    return {
      statusCode: 200,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": true,
      },
      body: JSON.stringify({
        message,
      }),
    };
  }
};

module.exports.signupUser = async (event) => {
  try {
    const { email, password } = JSON.parse(event.body);
    let valid = validateAuthRq({ email, password });

    if (!valid) {
      return {
        statusCode: 406,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Credentials": true,
        },
        body: JSON.stringify({
          message: "Empty fields are not accepted!",
          details: validateAuthRq.errors[0],
        }),
      };
    }
    const { user_pool_id } = process.env;
    const params = {
      UserPoolId: user_pool_id,
      Username: email,
      UserAttributes: [
        {
          Name: "email",
          Value: email,
        },
        {
          Name: "email_verified",
          Value: "true",
        },
      ],
      MessageAction: "SUPPRESS",
    };
    const response = await cognito.adminCreateUser(params).promise();
    if (response.User) {
      const paramsForSetPass = {
        Password: password,
        UserPoolId: user_pool_id,
        Username: email,
        Permanent: true,
      };
      await cognito.adminSetUserPassword(paramsForSetPass).promise();
    }
    return {
      statusCode: 200,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": true,
      },
      body: JSON.stringify({ message: "User registration successful" }),
    };
  } catch (error) {
    const message = error.message ? error.message : "Internal server error";
    return {
      statusCode: 200,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": true,
      },
      body: JSON.stringify({ message }),
    };
  }
};

