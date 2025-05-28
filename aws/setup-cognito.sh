#!/bin/bash

set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
USER_POOL_NAME="${COGNITO_USER_POOL_NAME:-api-gateway-users}"
CLIENT_NAME="${COGNITO_APP_CLIENT_NAME:-api-gateway-client}"

echo "Creating Cognito User Pool: $USER_POOL_NAME in $REGION"

USER_POOL_ID=$(aws cognito-idp create-user-pool \
  --region "$REGION" \
  --pool-name "$USER_POOL_NAME" \
  --policies '{
    "PasswordPolicy": {
      "MinimumLength": 8,
      "RequireUppercase": true,
      "RequireLowercase": true,
      "RequireNumbers": true,
      "RequireSymbols": false
    }
  }' \
  --auto-verified-attributes email \
  --username-attributes email \
  --verification-message-template '{
    "DefaultEmailOption": "CONFIRM_WITH_CODE",
    "DefaultEmailSubject": "Your verification code",
    "DefaultEmailMessage": "Your verification code is {####}"
  }' \
  --output json | jq -r '.UserPool.Id')

if [[ -z "$USER_POOL_ID" ]]; then
  echo "Failed to create user pool" >&2
  exit 1
fi

echo "User Pool created with ID: $USER_POOL_ID"

echo "Creating App Client: $CLIENT_NAME"

CLIENT_ID=$(aws cognito-idp create-user-pool-client \
  --region "$REGION" \
  --user-pool-id "$USER_POOL_ID" \
  --client-name "$CLIENT_NAME" \
  --generate-secret \
  --explicit-auth-flows ADMIN_NO_SRP_AUTH ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH \
  --token-validity-units '{
    "AccessToken": "hours",
    "IdToken": "hours",
    "RefreshToken": "days"
  }' \
  --access-token-validity 24 \
  --id-token-validity 24 \
  --refresh-token-validity 30 \
  --output json | jq -r '.UserPoolClient.ClientId')

if [[ -z "$CLIENT_ID" ]]; then
  echo "Failed to create app client" >&2
  exit 1
fi

echo "App Client created with ID: $CLIENT_ID"

echo "\nCognito setup complete."

