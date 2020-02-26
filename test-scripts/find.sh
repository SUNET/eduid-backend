#!/bin/bash

source scimapi_env

if [[ ! $api ]]; then
    echo "API not configured"
    exit 1
fi

if [[ ! $eduid_eppn ]]; then
    echo "eduID eppn not configured"
    exit 1
fi

json="
{
  \"schemas\": [\"urn:ietf:params:scim:api:messages:2.0:SearchRequest\"],
  \"attributes\": [\"givenName\", \"familyName\"],
  \"filter\": \"externalId eq \\\"${eduid_eppn}\\\"\",
  \"startIndex\": 1,
  \"count\": 1
}
"

echo "Query:"
echo "${json}" | jq

resp=$(curl --data "${json}" \
     -H 'Content-Type: application/scim+json' \
     "${api}/Users/.search")

echo ""
echo "Response:"
echo "${resp}" | jq


echo ""
