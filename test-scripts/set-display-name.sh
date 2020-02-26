#!/bin/bash

new="$1"

if [[ ! $new ]]; then
    echo "Syntax: $0 new-display-name"
    exit 1
fi

source scimapi_env

if [[ ! $api ]]; then
    echo "API not configured"
    exit 1
fi

if [[ ! $scim_id ]]; then
    echo "SCIM user id not configured"
    exit 1
fi

json=$(curl "${api}/Users/${scim_id}")

echo "$json" | jq

update=$(echo $json | jq ".\"https://scim.eduid.se/schema/nutid/v1\".displayName = \"${new}\"")

echo ""
echo "Update:"
echo ""
echo "$update" | jq

curl -X PUT -v --data "${update}" \
     -H 'Content-Type: application/scim+json' \
     "${api}/Users/${scim_id}"

echo ""
