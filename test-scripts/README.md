## Setup

- Set the API path in the file `scimapi_env`
- Get your eppn in the eduid dashboard (hubba-bubba in this example), and enter it in the
  `scimapi_env` file, suffixed by @eduid.se
- Run `find.sh` to find your SCIM UUID

```
  $ ./find.sh
  ...
  Response:
  {
    ...
    "id": "d4aa1c10-7120-452b-a109-adf9030b9ef3",
    "externalId": "hubba-bubba@eduid.se",
    "https://scim.eduid.se/schema/nutid/v1": {
      "displayName": "Your Name"
    }
  }
```

- Enter your SCIM UUID (d4aa1c10-7120-452b-a109-adf9030b9ef3) in the `scimapi_env` file

The `scimapi_env` file should now contain the following:

```
  api='https://api.example.org'
  scim_id='d4aa1c10-7120-452b-a109-adf9030b9ef3'
  eduid_eppn='hubba-bubba@eduid.se'
```

- Use set-display-name.sh to change your display name:

```
  $ ./set-display-name.sh "Kalle Anka"
  ...
  Response:

  {
    ...
    "https://scim.eduid.se/schema/nutid/v1": {
      "displayName": "Kalle Anka"
    }
  }
```
