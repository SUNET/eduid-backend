## Setup

- Get your eppn in the eduid dashboard (hubba-bubba in this example), and suffix it with `@eduid.se`
- Create a YAML file called for example `test.yaml`, with initial contents like this
 (with the path to the API being `http://scimapi.eduid.docker:8000` in this example):

```
---
  'http://scimapi.eduid.docker:8000':
    'users':
      'search':
        'externalId':
           - 'hubba-bubba@eduid.se'
    'groups':
      'search':
         - 'Test Group 1'
```

- Run `scim-util.py test.yaml` to find your SCIM UUID. Note that scim-util.py requires Python 3.7.

```
  $ ./scim-util.py test.yaml
  ...
  2020-03-11 11:08:46,131: scim-util: INFO User search result:
  {
    ...
    "id": "d4aa1c10-7120-452b-a109-adf9030b9ef3",
    "externalId": "hubba-bubba@eduid.se",
  }
  ...
  2020-04-09 11:39:51,685: scim-util: INFO Group create result:
  {
    ...
    "displayName": "Test Group 1",
    "id": "8b5a3e6f-709d-4ae9-961d-bc73bfa51deb",
  }
```

- Add a PUT operation to the `test.yaml` file like this:

```
---
  'http://scimapi.eduid.docker:8000':
    'users':
      'search':
        'externalId':
           - 'hubba-bubba@eduid.se'
      'put':
        'd4aa1c10-7120-452b-a109-adf9030b9ef3':
          'profiles':
            'student':
	          'attributes':
              'displayName': 'Kalle Anka'
	        'data':
              'some-opaque-data': 17,

    'groups':
      'search':
         - 'Test Group 1'
      'put':
        '8b5a3e6f-709d-4ae9-961d-bc73bfa51deb':
          'display_name': 'Test Group 1'
          'members':
            - 'id': 'd4aa1c10-7120-452b-a109-adf9030b9ef3'
              'display_name': 'Donald Duck'
```

- Run `scim-util.py test.yaml` again to change your eduID display name:

```
  $ ./scim-util.py test.yaml
  ...
  2020-03-11 11:11:59,025: scim-util: INFO Update result:
  {'https://scim.eduid.se/schema/nutid/v1':
     {'student': {'attributes': {
                    'displayName': 'Kalle Anka'},
		 },
		 {'data': {
		    'some-opaque-data': 17
		   }
		 }
     },
  ...
  }
  ...
  2020-04-09 11:48:17,389: scim-util: INFO Update result:
  {
    "displayName": "Test Group 1",
    "id": "8b5a3e6f-709d-4ae9-961d-bc73bfa51deb",
    "members": [
        {
            "$ref": "http://scimapi.eduid.docker:8000/Users/d4aa1c10-7120-452b-a109-adf9030b9ef3",
            "display": "Donald Duck",
            "value": "d4aa1c10-7120-452b-a109-adf9030b9ef3"
        }
    ],
    ...
  }
```


## Search operations

To search for one or more users based on their externalId:

```
---
  'http://scimapi.eduid.docker:8000':
    'users':
      'search':
        'externalId':
           - 'hubba-bubba@eduid.se'
```

To search for users based on last modification timestamp:

```
---
  'http://scimapi.eduid.docker:8000':
    'users':
      'search':
        'lastModified':
           'ge':
             - '2020-03-31T14:01:55.830000+00:00'
```

Supported operations for this search:
  - 'gt' (greater than)
  - 'ge' (greater than, or equal)


## Authorization

The API uses (currently optional) bearer tokens for authorization. As a first step during development,
bearer tokens can be requested without authentication from the /login endpoint.

```
---
  'http://scimapi.eduid.docker:8000':
    'login':
      url: 'http://scimapi.eduid.docker:8000/login'
      data_owner: 'eduid.se'
    'users':
      'search':
        'externalId':
           - 'hubba-bubba@eduid.se'
```
