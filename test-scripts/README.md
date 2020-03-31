## Setup

- Get your eppn in the eduid dashboard (hubba-bubba in this example), and suffix it with `@eduid.se`
- Create a YAML file called for example `test.yaml`, with initial contents like this
 (with the path to the API being `http://scimapi.eduid.docker:8000` in this example):

```
---
  'http://scimapi.eduid.docker:8000':
    'users':
      'search':
         - 'hubba-bubba@eduid.se'
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
```

- Add a PUT operation to the `test.yaml` file like this:

```
---
  'http://scimapi.eduid.docker:8000':
    'users':
      'search':
         - 'hubba-bubba@eduid.se'
      'put':
        'd4aa1c10-7120-452b-a109-adf9030b9ef3':
          'profiles':
            'student':
	      'attributes':
                'displayName': 'Kalle Anka'
	      'data':
                'some-opaque-data': 17,

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
```
