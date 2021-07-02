## Setup

- Get your eppn in the eduid dashboard (hubba-bubba in this example), and suffix it with `@eduid.se`
- Create a YAML file called for example `test.yaml`, with initial contents like this
 (with the path to the API being `https://api.eduid.docker/scim` in this example):

``` yaml
---
  'https://api.eduid.docker/scim':
    'users':
      'search':
        'externalId':
           - 'hubba-bubba@eduid.se'
    'groups':
      'search':
        'displayName':
           - 'Test Group 1'
```

- Run `scim-util.py test.yaml` to find your SCIM UUID. Note that scim-util.py requires Python 3.7.

``` shell
  $ ./scim-util.py test.yaml
  ...
  2021-05-07 15:11:12,443: scim-util: INFO User search result:
  {
      "Resources": [
          {
              "id": "87c5ae99-9e98-49d5-9b84-2c210cacfea4"
          }
      ],
      "schemas": [
          "urn:ietf:params:scim:api:messages:2.0:ListResponse"
      ],
      "totalResults": 1
  }
  ...
  2021-05-07 15:11:12,519: scim-util: INFO Group search result:
  {
      "Resources": [
          {
              "displayName": "Test Group 1",
              "id": "ab2506e0-39a7-41cb-8370-1584b880b307"
          }
      ],
      "schemas": [
          "urn:ietf:params:scim:api:messages:2.0:ListResponse"
      ],
      "totalResults": 1
  }
```

- Add a PUT operation to the `test.yaml` file like this:

``` yaml
---
  'https://api.eduid.docker/scim':
    'users':
      'search':
        'externalId':
           - 'hubba-bubba@eduid.se'
      'put':
        '87c5ae99-9e98-49d5-9b84-2c210cacfea4':
          'profiles':
            'student':
              'attributes':
                'displayName': 'Kalle Anka'
              'data':
                'some-opaque-data': 17

    'groups':
      'search':
        'displayName':
           - 'Test Group 1'
      'put':
        'ab2506e0-39a7-41cb-8370-1584b880b307':
          'display_name': 'Test Group 1'
          'members':
            - 'id': '87c5ae99-9e98-49d5-9b84-2c210cacfea4'
              'display_name': 'Donald Duck'
          'data':
            'some-opaque-data': 17
```

- Run `scim-util.py test.yaml` again to change your eduID display name:

``` shell
  $ ./scim-util.py test.yaml
  ...
  2021-05-07 15:23:20,655: scim-util: INFO Update result:
  {
      "emails": [],
      "externalId": "hubba-bubba@eduid.se",
      "groups": [],
      "https://scim.eduid.se/schema/nutid/user/v1": {
          "linked_accounts": [],
          "profiles": {
              "student": {
                  "attributes": {
                      "displayName": "Kalle Anka"
                  },
                  "data": {
                      "some-opaque-data": 17
                  }
              }
          }
      },
      "id": "87c5ae99-9e98-49d5-9b84-2c210cacfea4",
      "meta": {
          "created": "2021-05-07T13:09:29.837000+00:00",
          "lastModified": "2021-05-07T13:22:04.196000+00:00",
          "location": "https://api.eduid.docker/scim/Users/87c5ae99-9e98-49d5-9b84-2c210cacfea4",
          "resourceType": "User",
          "version": "W/\"60953efc514fad85acdf4d6f\""
      },
      "name": {},
      "phoneNumbers": [],
      "schemas": [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "https://scim.eduid.se/schema/nutid/user/v1"
      ]
  }
  ...
  2021-05-07 15:23:21,371: scim-util: INFO Update result:
  {
      "displayName": "Test Group 1",
      "https://scim.eduid.se/schema/nutid/group/v1": {
          "data": {
              "some-opaque-data": 17
          }
      },
      "id": "ab2506e0-39a7-41cb-8370-1584b880b307",
      "members": [
          {
              "$ref": "https://api.eduid.docker/scim/Users/87c5ae99-9e98-49d5-9b84-2c210cacfea4",
              "display": "Donald Duck",
              "value": "87c5ae99-9e98-49d5-9b84-2c210cacfea4"
          }
      ],
      "meta": {
          "created": "2021-05-07T13:09:30.696000+00:00",
          "lastModified": "2021-05-07T13:23:20.860000+00:00",
          "location": "https://api.eduid.docker/scim/Groups/ab2506e0-39a7-41cb-8370-1584b880b307",
          "resourceType": "Group",
          "version": "W/\"60953f48514fad85acdf4d72\""
      },
      "schemas": [
          "urn:ietf:params:scim:schemas:core:2.0:Group",
          "https://scim.eduid.se/schema/nutid/group/v1"
      ]
  }
```

### Events

Add a POST operation for Events to the `test.yaml` file like this:

``` yaml
---
  'https://api.eduid.docker/scim':
    'events':
      'post':
        'user_event_1':
          'resource_scim_id': 'd4aa1c10-7120-452b-a109-adf9030b9ef3'
          'resource_type': 'User'
          'level': 'debug'
          'data':
            'message': 'debug message for a user'
            'test_key': 'test_value'
```

## Search operations

To search for one or more users based on their externalId:

``` yaml
---
  'https://api.eduid.docker/scim':
    'users':
      'search':
        'externalId':
           - 'hubba-bubba@eduid.se'
```

To search for users based on last modification timestamp:

``` yaml
---
  'https://api.eduid.docker/scim':
    'users':
      'search':
        'lastModified':
           'ge':
             - '2020-03-31T14:01:55.830000+00:00'
```

Supported operations for this search:
  - 'gt' (greater than)
  - 'ge' (greater than, or equal)


To search for one or more groups based on NUTID attributes:

``` yaml
---
  'https://api.eduid.docker/scim':
    'groups':
      'search':
        'extensions.data.foo':
          - 'bar'
      'put':
        'a3add4cf-ce03-4d5f-bb9a-e5cb864d7bbb':
          'display_name': 'Test Group 1'
          'members':
            - 'id': 'dd5d6f37-b60a-4859-b530-16ca181c4244'
              'display_name': 'Donald Duck'
          'data':
            'foo': 'bar'
```


## Authorization

The API uses (currently optional) bearer tokens for authorization. As a first step during development,
bearer tokens can be requested without authentication from the /login endpoint.

``` yaml
---
  'https://api.eduid.docker/scim':
    'login':      
      data_owner: 'eduid.se'
    'users':
      'search':
        'externalId':
           - 'hubba-bubba@eduid.se'
```
