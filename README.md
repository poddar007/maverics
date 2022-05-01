### Request Body to be sent to Plain ID

https://oneauthorize.sandbox.ey.com/api/runtime/token/v4

```json
{
    "entityId": "<user id obtained after primary authentication>",
    "entityTypeId": "MyEY-Users",
    "clientId": "<client id>",
    "clientSecret": "<client secret>",
    "includeAssetAttributes": false,
    "includeAccessPolicy": false,
    "includeIdentity": false,
    "includeContext": false,
    "useCache": false,
    "contextData": {
        "application": [
            "<application name, primarily obtained for application gateway name>"
        ]
    }
}
```
