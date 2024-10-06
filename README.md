# cognito-srp-php

Helper written by PHP to get through SRP authentication for Amazon Cognito.

This was written in reference to the [jenky/AwsCognitoIdentitySRP.php](https://gist.github.com/jenky/a4465f73adf90206b3e98c3d36a3be4f).

## Install

```shell
composer require yasuaki640/cognito-srp-php
```

## Usage

```php
    // instantiate helper
    $srpHelper = new CognitoSrp(
        'your client id',
        'your pool id',
        'your client secret (if set)',
    );
    
    $result = $client->adminInitiateAuth([
        'AuthFlow' => 'USER_SRP_AUTH',
        'ClientId' => 'your client id',
        'UserPoolId' => 'your client secret (if set)',
        'AuthParameters' => [
            'USERNAME' => $username,
             // calculate A
            'SRP_A' => $srpHelper->largeA()->toHex(),
             // calculate secret Hash
            'SECRET_HASH' => $srpHelper->cognitoSecretHash($username),
        ],
    ]);

    $authRes = $client->adminRespondToAuthChallenge([
        'ChallengeName' => 'PASSWORD_VERIFIER',
        'UserPoolId' => 'your pool id',
        'ClientId' => 'your client id',
        // generate authentication challenge response params
        'ChallengeResponses' => $srpHelper->processChallenge($result, $username, $password), 
    ]);
```