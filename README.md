# Lambda Authorizer for OpenID/JWT Tokens and RDS Backend
This lambda authorizer function allows to use JWT Tokens generated by OAuth 2.0
authorization flows within the AWS API Gateway. Permissions to access individual
API functions can be stored within a table on a RDS backend (MariaDB implementation).

## How it Works?
This lambda authorizer expects a Bearer Authorization header containing a JWT Token.
The token must include a `unique_name` claim. The claim is then used to lookup for
permissions in a RDS table.

Token signature is validated against the public certificates exposed by the Well-known
OAuth configuration endpoint and a AWS policy is built "on-the-fly" using the permissions
stored in another RDS table.

To get the JWT Token from the OpenID provider please consult the provider documentation.

## Why?
There are a couple of reasons why you want to use a lambda authorizer like this for an
API Gateway Endpoint:
* Your IAM provider is hosted outside of AWS infrastructure.
* You want to keep it simple without going into the complexities of the AWS role management.
* Your application is fairly simple and you want to have a simple user/permission backend.

Please take into consideration that lambda authorizers come with a computational cost as they
are ran to check every request. However, you can enable cache to reduce a little bit the costs.

## Requirements
To use this lambda layer you must make sure you include the following libraries in a
Python layer:
* cryptography
* PyMySQL
* requests
* PyJWT

You can build each library as a separate layer or just make a big layer with all
the dependencies. You can find examples about how to create the python layers here:

https://github.com/mxgxw/aws_lambda_layers

## Configuration
You can change the configuration using environment variables:
- ***OPENID_CONFIG_URI***: Well-known configuration for the OpenID provider.
- ***APP_CLIENT_ID***: This is the 'audience' used to validate the JWT Tokens.
- ***RDS_INSTANCE_ENDPOINT***: RDS Instance endpoint.
- ***DB_NAME***: RDS Database name.
- ***DB_PASSWORD***: RDS Database password.
- ***DB_USERNAME***: RDS Database username.

To connect to a RDS instance from a lambda you could use RDS Proxys. However
they are not avaiable for all the availability regions and they are in "preview"
status.

To allow this lambda to connect to a RDS backend you'll have to:
1. Configure a VPC with access to your RDS Instance.
2. Provide lambda role permissions to create EC2 network interfaces.
3. Enable NAT* to access the RDS instance.
More info is available here:

https://aws.amazon.com/premiumsupport/knowledge-center/internet-access-lambda-function/

*Please take into consideration that NAT is not covered under the AWS Free-Tier.

## Copyrights
This code is based on the lambda authorizer example for Python from AWS.
Copyrights 2020 Mario Gómez <mxgxw.alpha@gmail.com>
Apache 2.0 License
