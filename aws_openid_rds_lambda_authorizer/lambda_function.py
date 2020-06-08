from __future__ import print_function
import requests
import json
import urllib.parse
import uuid
import jwt as jwt
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import os
import re
import logging
import pymysql

def format_as_pem(cert_string):
    """Adds ASCII armor to the specified PEM base46 certificate."""
    i = 64
    while i<len(cert_string):
        cert_string = cert_string[0:i] + '\n' + cert_string[i:]
        i+=65
    cert_string = "-----BEGIN CERTIFICATE-----\n" + cert_string + "\n-----END CERTIFICATE-----"
    return cert_string

def find_key(jwks_keys, key_id):
    """Finds the  coresponding signing key for the provided key id."""
    key_found = False
    cert_string = ''
    
    for key in jwks_keys['keys']:
        print(str(key))
        if key['kid'] == key_id:
            key_found = True
            cert_string = key['x5c'][0]
    
    return (key_found, cert_string)

def lambda_handler(event, context):
    """This AWS lambda handler validates JWT Tokens and
    builds a policy "on the fly" with the rules stored in a RDS
    backend.
    
    This function works validating the Bearer token against the
    certificates published over the Well-known configuration
    for the specified OpenID provider. The 'unique_name' claim
    is then used to look-up for the access rules stored in a RDS
    backend.
    
    Please consider that by the time this lambda authorizer was
    written, the "lambda RDS proxys" were on "preview" status. If you want
    to allow this lambda to connect to  a RDS backend you'll have to:
    1. Configure a VPC with access to your RDS Instance.
    2. Provide lambda role permissions to create EC2 network interfaces.
    3. Enable NAT to access the RDS instance.
    More info is available here:
    https://aws.amazon.com/premiumsupport/knowledge-center/internet-access-lambda-function/
    
    Derived from the AWS sample lambda authorizer function
    provided by Amazon.
    Copyright 2020 <mario.gomez@wfp.org>
    Apache License, Version 2.0
    """ 
    
    # RDS Connection settings from environment
    rds_host  = os.environ['RDS_INSTANCE_ENDPOINT']
    name = os.environ['DB_USERNAME']
    password = os.environ['DB_PASSWORD']
    db_name = os.environ['DB_NAME']
    
    # Start logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    # Extract token and do a first structure validaton
    token_elements = event['authorizationToken'].split(' ')
    # Split result must have two elements
    if len(token_elements) != 2:
      logger.error('Invalid Token format')
      raise Exception('Invalid token.')
    if token_elements[0]!='Bearer':
      logger.error('Token does not start with Bearer')
      raise Exception('Only Token Bearer Authorization header is allowed.')
    
    # JWT Token must be on the second element
    token = token_elements[1]
    
    logger.debug("Token received.")
    
    # We need the unverified token as we need to look up for the
    # certificate used to sign it.
    jwt_token_headers = None
    try:
      jwt_token_headers = jwt.get_unverified_header(token)
    except Exception as e:
      logger.error('Invalid Token format')
      logger.error(e)
      raise Exception('Unable to decode the provided token')
    
    logger.debug("Token decoded.")
    
    # Following code downloads the configuration and the
    # certificates used to sign the token.
    # This configuration files could be cached for performance, it will
    # depend on how paranoic you are about the possibility of the OpenID provider
    # changing/revoking the certificates.
    public_key = None
    try:
      response = requests.get(os.environ['OPENID_CONFIG_URI'])
      client_id = os.environ['APP_CLIENT_ID']
      openid_config = json.loads(response.content)
      response = requests.get(openid_config['jwks_uri'])
      jwks_keys = json.loads(response.content)
      
      # We extract the certificate used to sign the  token
      (key_found, cert_string) = find_key(jwks_keys,jwt_token_headers['kid'])
      cert_string = format_as_pem(cert_string)
      
      # We need to extract the public key from the certificate
      cert = x509.load_pem_x509_certificate(cert_string.encode('ascii'), default_backend())
      public_key = cert.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
    except Exception as e:
      logger.error('Unable to download certificates')
      logger.error(e)
      raise Exception('Unable to download OpenID provider certificates.')
    logger.debug("Certificates downloaded.")
    
    jwt_token = None
    try:
        # The decode function will both validate the token format and verify the signature
        jwt_token = jwt.decode(token, public_key, audience=os.environ['APP_CLIENT_ID'])
    except Exception as e:
        logger.error('Unable to verify token')
        logger.error(e)
        raise Exception('Unauthorized')
    logger.debug("Token verified.")
    
    # Extract PrincipalID from the token. (Usually this is an email address)
    principalId = jwt_token['unique_name']

    # Extract the ARN components for this call
    tmp = event['methodArn'].split(':')
    apiGatewayArnTmp = tmp[5].split('/')
    awsAccountId = tmp[4]

    policy = AuthPolicy(principalId, awsAccountId)
    policy.restApiId = apiGatewayArnTmp[0]
    policy.region = tmp[3]
    policy.stage = apiGatewayArnTmp[1]
    
    # Now we are ready to build the policy using the rules stored over
    # the RDS backend.
    conn = None
    try:
        conn = pymysql.connect(rds_host, user=name, passwd=password, db=db_name, connect_timeout=5)
    except pymysql.MySQLError as e:
        logger.error("ERROR: Unexpected error: Could not connect to MySQL instance.")
        logger.error(e)
        raise e
    
    # Extract permissions from RDS backend
    with conn.cursor() as cur:
        cur.execute("SELECT `method`,`path` FROM all_user_permissions WHERE email = %s", principalId)
        rows = cur.fetchall()
        count = 0
        # Allow methods and paths founds on the table
        for row in rows:
            count += 1
            policy.allowMethod(row[0],row[1])
        
        # If nothing is found. Then just deny all.
        if count == 0:
            policy.denyAllMethods()
    logger.debug('Policy generated.')
    conn.close()
    
    # Finally, build the policy
    authResponse = policy.build()
    logger.debug('Policy built.')

    # You can add additional key-value pairs associated with the authenticated principal
    # these are made available by APIGW like so: $context.authorizer.<key>
    # Useful for example if you want to copy claims values to the context for use
    # on the called lambda.
    # additional context is cached
    #context = {
    #    'user_email': principalId,
    #}
    # context['arr'] = ['foo'] <- this is invalid, APIGW will not accept it
    # context['obj'] = {'foo':'bar'} <- also invalid

    #authResponse['context'] = context

    return authResponse

class HttpVerb:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    PATCH = 'PATCH'
    HEAD = 'HEAD'
    DELETE = 'DELETE'
    OPTIONS = 'OPTIONS'
    ALL = '*'

class AuthPolicy(object):
    # The AWS account id the policy will be generated for. This is used to create the method ARNs.
    awsAccountId = ''
    # The principal used for the policy, this should be a unique identifier for the end user.
    principalId = ''
    # The policy version used for the evaluation. This should always be '2012-10-17'
    version = '2012-10-17'
    # The regular expression used to validate resource paths for the policy
    pathRegex = '^[/.a-zA-Z0-9-\*]+$'

    '''Internal lists of allowed and denied methods.

    These are lists of objects and each object has 2 properties: A resource
    ARN and a nullable conditions statement. The build method processes these
    lists and generates the approriate statements for the final policy.
    '''
    allowMethods = []
    denyMethods = []

    # The API Gateway API id. By default this is set to '*'
    restApiId = '*'
    # The region where the API is deployed. By default this is set to '*'
    region = '*'
    # The name of the stage used in the policy. By default this is set to '*'
    stage = '*'

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        '''Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null.'''
        if verb != '*' and not hasattr(HttpVerb, verb):
            raise NameError('Invalid HTTP verb ' + verb + '. Allowed verbs in HttpVerb class')
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError('Invalid resource path: ' + resource + '. Path should match ' + self.pathRegex)

        if resource[:1] == '/':
            resource = resource[1:]

        resourceArn = 'arn:aws:execute-api:{}:{}:{}/{}/{}/{}'.format(self.region, self.awsAccountId, self.restApiId, self.stage, verb, resource)

        if effect.lower() == 'allow':
            self.allowMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })
        elif effect.lower() == 'deny':
            self.denyMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })

    def _getEmptyStatement(self, effect):
        '''Returns an empty statement object prepopulated with the correct action and the
        desired effect.'''
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        '''This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy.'''
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            if statement['Resource']:
                statements.append(statement)

        return statements

    def allowAllMethods(self):
        '''Adds a '*' allow to the policy to authorize access to all methods of an API'''
        self._addMethod('Allow', HttpVerb.ALL, '*', [])

    def denyAllMethods(self):
        '''Adds a '*' allow to the policy to deny access to all methods of an API'''
        self._addMethod('Deny', HttpVerb.ALL, '*', [])

    def allowMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy'''
        self._addMethod('Allow', verb, resource, [])

    def denyMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy'''
        self._addMethod('Deny', verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Allow', verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Deny', verb, resource, conditions)

    def build(self):
        '''Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy.'''
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
                (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError('No statements defined for the policy')

        policy = {
            'principalId': self.principalId,
            'policyDocument': {
                'Version': self.version,
                'Statement': []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Allow', self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Deny', self.denyMethods))

        return policy
