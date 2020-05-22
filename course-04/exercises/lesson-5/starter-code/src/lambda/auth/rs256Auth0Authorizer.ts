
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJMEpMklHyew74MA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMTFmRldi01MGphLWotZi5hdXRoMC5jb20wHhcNMjAwNTIwMjEzMDU2WhcNMzQw
MTI3MjEzMDU2WjAhMR8wHQYDVQQDExZkZXYtNTBqYS1qLWYuYXV0aDAuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+GuLn30VEfKUqD4NFZSG9UMg
JYaSDg1dcAJewDRktFT7ynDWuJuAdJcYkOAxLO+9FF9p6Y7OFectK5UYjWL4Ng97
duKd6EqOGd+WRFdxdYS77Lb2VL1HC4jYybSj6qWcosr0xmknQ6VeNPfN7AEjIcgk
Xz8GvkeIdACDmxWEoJQTgzFiJtwn81hOw9eGwY/6CldykGwgZoCmHGzsbZHWh4Fx
rPPH/oKtEm/hM5U+YbXqX6rjKipYhxA7KQQLC2NioBmFaMRwuCZR2xMX4bLoq0Gd
7hg/a7+Yh0afULyMW+XGsq2oRGL+GsafO02zlMTe3C9SeIv6bE3ACcRqCqhhgwID
AQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSOlXCubiGIgPOAeCky
+Jibp+5eLzAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAGuKnaP5
xPDI3SOhjMtTSMzTXLjaJR4J+LVbPazkwGVWh3rnCJoIDfRkFVyqwDyShQ8jqDny
MA9X/ypyWHjg2J1YEGYJSfu04KJyxs+XbmFKKVWFC+YVfsNHjEfbzZFcfghGICtm
J6sPegUxE/OjcBzKaXe0DkkL2hfe5WRyNDjZ2nykVbmNBLCDNSiXawuMliQPQRv2
D+x0BBh48IgkKTfIVO868nct53sqbaNWQDDui//Wsqq8QuboiNp5uhaKS+w0mzJg
P8nzAP12CR+nyf4j0pvzoxiMGRJQfR3x8cfI27FuUE1lxA/YDhvm0Fc1fRAkMGWE
g+VPEM+hryqZFiE=
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}
