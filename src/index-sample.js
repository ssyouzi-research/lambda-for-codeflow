import { createRemoteJWKSet, jwtVerify, decodeJwt } from 'jose';
import https from 'https';
import querystring from 'querystring';

const env = {
    'URL': 'https://www.googleapis.com/oauth2/v3/certs',
    'TOKEN_ENDPOINT': 'https://oauth2.googleapis.com/token',
    'ISSUER': 'https://accounts.google.com',
    'CLIENT_ID': 'YOUR-CLIENT-ID.apps.googleusercontent.com',
    'CLIENT_SECRET': 'YOUR-CLIENT-SECRET',
    'SUBJECT': 'YOUR-SUBJECT',
    'REDIRECT_URI': 'https://your-cloudfront-domain/callback'
};

const JWKS = createRemoteJWKSet(
  new URL(env.URL)
);
const issuer = env.ISSUER;
const audience = env.CLIENT_ID;

const subject = env.SUBJECT;

async function verifyOidcTokenWithoutExpireCheck(token) {
  const payload = decodeJwt(token);
  if (payload.iss == issuer && payload.aud == audience && payload.sub == subject) {
    return payload;
  }
  console.error('Token verification failed');
  return false;
}

async function verifyOidcToken(token) {
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      'issuer': issuer,
      'audience': audience
    });

    if (payload.sub != subject) {
      throw new Error(`Invalid subject: ${payload.sub}`);
    }

    return payload;
  } catch (error) {
    console.error('Token verification failed:', error);
    return false;
  }
}

async function exchangeCodeForTokens(code) {
    const tokenEndpoint = env.TOKEN_ENDPOINT;
    const clientSecret = env.CLIENT_SECRET;
    const redirectUri = env.REDIRECT_URI;

    const postData = querystring.stringify({
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirectUri,
        'client_id': audience,
        'client_secret': clientSecret
    });

    return new Promise((resolve, reject) => {
        const options = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(postData)
            }
        };

        const req = https.request(tokenEndpoint, options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode === 200) {
                    resolve(JSON.parse(data));
                } else {
                    reject(new Error(`Token exchange failed: ${res.statusCode}`));
                }
            });
        });

        req.on('error', reject);
        req.write(postData);
        req.end();
    });
}

export const handler = async (event, context, callback) => {
  const request = event.Records[0].cf.request;
  console.log(JSON.stringify(request));
  const uri = request.uri;
  const method = request.method;
  if (uri == '/callback' && method == 'GET') {
    const querystring = request.querystring;
    const params = {};
    querystring.split('&').map((param) => {
      const keyValue = param.split('=');
      const key = keyValue[0];
      const value = keyValue[1];
      params[key] = value;
    });
    if (params['code']) {
      const code = params['code'];
      try {
        const tokenResponse = await exchangeCodeForTokens(decodeURIComponent(code));
        const response = {
          'status': '302',
          'statusDescription': 'Found',
          'headers': {
            'location': [{
              'key': 'Location',
              'value': '/'
            }],
            'set-cookie': [{
              'key': 'Set-Cookie',
              'value': `jwt_token=${tokenResponse.id_token}; Path=/; Secure; HttpOnly`
            }]
          }
        };
        callback(null, response);
      } catch (error) {
        const response = {
          'status': '403',
          'statusDescription': 'Forbidden',
          'headers': {
            'content-type': [{
              'key': 'Content-Type',
              'value': 'text/html'
            }]
          }
        };
        callback(null, response);        
      }
      return;
    }
  }

  const cookie = request.headers['cookie'];
  if (cookie) {
    const cookies = cookie[0].value.split(';');
    for (let i = 0; i < cookies.length; i++) {
      const keyValue = cookies[i].split('=');
      const key = keyValue[0].trim();
      const value = keyValue[1].trim();
      if (key == 'jwt_token' && await verifyOidcToken(value)) {
        callback(null, request);
        return;
      }
    }
  }

  const response = {
    'status': '403',
    'statusDescription': 'Forbidden',
    'headers': {
      'content-type': [{
        'key': 'Content-Type',
        'value': 'text/html'
      }]
    }
  };
  callback(null, response);
  return;
};
