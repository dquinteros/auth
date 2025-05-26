import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { FastifyRequest, FastifyReply } from 'fastify';

interface JWTPayload {
  sub: string;
  email: string;
  tenantId: string;
  roles: string[] | string;
  permissions: string[] | string;
  iat: number;
  exp: number;
}

const client = jwksClient({
  jwksUri: `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${process.env.AWS_COGNITO_USER_POOL_ID}/.well-known/jwks.json`,
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 600000
});

const getKey = (header: any, callback: any) => {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err);
      return;
    }
    const signingKey = key?.getPublicKey();
    callback(null, signingKey);
  });
};

export const authenticateToken = async (
  request: FastifyRequest,
  reply: FastifyReply
) => {
  try {
    const authHeader = request.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return reply.code(401).send({
        error: 'Unauthorized',
        message: 'Missing or invalid authorization header'
      });
    }

    const token = authHeader.substring(7);

    const decoded = await new Promise<JWTPayload>((resolve, reject) => {
      jwt.verify(
        token,
        getKey,
        {
          audience: process.env.AWS_COGNITO_CLIENT_ID,
          issuer: `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${process.env.AWS_COGNITO_USER_POOL_ID}`,
          algorithms: ['RS256']
        },
        (err, decoded) => {
          if (err) reject(err);
          else resolve(decoded as JWTPayload);
        }
      );
    });

    (request as any).user = {
      userId: decoded.sub,
      email: decoded.email,
      tenantId: decoded.tenantId,
      roles: Array.isArray(decoded.roles) ? decoded.roles : JSON.parse(decoded.roles || '[]'),
      permissions: Array.isArray(decoded.permissions) ? decoded.permissions : JSON.parse(decoded.permissions || '[]')
    };
  } catch (error) {
    request.log.error('Token validation failed:', error);
    return reply.code(401).send({
      error: 'Unauthorized',
      message: 'Invalid or expired token'
    });
  }
};
