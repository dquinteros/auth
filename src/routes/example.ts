import { FastifyInstance } from 'fastify';
import { authenticateToken } from '../middleware/auth';

export default async function exampleRoutes(fastify: FastifyInstance) {
  fastify.get('/example', { preHandler: authenticateToken }, async () => {
    return { message: 'Authorized access' };
  });
}
