import Fastify from 'fastify';
import exampleRoutes from './routes/example';

const server = Fastify();

server.register(exampleRoutes);

const start = async () => {
  try {
    const port = Number(process.env.PORT) || 3000;
    await server.listen({ port });
    console.log(`Server listening on port ${port}`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
};

start();
