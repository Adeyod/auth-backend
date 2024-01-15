import cookieParser from 'cookie-parser';
import express from 'express';
import DBConfig from './DBConfig/DBConfig.js';
import cors from 'cors';
import authRoute from './routes/authRoute.js';

const app = express();

// middlewares
app.use(
  cors({
    // origin: 'http://localhost:5173',
    origin: 'https://my-auth-frontend.netlify.app',
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader(
    'Access-Control-Allow-Origin',
    // 'http://localhost:5173'
    'https://my-auth-frontend.netlify.app'
  ); // Replace with your frontend origin
  // Other headers...
  next();
});

app.use([
  cookieParser(),
  express.json(),
  express.urlencoded({ extended: true }),
]);

app.get('/', (req, res) => {
  res.send('Welcome to the home page');
});

// routes
app.use('/api', authRoute);

const port = process.env.PORT || 4400;
app.listen(port, () => {
  console.log(`Server connected successfully on port ${port}`);
});
