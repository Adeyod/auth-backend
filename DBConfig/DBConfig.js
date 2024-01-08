import mongoose from 'mongoose';
import dotenv from 'dotenv';
dotenv.config();

const DBConfig = mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log(
      `MongoDB connected to database successfully on ${mongoose.connection.host}`
    );
  })
  .catch((err) => {
    console.error(err.message);
    console.log(`MongoDB unable to connect`);
  });

export default DBConfig;
