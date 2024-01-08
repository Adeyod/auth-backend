import nodemailer from 'nodemailer';

const verifyEmail = async (email, link) => {
  try {
    // create transporter
    const transporter = nodemailer.createTransport({
      host: process.env.HOST,
      port: process.env.EMAIL_PORT,
      secure: process.env.SECURE,
      service: process.env.SERVICE,
      auth: {
        user: process.env.USER,
        pass: process.env.PASS,
      },
      tls: { rejectUnauthorized: false },
    });

    // send mail
    const info = await transporter.sendMail({
      from: process.env.USER,
      to: email,
      subject: 'Verify your email',
      text: 'Welcome',
      html: `
      <div>
      <p>Thank you for registering on our website. Please verify your email to be able to login and use our services</p>
      <a href=${link}>Click here to verify your email</a>
      </div>
      `,
    });
  } catch (error) {
    console.error(error);
  }
};

export { verifyEmail };
