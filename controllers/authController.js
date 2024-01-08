import User from '../models/userModel.js';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import Token from '../models/tokenModel.js';
import { verifyEmail } from '../utils/nodemailer.js';
import { generateToken } from '../utils/jwtVerification.js';

// user registration
const userRegister = async (req, res) => {
  try {
    const { email, firstName, lastName, password, confirmPassword } = req.body;

    if (!email || !firstName || !lastName || !password || !confirmPassword) {
      return res.json({
        message: 'All fields are required',
        status: 400,
        success: false,
      });
    }

    const trimmedEmail = email.trim();
    const trimmedFirstName = firstName.trim();
    const trimmedLastName = lastName.trim();

    // check the firstName field to prevent input of unwanted characters
    if (!/^[a-zA-Z0-9 -]+$/.test(trimmedFirstName)) {
      return res.json({
        message: 'Invalid input for the first name...',
        status: 400,
        success: false,
      });
    }

    // check the lastName field to prevent input of unwanted characters
    if (!/^[a-zA-Z0-9 -]+$/.test(trimmedLastName)) {
      return res.json({
        message: 'Invalid input for the last name...',
        status: 400,
        success: false,
      });
    }

    // check the email field to prevent input of unwanted characters
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      return res.json({
        message: 'Invalid input for email...',
        status: 400,
        success: false,
      });
    }

    // strong password check
    if (
      !/^(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-])(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9]).{8,20}$/.test(
        password
      )
    ) {
      return res.json({
        message:
          'Password must contain at least 1 special character, 1 lowercase letter, and 1 uppercase letter. Also it must be minimum of 8 characters and maximum of 20 characters',
        success: false,
        status: 401,
      });
    }

    // check if password and confirm password matches
    if (password !== confirmPassword) {
      return res.json({
        message: 'Password do not match',
        success: false,
        status: 400,
      });
    }

    const emailExist = await User.findOne({ email });
    if (emailExist) {
      return res.json({
        message: 'Email already chosen',
        status: 400,
        success: false,
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await new User({
      email,
      firstName,
      lastName,
      password: hashedPassword,
    }).save();

    const { password: hashedPassword2, ...others } = newUser._doc;

    // generate token using crypto
    const verificationToken =
      crypto.randomBytes(16).toString('hex') +
      crypto.randomBytes(16).toString('hex');

    const token = await new Token({
      token: verificationToken,
      user: others._id,
    }).save();

    const link = `${process.env.FRONTEND}/${others._id}/${token.token}`;
    verifyEmail(newUser.email, link);

    return res.json({
      message: `${others.firstName} your account was created successfully. Please check your email for email verification link. Link expires in 15mins`,
      status: 201,
      success: true,
    });
  } catch (error) {
    console.error(error.message);
    return res.json({
      message: 'Something happened',
      status: 500,
      success: false,
    });
  }
};

// email verification
const verifyUserEmail = async (req, res) => {
  try {
    const { userId, token } = req.params;
    const user = await User.findById({ _id: userId });
    if (!user) {
      return res.json({
        message: 'User can not be found',
        status: 400,
        success: false,
      });
    }

    console.log(token);
    const checkToken = await Token.findOne({
      token,
    });
    if (!checkToken) {
      return res.json({
        message: 'Token not found',
        status: 404,
        success: false,
      });
    }

    const updateUser = await User.findByIdAndUpdate(
      { _id: userId },
      {
        $set: {
          isVerified: true,
        },
      }
    );
    if (!updateUser) {
      return res.json({
        message: 'Error verifying user',
        status: 400,
        success: false,
      });
    }

    const deleteToken = await Token.findOneAndDelete({ token });

    return res.json({
      message: 'Email verified successfully',
      status: 200,
      success: true,
    });
  } catch (error) {
    console.error(error);
  }
};

// resend email verification link
const resendEmail = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.json({
        message: 'Email does not exist',
        status: 404,
        success: false,
      });
    }

    const trimmedEmail = email.trim();
    // check the email field to prevent input of unwanted characters
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      return res.json({
        message: 'Invalid input for email...',
        status: 400,
        success: false,
      });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.json({
        message: 'Email does not exist',
        status: 400,
        success: false,
      });
    }

    if (user.isVerified === true) {
      return res.json({
        message: 'User is already verified',
        success: false,
      });
    }

    // check if token exist in database
    const checkToken = await Token.findOne({
      user: user._id,
    });

    if (!checkToken) {
      const verificationToken =
        crypto.randomBytes(16).toString('hex') +
        crypto.randomBytes(16).toString('hex');

      const token = await new Token({
        token: verificationToken,
        user: user._id,
      }).save();

      const link = `${process.env.FRONTEND}/${token.user}/${token.token}`;

      verifyEmail(user.email, link);
      return res.json({
        message: `${user.firstName} please verify your email address`,
        success: true,
      });
    }

    const link = `${process.env.FRONTEND}/${checkToken.user}/${checkToken.token}`;

    verifyEmail(user.email, link);
    return res.json({
      message: `${user.firstName} please verify your email address`,
      success: true,
    });
  } catch (error) {
    return res.json({
      message: 'Something happened',
      status: 500,
      success: false,
    });
  }
};

// user login
const userLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.json({
        message: 'All fields are required',
        status: 400,
        success: false,
      });
    }

    // prevent unwanted characters with regex
    const trimmedEmail = email.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      return res.json({
        message: 'Invalid format in email field...',
        status: 401,
        success: false,
      });
    }

    // check for password length
    if (password.length < 8 || password.length > 20) {
      return res.json({
        message:
          'Password must be minimum of 8 characters and  maximum of 20 characters',
        status: 411,
        success: false,
      });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.json({
        message: 'Invalid credentials',
        status: 404,
        success: false,
      });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.json({
        message: 'Invalid credential',
        success: false,
        status: 404,
      });
    }

    if (!user.isVerified) {
      // check if there is a token in the database
      const tokenExist = await Token.findOne({ user: user._id });

      if (!tokenExist) {
        // generate token and send
        const verificationToken =
          crypto.randomBytes(16).toString('hex') +
          crypto.randomBytes(16).toString('hex');

        const token = await new Token({
          token: verificationToken,
          user: user._id,
        }).save();

        const link = `${process.env.FRONTEND}/${user._id}/${token.token}`;
        verifyEmail(user.email, link);
        return res.json({
          message: 'Please verify your email.',
          success: false,
        });
      }

      const link = `${process.env.FRONTEND}/${tokenExist.user}/${tokenExist.token}`;
      verifyEmail(res, user.email, link);
      return res.json({
        message: `${user.firstName} please check your email and verify you email address`,
        success: false,
      });
    }

    const { password: hashedPassword, ...others } = user._doc;
    const token = await generateToken(res, user._id, user.email);

    return res.json({
      message: 'User fetched successfully',
      status: 200,
      user: others,
      success: true,
    });
  } catch (error) {
    console.error(error);
    return res.json({
      message: 'Something happened',
      success: false,
      status: 500,
    });
  }
};

const logout = (req, res) => {
  try {
    const cookies = req.cookies;
    if (!cookies?.access_token) {
      return res.json({
        message: 'No access token',
        status: 404,
      });
    }
    res.clearCookie('access_token', {
      httpOnly: true,
      sameSite: 'None',
      secure: true,
    });

    return res.json({
      message: 'logout successful',
      success: true,
    });
  } catch (error) {
    return res.json({
      message: 'Something happened',
      status: 500,
      success: false,
    });
  }
};

export { userLogin, logout, userRegister, resendEmail, verifyUserEmail };
