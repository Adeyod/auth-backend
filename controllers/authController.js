import User from '../models/userModel.js';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import Token from '../models/tokenModel.js';
import { verifyEmail } from '../utils/nodemailer.js';
import { generateToken } from '../utils/jwtVerification.js';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';

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

    const link = `${process.env.FRONTEND}/verification/?userId=${others._id}&token=${token.token}`;

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
    const { userId, token } = req.body;
    console.log(req.body);
    const user = await User.findById({ _id: userId });
    if (!user) {
      return res.json({
        message: 'User can not be found',
        status: 400,
        success: false,
      });
    }

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
        message: 'Email can not be empty',
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

    const link = `${process.env.FRONTEND}/verification/?userId=${checkToken.user}&token=${checkToken.token}`;

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

        const link = `${process.env.FRONTEND}/verification/?userId=${user._id}&token=${token.token}`;
        verifyEmail(user.email, link);
        return res.json({
          message: 'Please verify your email.',
          success: false,
        });
      }

      const link = `${process.env.FRONTEND}/verification/?userId=${tokenExist.user}&token=${tokenExist.token}`;
      verifyEmail(user.email, link);

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

// credit user wallet
const payment = async (req, res) => {
  try {
    const user = req.user;

    // const { businessId } = req.params;

    // const business = await Business.findOne({ _id: businessId });

    // if (!business) {
    //   return res.json({
    //     message: 'Business does not exist',
    //     status: 404,
    //     success: false,
    //   });
    // }

    // const isMember = business.members.find((member) =>
    //   member.member.equals(user._id)
    // );
    // if (!isMember) {
    //   return res.json({
    //     message: 'User is not a member of the business',
    //     status: 404,
    //     success: false,
    //   });
    // }

    const itemInfo = 'Wallet crediting';

    const userInfo = {
      userId: user._id,
      // owner: business.owner,
      // creditor: isMember.member,
      // creditorRole: isMember.role,
      email: user.email,
    };

    const commandDetails = `${itemInfo} for user ${user.firstName}`;
    console.log(commandDetails);
    // this means that each wallet crediting requires unique ref_command
    const uniqueId = uuidv4();

    const { number } = req.body;
    const amount = parseInt(number);

    // console.log('uniqueId:', uniqueId);
    // console.log(userInfo);
    // console.log(amount);
    // console.log(typeof amount);
    // return;

    const currency = 'XOF';

    // const { amount } = req.body;

    let paymentRequestUrl = 'https://paytech.sn/api/payment/request-payment';
    // http client
    let params = {
      item_name: itemInfo,
      item_price: amount,
      currency: currency,
      ref_command: uniqueId,
      command_name: commandDetails,

      env: 'test',
      ipn_url: 'https://webhook.site/bd627225-628c-4e8d-abe8-dabfac3da97f',
      ipn_url:
        'https://auth-backend-d9n5.onrender.com/api/payment-notification',
      success_url: 'https://domain.com/success',
      cancel_url: 'https://domain.com/cancel',

      custom_field: JSON.stringify({
        custom_fiel1: userInfo,
        // custom_fiel2: 'value_2',
      }),

      // ipn_url: 'https://domain.com/ipn',
    };
    console.log('refCommand:', params.ref_command);

    let headers = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      API_KEY: process.env.API_KEY,
      API_SECRET: process.env.API_SECRET,
    };

    // return res.json({ businessInfo: params.custom_field });

    fetch(paymentRequestUrl, {
      method: 'POST',
      body: JSON.stringify(params),
      headers: headers,
    })
      .then(function (response) {
        return response.json();
      })
      .then(function (jsonResponse) {
        console.log(jsonResponse);
        // send the response for making payment to the frontend so that frontend can redirect user to the page
        // we can also handle the redirection from the backend
        // we can also save the payment token coming from the payment gateway and make it a default of initiated. Then we change it to success when it is successful and failure when it fails. Then we query the business collection based on whether the payment is initiated, successful or failed
        const { token, ...others } = jsonResponse;
        return res.json({
          others,
        });
      })
      .catch((error) => {
        console.log(error.message);
        return res.json(error.message);
      });
  } catch (error) {
    return res.json({
      message: 'Something happened',
      status: 500,
      success: false,
    });
  }
};

/*
item_name: product name(wallet crediting)
item_price: amount
ref_command: uniqueID generated for each transaction using UUID 
command_name: i concatenate the item_name with the firstName of the user making the request
currency: as selected by the user
approx: Environment['test', 'prod']
custom_field: Additional data sent to paytech server when requesting for token(we may decide to add the type of user sending the request. it can be business user or the business itself, we may also send the the id of the user or business making the request)
token: payment token
api_key_sha256: company API key hashed with the sha256 algorithm
api_secret_sha256: company secret key hashed with the sha256 algorithm
*/

// paytech IPN
const paymentNotification = async (req, res) => {
  try {
    let {
      type_event,
      ref_command,
      item_name,
      item_price,
      currency,
      command_name,
      env,
      token,
      api_key_sha256,
      api_secret_sha256,
    } = req.body;

    let custom_field = JSON.parse(req.body.custom_field);

    let my_api_key = process.env.API_KEY;
    let my_api_secret = process.env.API_SECRET;
    if (
      SHA256Encrypt(my_api_secret) === api_secret_sha256 &&
      SHA256Encrypt(my_api_key) === api_key_sha256
    ) {
      // supposed we add details like whether the wallet to be credited belong to a business user or business, then we can check and we pick the user from the collection it belongs to and update the wallet and we can also save the details of the data coming from the payment gateway their.
      // supposed we save the ref_command inside the user collection when the request was made, then we remove it and push it into wallet crediting successful. Or we might just give it 3 conditions: activate, successful and failure. then we update it accordingly when the notification comes to our website
    } else {
      return;
    }

    // {
    //   let type_event = req.body.type_event;
    //   let custom_field = JSON.parse(req.body.custom_field);
    //   let ref_command = req.body.ref_command;
    //   let item_name = req.body.item_name;
    //   let item_price = req.body.item_price;
    //   let currency = req.body.currency;
    //   let command_name = req.body.command_name;
    //   let env = req.body.env;
    //   let token = req.body.token;
    //   let api_key_sha256 = req.body.api_key_sha256;
    //   let api_secret_sha256 = req.body.api_secret_sha256;
    // }
  } catch (error) {
    return res.json({
      message: 'Something happened',
      status: 500,
      success: false,
    });
  }
};

export {
  payment,
  userLogin,
  logout,
  userRegister,
  resendEmail,
  verifyUserEmail,
  paymentNotification,
};
