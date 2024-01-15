import jwt from 'jsonwebtoken';

const generateToken = async (res, userId, userEmail) => {
  try {
    const token = jwt.sign(
      {
        _id: userId,
        email: userEmail,
      },
      process.env.JWT_SECRET,
      { expiresIn: '3600s' }
    );

    res.cookie('access_token', token, {
      httpOnly: true,
      maxAge: 60 * 60 * 10 * 1000,
      sameSite: 'None',
      // sameSite: 'strict',
      // secure: false, // Include this if your app is served over HTTP
      secure: true, // Include this if your app is served over HTTPS
    });
  } catch (error) {
    console.error(error);
  }
};

const verifyToken = async (req, res, next) => {
  const token = req.cookies.access_token;
  try {

    if (!token) {
      return res.json({
        message: 'Please login to proceed',
        success: false,
        status: 401,
      });
    }

    await jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.json({
          message: 'Invalid token',
          status: 404,
          success: false,
          err,
        });
      }
      req.user = user;
      next();
    });
  } catch (error) {
    console.error(error);
    return;
  }
};

export { generateToken, verifyToken };
