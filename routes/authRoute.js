import express from 'express';
import {
  userLogin,
  userRegister,
  verifyUserEmail,
  logout,
  resendEmail,
  payment,
  paymentNotification,
} from '../controllers/authController.js';
import { verifyToken } from '../utils/jwtVerification.js';

const router = express.Router();

router.post('/login', userLogin);
router.post('/payment', verifyToken, payment);
router.post('/payment-notification', verifyToken, paymentNotification);
router.post('/register', userRegister);
router.post('/verify-email', verifyUserEmail);
router.post('/logout', verifyToken, logout);
router.post('/resend-email', resendEmail);

export default router;
