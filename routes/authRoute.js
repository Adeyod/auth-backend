import express from 'express';
import {
  userLogin,
  userRegister,
  verifyUserEmail,
  logout,
  resendEmail,
} from '../controllers/authController.js';
import { verifyToken } from '../utils/jwtVerification.js';

const router = express.Router();

router.post('/login', userLogin);
router.post('/register', userRegister);
router.get('/:userId/verify-email/:token', verifyUserEmail);
router.post('/logout', verifyToken, logout);
router.post('/resend-email', resendEmail);

export default router;
