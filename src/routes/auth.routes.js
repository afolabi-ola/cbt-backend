import express from "express";
import * as auth from "../controllers/auth.controller.js";
import {
  validateBody,
  validateParams,
} from "../middleware/validate.middleware.js";
import {
  registerSchema,
  loginSchema,
  updateUsersPasswordSchema,
  deleteUserSchema,
} from "../validators/auth.validator.js";
import { authorizeRoles } from "../middleware/role.middleware.js";
import { authenticate, checkDemoUser } from '../middleware/auth.middleware.js';

const router = express.Router();

router.post(
  "/register",
  validateBody(registerSchema),
  authenticate,
  authorizeRoles("ADMIN"),
  auth.register
);

router.post("/login", validateBody(loginSchema), auth.login);

// Clear auth cookie on logout
router.post("/logout", authenticate, auth.logout);

// delete a user account

router.delete(
  '/delete-user/:userId',
  validateParams(deleteUserSchema),
  authenticate,
  authorizeRoles('ADMIN'),
  checkDemoUser, // Middleware to check if the user is a demo user
  auth.deleteUser,
);

// route for admin to change a user's password
router.patch(
  '/change-user-password/:userId',
  authenticate,
  validateBody(updateUsersPasswordSchema),
  authorizeRoles('ADMIN'),
  checkDemoUser, // Middleware to check if the user is a demo user
  auth.changeUsersPassword,
);

export default router;
