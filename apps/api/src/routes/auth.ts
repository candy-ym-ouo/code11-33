import { Router, type Response } from 'express';
import { loginSchema, registerSchema, updateMeSchema } from '@heirloom/shared';
import { asyncHandler } from '../http/asyncHandler';
import { currentUser, clientMeta, requireAuth } from '../middleware/auth';
import { authLimiter, writeLimiter } from '../middleware/rateLimit';
import { validateBody } from '../middleware/validation';
import { config } from '../config';
import * as authService from '../services/authService';
import {
  CSRF_COOKIE,
  REFRESH_COOKIE,
  cookieOptions,
  csrfCookieOptions,
  issueRefreshToken,
  revokeRefreshToken,
  rotateRefreshToken,
  signAccessToken,
} from '../services/tokenService';
import { prisma } from '../db';
import { unauthenticated } from '../http/errors';

export const authRouter = Router();

function setSessionCookies(res: Response, refresh: { token: string; csrfToken: string }): void {
  res.cookie(REFRESH_COOKIE, refresh.token, cookieOptions());
  res.cookie(CSRF_COOKIE, refresh.csrfToken, csrfCookieOptions());
}

authRouter.post(
  '/register',
  authLimiter,
  validateBody(registerSchema),
  asyncHandler(async (req, res) => {
    const user = await authService.register(req.body, {
      ...clientMeta(req),
      allowPublicSignup: config.PUBLIC_SIGNUP,
    });
    const refresh = await issueRefreshToken(user.id, clientMeta(req));
    setSessionCookies(res, refresh);
    res.status(201).json({
      user: authService.toPublicUser(user),
      accessToken: signAccessToken(user),
      memberships: await authService.listMemberships(user.id),
    });
  }),
);

authRouter.post(
  '/login',
  authLimiter,
  validateBody(loginSchema),
  asyncHandler(async (req, res) => {
    const user = await authService.login(req.body, clientMeta(req));
    const refresh = await issueRefreshToken(user.id, clientMeta(req));
    setSessionCookies(res, refresh);
    res.json({
      user: authService.toPublicUser(user),
      accessToken: signAccessToken(user),
      memberships: await authService.listMemberships(user.id),
    });
  }),
);

authRouter.post(
  '/refresh',
  asyncHandler(async (req, res) => {
    const raw = req.cookies?.[REFRESH_COOKIE];
    if (!raw) throw unauthenticated('会话不存在，请重新登录');
    const { userId, refresh } = await rotateRefreshToken(raw, clientMeta(req));
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw unauthenticated('账号不存在');
    setSessionCookies(res, refresh);
    res.json({
      user: authService.toPublicUser(user),
      accessToken: signAccessToken(user),
      memberships: await authService.listMemberships(user.id),
    });
  }),
);

authRouter.post(
  '/logout',
  asyncHandler(async (req, res) => {
    const raw = req.cookies?.[REFRESH_COOKIE];
    if (raw) await revokeRefreshToken(raw);
    res.clearCookie(REFRESH_COOKIE, { path: '/' });
    res.clearCookie(CSRF_COOKIE, { path: '/' });
    res.status(204).end();
  }),
);

authRouter.get(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    const user = currentUser(req);
    res.json({ user: authService.toPublicUser(user), memberships: await authService.listMemberships(user.id) });
  }),
);

authRouter.patch(
  '/me',
  requireAuth,
  writeLimiter,
  validateBody(updateMeSchema),
  asyncHandler(async (req, res) => {
    const user = currentUser(req);
    const updated = await authService.updateProfile(user.id, req.body);
    res.json({ user: authService.toPublicUser(updated) });
  }),
);
