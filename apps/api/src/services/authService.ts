import { argon2Verify, argon2id } from 'hash-wasm';
import { Prisma, type User } from '@prisma/client';
import { prisma } from '../db';
import { conflict, unauthenticated, badRequest } from '../http/errors';
import { randomBytes } from 'node:crypto';
import * as audit from './auditService';

export interface PublicUser {
  id: string;
  email: string;
  displayName: string;
  avatarColor: string;
  systemRole: 'sysadmin' | 'user';
  createdAt: string;
}

export function toPublicUser(user: User): PublicUser {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    avatarColor: user.avatarColor,
    systemRole: user.systemRole,
    createdAt: user.createdAt.toISOString(),
  };
}

export async function hashPassword(password: string): Promise<string> {
  return argon2id({
    password,
    salt: randomBytes(16),
    parallelism: 1,
    iterations: 2,
    memorySize: 19_456, // 19 MiB，与项目文档的 argon2id 参数一致
    hashLength: 32,
    outputType: 'encoded',
  });
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    return await argon2Verify({ password, hash });
  } catch {
    return false;
  }
}

// 「首个用户」判定的咨询锁命名空间：固定 (namespace, key)，只用于注册串行化。
// 所有注册请求都先抢同一把事务级咨询锁，保证 count() 判定与建号写入串行化，
// 竞争请求里只有一个能在 users 表为空时完成写入、拿到 sysadmin 身份。
const REGISTER_LOCK_NAMESPACE = 0x5245_474d; // 'REGM'
const FIRST_USER_LOCK_KEY = 1;

export async function register(
  input: { email: string; password: string; displayName: string },
  meta: { ip?: string | null; userAgent?: string | null; allowPublicSignup: boolean },
): Promise<User> {
  // 快速失败路径：邮箱占用与密码哈希放在锁外，避免无谓地串行化注册请求。
  const existing = await prisma.user.findUnique({ where: { email: input.email } });
  if (existing) throw conflict('该邮箱已注册');

  const passwordHash = await hashPassword(input.password);

  const user = await prisma.$transaction(async (tx) => {
    // 事务级咨询锁，COMMIT/ROLLBACK 时自动释放。
    // 并发注册在此排队：只有拿到锁后看到「表为空」的请求能成为首个用户。
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(${REGISTER_LOCK_NAMESPACE}, ${FIRST_USER_LOCK_KEY})`;

    // 锁内再次确认邮箱，挡住「锁外检查后另一个请求已注册同邮箱」的窗口。
    const emailTaken = await tx.user.findUnique({ where: { email: input.email } });
    if (emailTaken) throw conflict('该邮箱已注册');

    const userCount = await tx.user.count();
    const isFirstUser = userCount === 0;
    if (!isFirstUser && !meta.allowPublicSignup) {
      throw conflict('本系统未开放公开注册，请使用家人发来的邀请链接加入');
    }

    const colors = ['#2F4858', '#A44A3F', '#3F6B4A', '#6B4E71', '#8A6D3B'];
    const avatarColor = colors[userCount % colors.length]!;

    let created: User;
    try {
      created = await tx.user.create({
        data: {
          email: input.email,
          passwordHash,
          displayName: input.displayName,
          avatarColor,
          systemRole: isFirstUser ? 'sysadmin' : 'user',
          // sysadmin 单例列：只有首个用户占用唯一槽位，其余为 NULL
          sysadminSlot: isFirstUser ? 1 : null,
        },
      });
    } catch (err) {
      // 兜底：唯一槽位已被占用（理论上被上面的咨询锁挡住，仅在异常竞态下触发）
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
        throw conflict('系统管理员已存在，请使用家人发来的邀请链接加入');
      }
      throw err;
    }
    await audit.record(
      {
        actorId: created.id,
        action: 'auth.register',
        targetType: 'user',
        targetId: created.id,
        diff: { firstUser: isFirstUser } as Prisma.InputJsonValue,
        ip: meta.ip,
        userAgent: meta.userAgent,
      },
      tx,
    );
    return created;
  });

  return user;
}

export async function login(
  input: { email: string; password: string },
  meta: { ip?: string | null; userAgent?: string | null },
): Promise<User> {
  const user = await prisma.user.findUnique({ where: { email: input.email } });
  const ok = user ? await verifyPassword(input.password, user.passwordHash) : false;

  if (!user || !ok) {
    if (user) {
      await audit.recordSoft({
        actorId: user.id,
        action: 'auth.login_failed',
        targetType: 'user',
        targetId: user.id,
        ip: meta.ip,
        userAgent: meta.userAgent,
      });
    }
    // 不区分「用户不存在 / 密码错误」，避免账号枚举
    throw unauthenticated('邮箱或密码不正确');
  }
  if (user.status === 'disabled') throw unauthenticated('账号已停用，请联系家庭管理员');

  await audit.recordSoft({
    actorId: user.id,
    action: 'auth.login',
    targetType: 'user',
    targetId: user.id,
    ip: meta.ip,
    userAgent: meta.userAgent,
  });
  return user;
}

export async function updateProfile(
  userId: string,
  input: { displayName?: string; currentPassword?: string; newPassword?: string; avatarColor?: string },
): Promise<User> {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });

  let passwordHash: string | undefined;
  if (input.newPassword) {
    if (!input.currentPassword) throw badRequest('修改密码需要提供当前密码');
    const ok = await verifyPassword(input.currentPassword, user.passwordHash);
    if (!ok) throw badRequest('当前密码不正确');
    passwordHash = await hashPassword(input.newPassword);
  }

  return prisma.$transaction(async (tx) => {
    const updated = await tx.user.update({
      where: { id: userId },
      data: {
        displayName: input.displayName ?? undefined,
        avatarColor: input.avatarColor ?? undefined,
        passwordHash,
      },
    });
    if (passwordHash) {
      await tx.refreshToken.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date() } });
    }
    return updated;
  });
}

export interface MembershipSummary {
  familyId: string;
  familyName: string;
  role: string;
  status: string;
  memberCount: number;
  itemCount: number;
}

export async function listMemberships(userId: string): Promise<MembershipSummary[]> {
  const memberships = await prisma.familyMember.findMany({
    where: { userId, family: { deletedAt: null } },
    include: { family: { include: { _count: { select: { members: true, items: true } } } } },
    orderBy: { joinedAt: 'asc' },
  });
  return memberships.map((m) => ({
    familyId: m.familyId,
    familyName: m.family.name,
    role: m.role,
    status: m.status,
    memberCount: m.family._count.members,
    itemCount: m.family._count.items,
  }));
}

