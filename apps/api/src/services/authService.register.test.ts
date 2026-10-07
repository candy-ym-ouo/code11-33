import { describe, expect, it, vi, beforeEach } from 'vitest';
import type { Prisma, User } from '@prisma/client';

type Row = { id: string; email: string; systemRole: string; sysadminSlot: number | null };

/**
 * 模拟 PostgreSQL 关键语义的最小 Prisma 假实现：
 * 1. pg_advisory_xact_lock 是事务级、互斥的（这里用一把 FIFO 异步互斥锁表达）；
 * 2. 事务内写入只有提交后才对后续事务可见（READ COMMITTED）；
 * 3. 迁移 users_sysadmin_slot_key 唯一索引：sysadmin_slot = 1 至多一行，
 *    多个 NULL 不冲突（普通用户不限数量）。
 */
function createFakeDb() {
  const committed: Row[] = [];
  let seq = 0;

  // FIFO 互斥锁：模拟单个 advisory lock 键上的排队。
  let tail: Promise<void> = Promise.resolve();
  function acquire(): Promise<() => void> {
    const prev = tail;
    let release!: () => void;
    tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    return prev.then(() => release);
  }

  // 在尝试获取锁的位置设置屏障，迫使所有并发事务在此汇合，
  // 最大化竞态（等价于「大家同时做完锁外检查、同时抢锁」）。
  let barrier: (() => void) | null = null;
  const arrived = new Set<() => void>();
  let expectedWaiters = 0;
  function setBarrier(n: number): Promise<void> {
    expectedWaiters = n;
    return new Promise((resolve) => {
      barrier = resolve;
    });
  }

  function makeTx() {
    const staged: Row[] = [];
    return {
      // 真实代码在事务内调用 pg_advisory_xact_lock；此处只是保留调用形态，
      // 真正的互斥由 $transaction 包装在进入回调前取得的 FIFO 锁保证。
      $executeRaw: vi.fn(async (): Promise<void> => {}),
      user: {
        async findUnique({ where }: { where: { email: string } }): Promise<Row | null> {
          // 只能读到已提交数据
          return committed.find((u) => u.email === where.email) ?? null;
        },
        async count(): Promise<number> {
          return committed.length;
        },
        async create({
          data,
        }: {
          data: { email: string; systemRole: string; sysadminSlot: number | null };
        }): Promise<Row> {
          if (
            data.sysadminSlot !== null &&
            committed.some((u) => u.sysadminSlot === data.sysadminSlot)
          ) {
            // users_sysadmin_slot_key 唯一索引：sysadmin_slot = 1 已被占用
            const err = new Error('unique constraint') as Prisma.PrismaClientKnownRequestError;
            err.code = 'P2002';
            throw err;
          }
          const row: Row = {
            id: `user_${++seq}`,
            email: data.email,
            systemRole: data.systemRole,
            sysadminSlot: data.sysadminSlot,
          };
          staged.push(row);
          return row;
        },
      },
      auditLog: { async create(): Promise<Record<string, never>> { return {}; } },
      __staged: staged,
    };
  }

  const fake = {
    user: {
      async findUnique({ where }: { where: { email: string } }): Promise<Row | null> {
        return committed.find((u) => u.email === where.email) ?? null;
      },
    },
    async $transaction(cb: (tx: ReturnType<typeof makeTx>) => Promise<User>): Promise<User> {
      // 模拟并发请求同时到达 advisory lock 前：先在屏障处汇合，再一起抢 FIFO 锁。
      if (barrier) {
        await new Promise<void>((resolve) => {
          arrived.add(resolve);
          // 必须在当前任务挂起前检查：最后一个到达者负责放行所有人，
          // 否则所有事务都停在 await 上，没有谁能触发释放。
          if (arrived.size === expectedWaiters) {
            const releaseBarrier = barrier;
            barrier = null;
            arrived.forEach((w) => w());
            arrived.clear();
            releaseBarrier();
          }
        });
      }
      const release = await acquire(); // pg_advisory_xact_lock（FIFO 排队）
      const tx = makeTx();
      try {
        const result = await cb(tx);
        committed.push(...tx.__staged); // 提交后才对后续事务可见
        return result;
      } finally {
        release(); // COMMIT/ROLLBACK 时释放咨询锁
      }
    },
    __committed: committed,
    __setBarrier: setBarrier,
  };
  return fake;
}

vi.mock('../db', () => ({ prisma: {} }));

import { prisma } from '../db';
import { register } from './authService';

function assignFake() {
  const fake = createFakeDb();
  Object.assign(prisma as object, {
    user: { findUnique: vi.fn(fake.user.findUnique.bind(fake.user)) },
    $transaction: vi.fn(fake.$transaction.bind(fake)),
  });
  return fake;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('register 首个用户原子化', () => {
  it('并发首次注册：只有一个请求拿到 sysadmin，其余被拒绝', async () => {
    const fake = assignFake();

    const N = 5;
    // 5 个请求同时冲到 advisory lock 前才一起放行，制造最激烈竞争。
    const barrierReady = fake.__setBarrier(N);

    const attempts = Array.from({ length: N }, (_, i) =>
      register(
        { email: `u${i}@example.com`, password: 'correct horse battery staple', displayName: `U${i}` },
        { ip: null, userAgent: null, allowPublicSignup: false },
      )
        .then((u) => ({ ok: true as const, role: u.systemRole }))
        .catch((err: { status?: number; message?: string }) => ({
          ok: false as const,
          status: err.status,
          message: err.message,
        })),
    );

    await barrierReady;
    const results = await Promise.all(attempts);

    expect(results.filter((r) => r.ok && r.role === 'sysadmin')).toHaveLength(1);
    expect(fake.__committed.filter((u) => u.systemRole === 'sysadmin')).toHaveLength(1);
    expect(fake.__committed).toHaveLength(1);

    const losers = results.filter((r) => !r.ok);
    expect(losers).toHaveLength(N - 1);
    for (const loser of losers) {
      expect(loser.status).toBe(409);
      expect(loser.message).toContain('未开放公开注册');
    }
  }, 30000);

  it('已有首个用户后的并发注册不会再产生 sysadmin，事务按 FIFO 串行完成', async () => {
    const fake = assignFake();

    await register(
      { email: 'a@example.com', password: 'correct horse battery staple', displayName: 'A' },
      { ip: null, userAgent: null, allowPublicSignup: false },
    );

    const order: number[] = [];
    const N2 = 3;
    const barrierReady = fake.__setBarrier(N2);
    const promises = Array.from({ length: N2 }, (_, i) =>
      register(
        { email: `v${i}@example.com`, password: 'correct horse battery staple', displayName: `V${i}` },
        { ip: null, userAgent: null, allowPublicSignup: true },
      ).then(() => {
        order.push(i);
      }),
    );
    await barrierReady;
    await Promise.all(promises);

    expect(fake.__committed.filter((u) => u.systemRole === 'sysadmin')).toHaveLength(1);
    expect(fake.__committed).toHaveLength(1 + N2);
    expect(order).toEqual([0, 1, 2]); // FIFO 入队顺序
  }, 30000);

  it('数据库唯一槽位列兜底：绕过应用层再写一个 sysadmin 会被拒绝', async () => {
    const fake = assignFake();

    await register(
      { email: 'root@example.com', password: 'correct horse battery staple', displayName: 'Root' },
      { ip: null, userAgent: null, allowPublicSignup: false },
    );

    // 模拟「绕过应用层判定」的第二次 sysadmin 写入：sysadmin_slot 唯一索引必须拒绝
    await expect(
      fake.$transaction(async (client) => {
        await client.user.create({
          data: {
            email: 'rogue@example.com',
            // @ts-expect-error 假实现只关心这几个字段
            systemRole: 'sysadmin',
            sysadminSlot: 1,
          },
        });
      }),
    ).rejects.toMatchObject({ code: 'P2002' });
  });
});
