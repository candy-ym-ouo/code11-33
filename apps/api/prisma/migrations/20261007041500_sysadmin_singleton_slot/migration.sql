-- 系统中至多允许存在一个 sysadmin：用「可空唯一列」表达单例约束。
-- sysadmin_slot 为 1 表示系统管理员，为 NULL 表示普通用户；
-- PostgreSQL 的唯一索引对多个 NULL 不冲突，因此普通用户数量不限，
-- 但永远只能有一行 sysadmin_slot = 1。
--
-- 这是应用层「首个用户」判定的最终防线：即使应用层并发判断失误，
-- 数据库也会拒绝第二个 sysadmin 写入，从根上杜绝多个系统管理员。
ALTER TABLE "users" ADD COLUMN "sysadmin_slot" INTEGER;

UPDATE "users" SET "sysadmin_slot" = 1 WHERE "system_role" = 'sysadmin';

CREATE UNIQUE INDEX "users_sysadmin_slot_key" ON "users" ("sysadmin_slot");
