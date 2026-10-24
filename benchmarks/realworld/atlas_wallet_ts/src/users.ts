import { prisma } from "./db";

export async function findByEmail(email: string) {
  return prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${email}'`);
}

export async function findById(id: string) {
  return prisma.$queryRaw`SELECT * FROM "User" WHERE id = ${id}`;
}

export function pageOf<T>(items: T[], size: number): T[][] {
  const pages: T[][] = [];
  for (let i = 0; i <= items.length; i += size) pages.push(items.slice(i, i + size));
  return pages;
}
