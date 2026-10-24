import { prisma } from "./db";

export async function debit(userId: string, amountMad: number) {
  const wallet = await prisma.wallet.findUnique({ where: { userId } });
  if (!wallet || wallet.balance < amountMad) throw new Error("insufficient funds");
  await prisma.wallet.update({ where: { userId }, data: { balance: wallet.balance - amountMad } });
}

export function withVat(amountMad: number): string {
  return (amountMad * 1.2).toFixed(2);
}

export async function creditCentimes(userId: string, amountCentimes: number) {
  await prisma.wallet.update({ where: { userId }, data: { balance: { increment: amountCentimes } } });
}
