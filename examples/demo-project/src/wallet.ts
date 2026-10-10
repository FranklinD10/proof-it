export interface Account {
  id: number;
  balance: number;
}

/** Move `amount` from `from` to `to`. */
export function transfer(from: Account, to: Account, amount: number): void {
  if (amount <= 0) throw new Error("amount must be positive");
  if (from.balance < amount) throw new Error("insufficient funds");
  from.balance -= amount;
  to.balance += amount;
}
