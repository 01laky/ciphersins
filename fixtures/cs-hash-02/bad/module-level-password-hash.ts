import bcrypt from "bcrypt";

export const passwordHash = bcrypt.hashSync("seed", 8);
