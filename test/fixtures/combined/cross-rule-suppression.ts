import jwt from "jsonwebtoken";

const token = "eyJ.test";
const secret = "dev-secret";

// ciphersins-ignore-next-line CS-JWT-01
jwt.decode(token);
jwt.verify(token, secret, { algorithms: ["none"] });

export {};
