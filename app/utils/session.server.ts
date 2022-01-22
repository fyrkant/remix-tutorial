import { db } from "./db.server";
import bcrypt from "bcryptjs";
import { createCookieSessionStorage, redirect } from "remix";

type LoginType = { username: string; password: string };

export async function register({ username, password }: LoginType) {
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await db.user.create({
    data: {
      username,
      passwordHash: hashedPassword,
    },
  });
  return user;
}

export const login = async ({ username, password }: LoginType) => {
  const existingUser = await db.user.findFirst({ where: { username } });
  if (!existingUser) return null;

  const passwordsMatch = await bcrypt.compare(
    password,
    existingUser.passwordHash
  );

  if (!passwordsMatch) return null;

  return existingUser;
};

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
  throw new Error("SESSION_SECRET must be set");
}

const storage = createCookieSessionStorage({
  cookie: {
    name: "RJ_session",
    // normally you want this to be `secure: true`
    // but that doesn't work on localhost for Safari
    // https://web.dev/when-to-use-local-https/
    secure: process.env.NODE_ENV === "production",
    secrets: [sessionSecret],
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 30,
    httpOnly: true,
  },
});

export async function createUserSession(userId: string, redirectTo: string) {
  const session = await storage.getSession();
  session.set("userId", userId);
  return redirect(redirectTo, {
    headers: {
      "Set-Cookie": await storage.commitSession(session),
    },
  });
}

const getUserSession = (request: Request) => {
  return storage.getSession(request.headers.get("Cookie"));
};

export const getUserId = async (request: Request) => {
  const session = await getUserSession(request);
  const userId = session.get("userId");

  if (typeof userId !== "string") return null;

  return userId;
};

export async function requireUserId(
  request: Request,
  redirectTo: string = new URL(request.url).pathname
) {
  const session = await getUserSession(request);
  const userId = session.get("userId");
  if (!userId || typeof userId !== "string") {
    const searchParams = new URLSearchParams([["redirectTo", redirectTo]]);
    throw redirect(`/login?${searchParams}`);
  }
  return userId;
}

export async function getUser(request: Request) {
  const userId = await getUserId(request);
  if (typeof userId !== "string") {
    return null;
  }

  try {
    const user = await db.user.findUnique({
      where: { id: userId },
    });
    return user;
  } catch {
    throw logout(request);
  }
}

export const logout = async (request: Request) => {
  const session = await getUserSession(request);
  return redirect("/jokes", {
    headers: {
      "Set-Cookie": await storage.destroySession(session),
    },
  });
};
