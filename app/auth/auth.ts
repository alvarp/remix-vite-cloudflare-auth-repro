import {
  createCookie,
  redirect,
  type LoaderFunctionArgs,
} from "@remix-run/cloudflare";

const secret = process.env.COOKIE_SECRET || "default";
if (secret === "default") {
  console.warn(
    "🚨 No COOKIE_SECRET environment variable set, using default. The app is insecure in production."
  );
}

export type UserSession = {
  id: string;
  name: string | null;
  accountId: string;
  email: string;
  lastName: string | null;
  role: "admin" | "user";
  account: {
    id: string;
    ownerId: string;
    name: string | null;
    code: string | null;
  };
};

const cookie = createCookie("auth", {
  secrets: [secret],
  // 30 days
  maxAge: 30 * 24 * 60 * 60,
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
});

export async function getAuthFromRequest(
  request: Request
): Promise<UserSession | null> {
  return getAuthFromToken(request.headers.get("Cookie") as string);
}

export async function getAuthFromToken(
  token: string
): Promise<UserSession | null> {
  const userStr = await cookie.parse(token);
  if (!userStr) return null;

  const user = JSON.parse(userStr) as UserSession;
  return user;
}

export function getAuthToken(user: UserSession) {
  return cookie.serialize(JSON.stringify(user));
}

export async function setAuthOnResponse(
  response: Response,
  user: UserSession
): Promise<Response> {
  const header = await getAuthToken(user);
  response.headers.append("Set-Cookie", header);
  return response;
}

export async function requireAuthCookie(request: Request) {
  const user = await getAuthFromRequest(request);
  if (!user) {
    throw redirect("/sign-in", {
      headers: {
        "Set-Cookie": await cookie.serialize("", {
          maxAge: 0,
        }),
      },
    });
  }
  return user;
}

export async function redirectIfLoggedInLoader({
  request,
}: LoaderFunctionArgs) {
  const user = await getAuthFromRequest(request);
  if (user) {
    throw redirect("/");
  }
  return null;
}

export async function redirectWithClearedCookie(): Promise<Response> {
  return redirect("/", {
    headers: {
      "Set-Cookie": await cookie.serialize(null, {
        expires: new Date(0),
      }),
    },
  });
}
