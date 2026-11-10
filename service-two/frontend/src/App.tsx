import { useEffect, useState } from "react";

type User = { username: string };
type Greeting = { service: string; username: string };

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    fetch("/bff/auth/user")
      .then((response) => {
        if (response.status === 401) return null;
        if (!response.ok) throw new Error(`Authentication check returned ${response.status}`);
        return response.json() as Promise<User>;
      })
      .then(setUser)
      .catch((error: unknown) => setMessage(`Authentication check failed: ${String(error)}`))
      .finally(() => setReady(true));
  }, []);

  function signIn() {
    window.location.assign("/auth/login");
  }

  async function loadGreeting() {
    try {
      const response = await fetch("/bff/api/hello");
      if (response.status === 401) {
        signIn();
        return;
      }
      if (!response.ok) throw new Error(`API returned ${response.status}`);
      const result: Greeting = await response.json();
      setMessage(`Hello ${result.username} from ${result.service}`);
    } catch (error) {
      setMessage(`API request failed: ${String(error)}`);
    }
  }

  async function signOut() {
    try {
      const csrfResponse = await fetch("/bff/auth/csrf");
      if (!csrfResponse.ok) throw new Error(`CSRF token request returned ${csrfResponse.status}`);
      const { token } = (await csrfResponse.json()) as { token: string };
      const response = await fetch("/bff/auth/logout", {
        method: "POST",
        headers: { "X-XSRF-TOKEN": token },
      });
      if (!response.ok) throw new Error(`Logout returned ${response.status}`);
      setUser(null);
      setMessage("Signed out.");
    } catch (error) {
      setMessage(`Sign out failed: ${String(error)}`);
    }
  }

  if (!ready) return <main><p>Checking session...</p></main>;

  return (
    <main>
      <h1>Service Two</h1>
      <p>API requests are proxied through the authenticated BFF and Kong.</p>
      {user ? (
        <>
          <p>Signed in as {user.username}</p>
          <button onClick={loadGreeting}>Call protected API</button>
          <button onClick={signOut}>Sign out</button>
        </>
      ) : (
        <button onClick={signIn}>Sign in with Keycloak</button>
      )}
      {message && <p role="status">{message}</p>}
    </main>
  );
}
