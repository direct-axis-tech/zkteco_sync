import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { api } from './api'

// Who is signed in is a server fact, not a browser one: it is always answered
// by GET /auth/me against the session cookie, never by anything stored here.
const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const me = await api.auth.me()
      setUser(me)
      return me
    } catch {
      setUser(null)
      return null
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  // A page restored from the back/forward cache keeps the React state it had
  // before sign-out, so re-check with the server rather than trusting it.
  useEffect(() => {
    function onPageShow(event) {
      if (event.persisted) refresh()
    }
    window.addEventListener('pageshow', onPageShow)
    return () => window.removeEventListener('pageshow', onPageShow)
  }, [refresh])

  return (
    <AuthContext.Provider value={{ user, loading, refresh, setUser }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
