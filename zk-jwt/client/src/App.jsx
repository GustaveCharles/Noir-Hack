import React, { useState, useEffect } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { Container } from '@mui/material';
import Navbar from './components/Navbar';
import Login from './pages/Login';
import JwtDisplay from './pages/JwtDisplay';
import VerifyProof from './pages/VerifyProof';
import AuthCallback from './pages/AuthCallback';
import { verifyIdToken } from './utils/auth';
import ProofCreator from './pages/ProofCreator';
import Home from './pages/Home';
import { GoogleOAuthProvider } from '@react-oauth/google';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    const idToken = localStorage.getItem('idToken');
    return verifyIdToken(idToken) !== null;
  });
  const location = useLocation();

  useEffect(() => {
    const idToken = localStorage.getItem('idToken');
    setIsAuthenticated(verifyIdToken(idToken) !== null);
  }, [location]);

  const isPublicPage = location.pathname === '/' || location.pathname === '/login';

  return (
    <GoogleOAuthProvider clientId="604604729243-ghkjdvrngdbg6558jvki2maggsjtlfvh.apps.googleusercontent.com">
      <>
        {!isPublicPage && (
          <Navbar isAuthenticated={isAuthenticated} setIsAuthenticated={setIsAuthenticated} />
        )}
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/login" element={!isAuthenticated ? <Login /> : <Navigate to="/jwt" />} />
          <Route 
            path="/auth/callback" 
            element={
              <Container maxWidth={false} disableGutters sx={{ mt: 8 }}>
                <AuthCallback setIsAuthenticated={setIsAuthenticated} />
              </Container>
            } 
          />
          <Route 
            path="/jwt" 
            element={
              <Container maxWidth={false} disableGutters sx={{ mt: 8 }}>
                {isAuthenticated ? <JwtDisplay /> : <Navigate to="/login" />}
              </Container>
            } 
          />
          <Route 
            path="/verify" 
            element={
              <Container maxWidth={false} disableGutters sx={{ mt: 8 }}>
                {isAuthenticated ? <VerifyProof /> : <Navigate to="/login" />}
              </Container>
            } 
          />
          <Route 
            path="/create-proof" 
            element={
              <Container maxWidth={false} disableGutters sx={{ mt: 8 }}>
                {isAuthenticated ? <ProofCreator /> : <Navigate to="/login" />}
              </Container>
            } 
          />
        </Routes>
      </>
    </GoogleOAuthProvider>
  );
}

export default App; 