import React, { useState, useEffect } from 'react';
import { Box, Typography } from '@mui/material';

function Login() {
  const [nonce] = useState('');

  useEffect(() => {
    // Load Google Identity Services Script
    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    document.body.appendChild(script);

    return () => {
      document.body.removeChild(script);
    };
  }, []);

  const handleGoogleLogin = async () => {
    const clientId = '604604729243-ghkjdvrngdbg6558jvki2maggsjtlfvh.apps.googleusercontent.com';
    const redirectUri = 'http://localhost:5173/auth/callback';
    const scope = 'openid email profile';
    const finalNonce = nonce.trim() !== '' ? nonce : Math.random().toString(36).substring(2);
    
    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
      `client_id=${clientId}&` +
      `redirect_uri=${encodeURIComponent(redirectUri)}&` +
      `response_type=id_token token&` +
      `scope=${encodeURIComponent(scope)}&` +
      `nonce=${finalNonce}&` +
      `prompt=select_account`;

    window.location.href = authUrl;
  };

  return (
    <Box
      sx={{
        height: '100vh',
        width: '100vw',
        margin: 0,
        padding: 0,
        position: 'fixed',
        top: 0,
        left: 0,
        background: 'radial-gradient(circle at center, #2C3333 0%, #3a4242 50%, #4d5757 100%)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: 'white',
        overflow: 'hidden',
      }}
    >
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 6,
          maxWidth: '400px',
          width: '100%',
          textAlign: 'center',
          p: 3,
        }}
      >
        <Box
          component="img"
          src="/logo/logo.svg"
          alt="Zauth Logo"
          sx={{
            width: '100px',
            height: '100px',
            filter: 'drop-shadow(0 0 20px rgba(255, 255, 255, 0.1))',
          }}
        />
        
        <Typography
          variant="h3"
          component="h1"
          sx={{
            fontWeight: 700,
            letterSpacing: '0.1em',
            textTransform: 'uppercase',
            color: '#fff',
            textShadow: '0 2px 10px rgba(0,0,0,0.2)',
            fontSize: { xs: '2rem', sm: '2.5rem', md: '3rem' },
          }}
        >
          Sign In
        </Typography>

        <Typography
          variant="h6"
          sx={{
            opacity: 0.8,
            maxWidth: '300px',
            lineHeight: 1.6,
            fontWeight: 400,
          }}
        >
          Authenticate securely using your Google account
        </Typography>

        {/* Modern Google Sign-In Button */}
        <div 
          id="g_id_onload"
          data-client_id="604604729243-ghkjdvrngdbg6558jvki2maggsjtlfvh.apps.googleusercontent.com"
          data-context="signin"
          data-ux_mode="redirect"
          data-login_uri="http://localhost:5173/auth/callback"
          data-auto_prompt="false"
        />
        <div
          className="g_id_signin"
          data-type="standard"
          data-shape="rectangular"
          data-theme="outline"
          data-text="signin_with"
          data-size="large"
          data-logo_alignment="left"
          data-width="280"
          onClick={handleGoogleLogin}
          style={{ 
            cursor: 'pointer',
            transform: 'scale(1.2)',
            marginTop: '20px',
          }}
        />
      </Box>
    </Box>
  );
}

export default Login; 