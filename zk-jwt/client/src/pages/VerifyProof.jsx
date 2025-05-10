import React, { useState } from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  Button,
  TextField,
  Alert,
  Grid,
} from '@mui/material';
import axios from 'axios';

function parseArrayInput(input, type = 'number') {
  try {
    const arr = JSON.parse(input);
    if (!Array.isArray(arr)) throw new Error('Not an array');
    if (type === 'number') return arr.map(Number);
    if (type === 'string') return arr.map(String);
    return arr;
  } catch {
    return [];
  }
}

function VerifyProof() {
  // Public inputs
  const [pubkeyModulusLimbs, setPubkeyModulusLimbs] = useState('[]');
  const [merkleRoot, setMerkleRoot] = useState('');
  const [proof, setProof] = useState('');

  const [verificationResult, setVerificationResult] = useState(null);
  const [error, setError] = useState('');

  const handleVerify = async () => {
    setError('');
    setVerificationResult(null);

    try {
      // Parse the proof from the input field
      const parsedProof = parseArrayInput(proof);
      if (!parsedProof.length) {
        setError('Invalid proof format. Please paste the proof from the Proof Creator page.');
        return;
      }

      // Send proof and public inputs to backend
      const publicInputs = [
        merkleRoot,
        parseArrayInput(pubkeyModulusLimbs)
      ];

      const response = await axios.post('http://localhost:4000/api/verify-jwt-proof', {
        proof: parsedProof,
        publicInputs,
      });
      setVerificationResult({
        isValid: true,
        message: response.data.message,
        backend: response.data,
      });
    } catch (err) {
      setVerificationResult(null);
      setError(err.response?.data?.message || 'Verification failed');
    }
  };

  return (
    <Container maxWidth="md">
      <Box sx={{ mt: 4 }}>
        <Paper elevation={3} sx={{ p: 4 }}>
          <Typography variant="h5" component="h1" gutterBottom>
            Verify Zuitzpass Proof
          </Typography>
          <Typography variant="body1" gutterBottom sx={{ mb: 3 }}>
            Paste the proof from the Proof Creator page and fill in the public inputs:
          </Typography>

          {/* Proof Input */}
          <Typography variant="h6" gutterBottom sx={{ mt: 2 }}>
            Proof
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <TextField
                label="Proof (paste from Proof Creator)"
                fullWidth
                multiline
                rows={4}
                value={proof}
                onChange={e => setProof(e.target.value)}
                placeholder='Paste the proof array here (e.g. [1, 2, 3, ...])'
                sx={{ mb: 2 }}
              />
            </Grid>
          </Grid>

          {/* Public Inputs Section */}
          <Typography variant="h6" gutterBottom sx={{ mt: 2 }}>
            Public Inputs
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <TextField
                label="Merkle Root (Field)"
                fullWidth
                value={merkleRoot}
                onChange={e => setMerkleRoot(e.target.value)}
                sx={{ mb: 2 }}
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                label="Pubkey Modulus Limbs ([u128; 18])"
                fullWidth
                value={pubkeyModulusLimbs}
                onChange={e => setPubkeyModulusLimbs(e.target.value)}
                placeholder='["num1", "num2", ...]'
                sx={{ mb: 2 }}
              />
            </Grid>
          </Grid>

          <Button
            variant="contained"
            onClick={handleVerify}
            sx={{ mt: 3, mb: 2 }}
          >
            Verify Proof
          </Button>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}
          {verificationResult && (
            <Alert 
              severity={verificationResult.isValid ? "success" : "error"}
              sx={{ mb: 2 }}
            >
              {verificationResult.message}
              {verificationResult.backend && (
                <pre style={{ marginTop: 8, background: '#f5f5f5', padding: 8, borderRadius: 4 }}>
                  {JSON.stringify(verificationResult.backend, null, 2)}
                </pre>
              )}
            </Alert>
          )}
        </Paper>
      </Box>
    </Container>
  );
}

export default VerifyProof; 