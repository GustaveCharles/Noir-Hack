import React, { useState, useEffect } from 'react';
import { Box, Button, Card, CardContent, Typography, TextField, Alert, Stack } from '@mui/material';
import { UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import { generateInputs } from '../utils/jwtProof';
import { jwtDecode } from 'jwt-decode';
import axios from 'axios';

let noir = null;
let backend = null;

function ProofCreator() {
  const jwt = localStorage.getItem('idToken');
  const [inputs, setInputs] = useState({
    merkle_root: '',
    proof_siblings: '',
    proof_index: '',
  });
  const [proofVerify, setProofVerify] = useState(null);
  const [publicInputs, setPublicInputs] = useState(null);
  const [error, setError] = useState('');
  const [circuitLoaded, setCircuitLoaded] = useState(false);
  const [pubkey, setPubkey] = useState(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);

  // Load circuit on mount
  useEffect(() => {
    const loadCircuit = async () => {
      try {
        const response = await fetch('/zuitzpass.json');
        const circuit = await response.json();
        
        // Initialize Noir and backend
        noir = new Noir(circuit);
        backend = new UltraHonkBackend(circuit.bytecode);
        
        setCircuitLoaded(true);
        console.log('Circuit loaded successfully');
      } catch (err) {
        console.error('Error loading circuit:', err);
        setError('Error loading circuit: ' + err.message);
      }
    };

    loadCircuit();
  }, []);

  // Fetch Google JWK for the JWT's kid
  useEffect(() => {
    if (!jwt) return;
    
    const fetchPubkey = async () => {
      try {
        const header = JSON.parse(atob(jwt.split('.')[0].replace(/-/g, '+').replace(/_/g, '/')));
        const response = await fetch('https://www.googleapis.com/oauth2/v3/certs');
        const jwks = await response.json();
        const key = jwks.keys.find(k => k.kid === header.kid);
        if (!key) throw new Error('Google public key not found for JWT');
        setPubkey(key);
      } catch (err) {
        console.error('Error fetching Google public key:', err);
        setError('Error fetching Google public key: ' + err.message);
      }
    };

    fetchPubkey();
  }, [jwt]);

  const handleChange = (e) => {
    setInputs({ ...inputs, [e.target.name]: e.target.value });
  };


  const handleGenerateProof = async () => {
    setError('');
    setProofVerify(null);
    setPublicInputs(null);
    setVerificationResult(null);
    setIsGenerating(true);

    try {
      if (!noir || !backend) {
        throw new Error('Circuit not loaded yet. Please wait.');
      }
      if (!pubkey) {
        throw new Error('Google public key not loaded yet.');
      }
      if (!jwt) {
        throw new Error('No JWT found in localStorage.');
      }

      const maxSignedDataLength = 910;
      const circuitInputs = await generateInputs({
        jwt,
        pubkey,
        maxSignedDataLength,
        merkle_root: inputs.merkle_root,
        proof_siblings: JSON.parse(inputs.proof_siblings),
        proof_index: Number(inputs.proof_index),
      });

      // Log what we get from generateInputs
      console.log('Circuit inputs from generateInputs:', {
        pubkey_limbs: circuitInputs.pubkey_modulus_limbs,
        merkle_root: inputs.merkle_root
      });

      const { witness } = await noir.execute(circuitInputs);
      console.log('Witness generated');

      const proof = await backend.generateProof(witness);
      const proofVerify = proof.proof
      const publicInputs = proof.publicInputs


      setProofVerify(proofVerify);
      setPublicInputs(publicInputs);

    } catch (err) {
      console.error('Proof generation failed:', err);
      setError('Proof generation failed: ' + err.message);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleVerifyProof = async () => {
    setError('');
    setVerificationResult(null);
    setIsVerifying(true);

    try {
      if (!proofVerify || !publicInputs) {
        throw new Error('No proof to verify. Please generate a proof first.');
      }

      console.log('Proof verify:', proofVerify);
      const response = await axios.post('http://localhost:4000/api/verify-jwt-proof', {
        proofVerify: JSON.stringify(Array.from(proofVerify)),
        publicInputs: JSON.stringify(publicInputs, null, 2)
      });

      setVerificationResult({
        isValid: response.data.verified,
        message: response.data.message
      });
    } catch (err) {
      console.error('Verification failed:', err);
      if (err.response?.data) {
        console.error('Server error details:', err.response.data);
      }
      const errorMessage = err.response?.data?.message || err.message;
      setError(`Verification failed: ${errorMessage}`);
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <Box sx={{ maxWidth: 700, mx: 'auto', mt: 8 }}>
      <Card>
        <CardContent>
          <Typography variant="h5" gutterBottom>
            Create and Verify Zuitzpass Proof
          </Typography>
          {!circuitLoaded && <Alert severity="info">Loading circuit...</Alert>}
          
          <Typography variant="subtitle1" sx={{ mt: 2 }}>JWT Token:</Typography>
          <TextField
            fullWidth
            multiline
            rows={3}
            value={jwt || 'No JWT found'}
            InputProps={{ readOnly: true }}
            margin="normal"
          />

          <Typography variant="subtitle1" sx={{ mt: 2 }}>Google Public Key:</Typography>
          <TextField
            fullWidth
            multiline
            rows={4}
            value={pubkey ? JSON.stringify(pubkey, null, 2) : 'Loading public key...'}
            InputProps={{ readOnly: true }}
            margin="normal"
          />

          <Typography variant="subtitle1" sx={{ mt: 2 }}>Merkle Proof Inputs:</Typography>
          <TextField label="Merkle Root" name="merkle_root" fullWidth margin="normal" value={inputs.merkle_root} onChange={handleChange} />
          <TextField label="Proof Siblings (JSON array)" name="proof_siblings" fullWidth margin="normal" value={inputs.proof_siblings} onChange={handleChange} />
          <TextField label="Proof Index" name="proof_index" fullWidth margin="normal" value={inputs.proof_index} onChange={handleChange} />
          
          <Stack direction="row" spacing={2} sx={{ mt: 2 }}>
            <Button 
              variant="contained" 
              onClick={handleGenerateProof} 
              disabled={!circuitLoaded || !pubkey || isGenerating}
            >
              {isGenerating ? 'Generating Proof...' : 'Generate Proof'}
            </Button>
            <Button
              variant="contained"
              onClick={handleVerifyProof}
              disabled={!proofVerify || isVerifying}
              color="secondary"
            >
              {isVerifying ? 'Verifying...' : 'Verify Proof'}
            </Button>
          </Stack>
          
          {proofVerify && (
            <>
              <Typography variant="subtitle1" sx={{ mt: 2 }}>Proof:</Typography>
              <Box sx={{ position: 'relative' }}>
                <pre style={{ 
                  background: '#f5f5f5', 
                  padding: 8, 
                  borderRadius: 4,
                  maxHeight: '100px',
                  overflow: 'hidden',
                  position: 'relative'
                }}>
                  {JSON.stringify(proofVerify.slice(0, 2), null, 2)}
                  {proofVerify.length > 2 && (
                    <Box sx={{ 
                      position: 'absolute', 
                      bottom: 0, 
                      left: 0, 
                      right: 0, 
                      background: 'linear-gradient(transparent, #f5f5f5)',
                      height: '40px',
                      display: 'flex',
                      alignItems: 'flex-end',
                      justifyContent: 'center',
                      padding: '4px'
                    }}>
                      <Typography variant="caption" color="text.secondary">
                        ... {proofVerify.length - 2} more elements
                      </Typography>
                    </Box>
                  )}
                </pre>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => {
                    navigator.clipboard.writeText(JSON.stringify(proofVerify, null, 2));
                  }}
                  sx={{ mt: 1 }}
                >
                  Copy Full Proof
                </Button>
              </Box>
              
              <Typography variant="subtitle1" sx={{ mt: 2 }}>Public Inputs:</Typography>
              <pre style={{ background: '#f5f5f5', padding: 8, borderRadius: 4 }}>
                {JSON.stringify(publicInputs, null, 2)}
              </pre>
            </>
          )}
          
          {verificationResult && (
            <Alert 
              severity={verificationResult.isValid ? "success" : "error"}
              sx={{ mt: 2 }}
            >
              {verificationResult.message}
            </Alert>
          )}
          
          {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
        </CardContent>
      </Card>
    </Box>
  );
}

export default ProofCreator;