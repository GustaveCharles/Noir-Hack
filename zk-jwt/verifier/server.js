const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const { Noir } = require('@noir-lang/noir_js');
const { UltraHonkBackend } = require('@aztec/bb.js');

const app = express();
const port = process.env.PORT || 4000;

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

let noir = null;
let backend = null;

// Load circuit on startup
async function loadCircuit() {
  try {
    const fs = require('fs');
    const circuit = JSON.parse(fs.readFileSync(path.join(__dirname, 'zuitzpass.json'), 'utf8'));
    noir = new Noir(circuit);
    backend = new UltraHonkBackend(circuit.bytecode);
    console.log('Circuit loaded successfully');
  } catch (err) {
    console.error('Error loading circuit:', err);
    process.exit(1);
  }
}

// POST /api/verify-jwt-proof
app.post('/api/verify-jwt-proof', async (req, res) => {
  try {


    const { proofVerify, publicInputs } = req.body;


    try {
     const proofParsed = Uint8Array.from(JSON.parse(proofVerify));
     const publicInputsParsed = JSON.parse(publicInputs);

      const verified = await backend.verifyProof({ 
        proof: proofParsed,
        publicInputs: publicInputsParsed
      });
      
      console.log('Proof verification result:', verified);
      
      if (!verified) {
        console.error('Proof verification failed');
        return res.status(400).json({
          error: 'Verification failed',
          message: 'Invalid ZK proof'
        });
      }

      res.status(200).json({
        message: 'Zuitzpass proof verified successfully!',
        verified: true
      });

    } catch (err) {
      console.error('Error converting public inputs:', err);
      return res.status(400).json({
        error: 'Invalid input format',
        message: err.message
      });
    }

  } catch (err) {
    console.error('Error during proof verification:', err);
    return res.status(500).json({
      error: 'Internal server error',
      message: err.message,
      details: err.stack
    });
  }
});

// Initialize server
loadCircuit().then(() => {
  app.listen(port, () => {
    console.log(`Verifier server running on port ${port}`);
  });
}); 