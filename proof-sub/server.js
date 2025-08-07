import express from 'express';
import axios from 'axios';
import fs from 'fs';
import dotenv from 'dotenv';
import cors from 'cors';

dotenv.config();

const app = express();
const port = 3001;

// Middleware
app.use(cors());
app.use(express.json());

const API_URL = 'https://relayer-api.horizenlabs.io/api/v1';
const API_KEY = "141fdb518133e2ea7256b77337956ced62e295bc";

// Endpoint to verify and aggregate a proof
app.post('/verify-proof', async (req, res) => {
    try {
        // Read proof.json from the script directory
        const proofPath = '../script/proof.json';
        if (!fs.existsSync(proofPath)) {
            return res.status(404).json({ error: 'proof.json not found' });
        }

        const proof = JSON.parse(fs.readFileSync(proofPath, 'utf8'));

        const params = {
            "proofType": "sp1",
            "vkRegistered": false,
            "chainId": 845320009,
            "proofData": {
                "proof": proof.proof,
                "publicSignals": proof.pub_inputs,
                "vk": proof.image_id
            }
        };

        console.log('Submitting proof to API...');
        const requestResponse = await axios.post(`${API_URL}/submit-proof/${API_KEY}`, params);
        
        if (requestResponse.data.optimisticVerify !== "success") {
            return res.status(400).json({ 
                error: "Proof verification failed", 
                details: requestResponse.data 
            });
        }

        console.log('Proof submitted successfully, waiting for aggregation...');
        
        // Poll for aggregation completion
        let attempts = 0;
        const maxAttempts = 60; // 20 minutes max (60 * 20 seconds)
        
        while (attempts < maxAttempts) {
            const jobStatusResponse = await axios.get(`${API_URL}/job-status/${API_KEY}/${requestResponse.data.jobId}`);
            
            if (jobStatusResponse.data.status === "Aggregated") {
                console.log('Job aggregated successfully');
                
                const aggregationData = {
                    ...jobStatusResponse.data.aggregationDetails,
                    aggregationId: jobStatusResponse.data.aggregationId
                };
                
                // Save to file
                fs.writeFileSync("aggregation.json", JSON.stringify(aggregationData));
                
                return res.json({
                    success: true,
                    message: "Proof verified and aggregated successfully",
                    aggregationData
                });
            } else {
                console.log(`Job status: ${jobStatusResponse.data.status}`);
                await new Promise(resolve => setTimeout(resolve, 20000)); // Wait 20 seconds
                attempts++;
            }
        }
        
        return res.status(408).json({ 
            error: "Aggregation timeout", 
            message: "Job did not complete within expected time" 
        });

    } catch (error) {
        console.error('Error:', error.message);
        res.status(500).json({ 
            error: "Internal server error", 
            message: error.message 
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', message: 'Proof verification API is running' });
});

// Get aggregation status endpoint
app.get('/status/:jobId', async (req, res) => {
    try {
        const { jobId } = req.params;
        const jobStatusResponse = await axios.get(`${API_URL}/job-status/${API_KEY}/${jobId}`);
        res.json(jobStatusResponse.data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(port, () => {
    console.log(`Proof verification API server running on http://localhost:${port}`);
});
