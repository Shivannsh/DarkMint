#!/bin/bash

# Install dependencies if not already installed
npm install

# Start the API server
echo "Starting proof verification API server on http://localhost:3001"
node server.js
