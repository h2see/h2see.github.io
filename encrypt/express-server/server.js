const crypto = require('crypto');
const express = require('express');

const port = 49160;

const app = express();

app.use(express.json());

app.post('/encrypt', async (req, res) => {
    try {
        const requestBody = req.body;

        const password = requestBody.password;
        const documentContent = Buffer.from(requestBody.document, 'base64'); // Decode base64 to Buffer

        // Convert password to Buffer
        const passwordBuffer = Buffer.from(password, 'utf-8');

        // Generate random salt with 128 bits (16 bytes)
        const salt = crypto.randomBytes(16);

        // Derive key from password using PBKDF2
        const key = crypto.pbkdf2Sync(passwordBuffer, salt, 480000, 32, 'sha256'); // Derive 256-bit key

        // Generate random IV (Initialization Vector)
        const iv = crypto.randomBytes(12);

        // Encrypt the document using AES-GCM
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

        const encrypted = Buffer.concat([cipher.update(documentContent), cipher.final()]);

        // Get the authentication tag
        const authTag = cipher.getAuthTag();

        // Encode ciphertext, authTag, IV, and salt to base64
        const encryptedDocument = Buffer.concat([encrypted, authTag]).toString('base64'); // Append authTag to ciphertext
        const ivBase64 = iv.toString('base64');
        const saltBase64 = salt.toString('base64');

        // Return JSON response
        res.json({
            document: encryptedDocument, // Encrypted document as base64 string
            iv: ivBase64, // IV as base64 string
            salt: saltBase64 // Salt as base64 string
        });
    } catch (error) {
        res.status(500).json({
            error: 'Encryption failed',
            details: error.message
        });
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://127.0.0.1:${port}`);
});
