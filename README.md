<body>
  <h1>WhiteSea: ML Model Encryption Agent</h1>
<!-- Placeholder for Video -->
 <div class="video-container">
        <h2>Introduction Video</h2>
        
 

https://github.com/user-attachments/assets/ee62cb2b-6a75-4b16-bd5d-6e6bcb6c4f86



   <h2>Overview</h2>
    <p>whiteseaML is a project designed to encrypt and decrypt machine learning models, specifically targeting models saved in the .h5 format. This tool aims to enhance the security of sensitive machine learning models and prevent unauthorized access and data breaches.</p>

  <h2>Technologies Used</h2>
    <ul>
        <li><strong>MongoDB Atlas:</strong> A cloud-hosted database service that simplifies deploying and managing databases. It provides scalability and security for storing model metadata and user information.</li>
        <li><strong>Postman:</strong> Used for testing API endpoints to ensure that the encryption and decryption processes are functioning correctly.</li>
        <li><strong>Streamlit:</strong> A framework for creating web applications that allow users to interact with the encryption and decryption functionalities easily.</li>
    </ul>

  <h2>Features</h2>
   <ul>
        <li><strong>Model Encryption:</strong> Securely encrypt your existing .h5 models to protect them from unauthorized access.</li>
        <li><strong>Model Decryption:</strong> Easily decrypt encrypted models for use in your applications.</li>
        <li><strong>User-Friendly Interface:</strong> Simple command-line interface for easy interaction with the encryption and decryption processes.</li>
        <li><strong>Efficient Performance:</strong> Designed to ensure that encryption and decryption processes are efficient and do not significantly impact model performance.</li>
    </ul>

  <h2>Installation</h2>
    <p>To get started with whiteseaML, follow these steps:</p>
    <pre><code>git clone https://github.com/codeslayed/whiteseaML.git
cd whiteseaML
pip install -r requirements.txt
</code></pre>
   <h2>Usage</h2>
    <p>Once installed, you can encrypt or decrypt your .h5 models using the following commands:</p>

  <h3>Encrypt a Model</h3>
    <pre><code># Command to encrypt a model
python3 -m streamlit run whitesea.py
</code></pre>

  <h3>Decrypt a Model</h3>
    <pre><code># Command to decrypt a model
python3 -m streamlit run whiteseadec.py
</code></pre>

  <h2>Contributing</h2>
    <p>If you would like to contribute to this project, please fork the repository and create a pull request. We welcome contributions that improve the functionality and security of the tool!</p>

  <h2>License</h2>
    <p>This project is licensed under the MIT License - see the LICENSE file for details.</p>

  <h2>Contact</h2>
    <p>If you have any questions or suggestions, feel free to reach out via GitHub issues or contact the maintainer.</p>

</body>
