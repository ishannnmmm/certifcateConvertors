# certifcateConvertors
A high-performance, privacy-first SSL certificate converter built with React and TypeScript. This tool allows users to convert complex certificate formats (like PKCS#12/PFX) into PEM format entirely within the browser.

# Key features 
Zero-Server Architecture: All cryptographic operations happen on the client side. Private keys never leave the user's machine.

Multithreaded Processing: Utilizes Web Workers to offload CPU-intensive RSA decryption, ensuring the UI remains responsive (60fps) during conversion.

Type-Safe Implementation: Built with TypeScript for robust error handling and data integrity.

Modern UX: Drag-and-drop interface with real-time feedback and progress states.

# Architecture
The project is designed with a Decoupled Worker Pattern to separate concerns:

UI Layer (React + Tailwind): Manages component state, file selection, and user interactions.

Orchestration Layer (Custom Hooks): A specialized useCertificateConverter hook manages the lifecycle of the Web Worker, including initialization and message passing.

Computation Layer (Web Workers + Node-Forge): Performs the heavy lifting of parsing ASN.1 structures and DER-encoded buffers in a background thread.

# Installation & Setup
Clone the repository:

Bash
git clone https://github.com/ishannnmmm/certifcateConvertors.git
cd certifcateConvertors
Install dependencies:

Bash
npm install
Run the development server:

Bash
npm run dev

# Future commits -

Will inculde automation of certifcate uploads to ACM
