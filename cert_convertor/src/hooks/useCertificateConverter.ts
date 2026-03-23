import { useState, useEffect, useRef, useCallback } from 'react';

export const useCertificateConverter = () => {
  const [isProcessing, setIsProcessing] = useState(false);
  const workerRef = useRef<Worker | null>(null);

  useEffect(() => {
    // Initialize worker using Vite/Webpack 5 syntax
    workerRef.current = new Worker(
      new URL('../workers/converter.worker.ts', import.meta.url)
    );
    
    return () => workerRef.current?.terminate();
  }, []);

  const convertPfx = useCallback((buffer: ArrayBuffer, password: string): Promise<string> => {
    return new Promise((resolve, reject) => {
      if (!workerRef.current) return reject('Worker not initialized');

      setIsProcessing(true);

      workerRef.current.onmessage = (e) => {
        setIsProcessing(false);
        if (e.data.status === 'success') resolve(e.data.data);
        else reject(e.data.message);
      };

      workerRef.current.postMessage({ buffer, password, action: 'CONVERT_PFX' });
    });
  }, []);

  return { convertPfx, isProcessing };
};