import React, { useState } from 'react';
import { Upload, Lock, ShieldCheck, Download, Loader2 } from 'lucide-react';
import { useCertificateConverter } from '../hooks/useCertificateConverter';

export const Converter: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const { convertPfx, isProcessing } = useCertificateConverter();

  const handleDownload = (content: string) => {
    const blob = new Blob([content], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = file ? `${file.name.split('.')[0]}.pem` : 'certificate.pem';
    link.click();
    URL.revokeObjectURL(url);
  };

  const startConversion = async () => {
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const buffer = e.target?.result as ArrayBuffer;
        const pem = await convertPfx(buffer, password);
        handleDownload(pem);
      } catch (err) {
        alert(err);
      }
    };
    reader.readAsArrayBuffer(file);
  };

  return (
    <div className="max-w-xl mx-auto mt-20 p-8 bg-white shadow-2xl rounded-2xl border border-slate-100">
      <header className="text-center mb-8">
        <h1 className="text-3xl font-bold text-slate-800">CertConvert Pro</h1>
        <p className="text-slate-500 mt-2">Secure PFX to PEM conversion in-browser</p>
      </header>

      {/* Upload Area */}
      <div className="relative group">
        <input 
          type="file" 
          accept=".pfx,.p12"
          onChange={(e) => setFile(e.target.files?.[0] || null)}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
        />
        <div className={`p-10 border-2 border-dashed rounded-xl flex flex-col items-center transition-all ${
          file ? 'border-green-400 bg-green-50' : 'border-slate-200 group-hover:border-blue-400 bg-slate-50'
        }`}>
          <Upload className={`w-10 h-10 mb-4 ${file ? 'text-green-500' : 'text-slate-400'}`} />
          <p className="text-sm font-medium text-slate-700">
            {file ? file.name : "Drag and drop your .pfx file here"}
          </p>
        </div>
      </div>

      {/* Password Input */}
      <div className="mt-6">
        <label className="block text-sm font-semibold text-slate-700 mb-2 flex items-center gap-2">
          <Lock className="w-4 h-4" /> PFX Password
        </label>
        <input 
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Enter certificate password"
          className="w-full px-4 py-3 rounded-lg border border-slate-200 focus:ring-2 focus:ring-blue-500 outline-none transition-all"
        />
      </div>

      {/* Action Button */}
      <button 
        onClick={startConversion}
        disabled={!file || isProcessing}
        className="w-full mt-8 bg-slate-900 text-white py-4 rounded-xl font-bold flex items-center justify-center gap-3 hover:bg-slate-800 disabled:bg-slate-300 transition-all shadow-lg"
      >
        {isProcessing ? (
          <Loader2 className="w-5 h-5 animate-spin" />
        ) : (
          <>
            <Download className="w-5 h-5" />
            Convert to PEM
          </>
        )}
      </button>

      <footer className="mt-6 flex items-center justify-center gap-2 text-xs text-slate-400 uppercase tracking-widest font-bold">
        <ShieldCheck className="w-4 h-4 text-green-500" />
        Privacy Guaranteed: No data leaves your browser
      </footer>
    </div>
  );
};