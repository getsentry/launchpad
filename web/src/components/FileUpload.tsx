import React, { useState } from 'react';
import type { FileAnalysisReport } from '../utils/dataConverter';
import { parseFileAnalysisReport } from '../utils/dataConverter';

interface FileUploadProps {
  onDataLoad: (data: FileAnalysisReport) => void;
  onError: (error: string) => void;
}

export const FileUpload: React.FC<FileUploadProps> = ({ onDataLoad, onError }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const handleFile = async (file: File) => {
    if (!file.name.endsWith('.json')) {
      onError('Please select a JSON file');
      return;
    }

    setIsLoading(true);
    try {
      const text = await file.text();
      const rawData = JSON.parse(text);

      // Debug logging
      console.log('Raw data keys:', Object.keys(rawData));
      console.log('Raw data sample:', JSON.stringify(rawData, null, 2).substring(0, 1000) + '...');

      // Parse the file analysis report
      const report = parseFileAnalysisReport(rawData);

      // Pass the full report
      onDataLoad(report);
    } catch (err) {
      if (err instanceof SyntaxError) {
        onError('Invalid JSON file. Please check that the file contains valid JSON.');
      } else {
        console.error('File loading error:', err);
        onError(`Error loading file: ${err instanceof Error ? err.message : 'Unknown error'}`);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleSampleData = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('/sample-data.json');
      if (!response.ok) {
        throw new Error('Failed to load sample data');
      }
      const rawData = await response.json();

      // Parse the file analysis report
      const report = parseFileAnalysisReport(rawData);
      onDataLoad(report);
    } catch (err) {
      onError(`Error loading sample data: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      handleFile(file);
    }
  };

  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);

    const file = event.dataTransfer.files[0];
    if (file) {
      handleFile(file);
    }
  };

  const handleDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        style={{
          border: `2px dashed ${isDragging ? '#007bff' : '#ccc'}`,
          borderRadius: '8px',
          padding: '40px',
          textAlign: 'center',
          backgroundColor: isDragging ? '#f8f9fa' : '#fff',
          cursor: 'pointer',
          transition: 'all 0.3s ease',
        }}
      >
        <input
          type="file"
          accept=".json"
          onChange={handleFileSelect}
          style={{ display: 'none' }}
          id="file-upload"
          disabled={isLoading}
        />
        <label htmlFor="file-upload" style={{ cursor: 'pointer' }}>
          {isLoading ? (
            <div>
              <div>Loading...</div>
              <div style={{ marginTop: '10px', fontSize: '14px', color: '#666' }}>
                Parsing and converting data...
              </div>
            </div>
          ) : (
            <div>
              <div style={{ fontSize: '24px', marginBottom: '10px' }}>📁</div>
              <div style={{ fontSize: '18px', marginBottom: '10px' }}>
                Drop a JSON file here or click to select
              </div>
              <div style={{ fontSize: '14px', color: '#666' }}>
                Supports FileAnalysisReport format
              </div>
            </div>
          )}
        </label>
      </div>

      {/* Quick Test Option */}
      <div style={{
        textAlign: 'center',
        padding: '20px',
        backgroundColor: '#e8f4f8',
        borderRadius: '8px',
        border: '1px solid #bee5eb'
      }}>
        <div style={{ marginBottom: '15px' }}>
          <strong>🚀 Quick Test</strong>
        </div>
        <div style={{ fontSize: '14px', color: '#0c5460', marginBottom: '15px' }}>
          Load sample iOS analysis data to try out the visualization
        </div>
        <button
          onClick={handleSampleData}
          disabled={isLoading}
          style={{
            padding: '10px 20px',
            backgroundColor: '#17a2b8',
            color: 'white',
            border: 'none',
            borderRadius: '6px',
            cursor: isLoading ? 'not-allowed' : 'pointer',
            fontSize: '14px',
            fontWeight: '500',
            opacity: isLoading ? 0.6 : 1
          }}
        >
          {isLoading ? 'Loading...' : 'Load Sample Data'}
        </button>
      </div>
    </div>
  );
};

export default FileUpload;
