import { useState } from 'react';
import './App.css';
import AppInfoDisplay from './components/AppInfoDisplay';
import FileUpload from './components/FileUpload';
import InsightsDisplay from './components/InsightsDisplay';
import TreemapVisualization from './components/TreemapVisualization';
import type { FileAnalysisReport } from './utils/dataConverter';

function App() {
  const [treemapData, setTreemapData] = useState<FileAnalysisReport | null>(null);
  const [sizeMode, setSizeMode] = useState<'install' | 'download'>('install');
  const [error, setError] = useState<string | null>(null);

  const handleDataLoad = (data: FileAnalysisReport) => {
    setTreemapData(data);
    setError(null);
  };

  const handleError = (errorMessage: string) => {
    setError(errorMessage);
    setTreemapData(null);
  };

  return (
    <div className="App" style={{ backgroundColor: '#fff', padding: '2rem' }}>
      <header style={{
        marginBottom: '2rem'
      }}>
        <h1 style={{ margin: 0, color: '#343a40' }}>
          Launchpad Size Analysis Viewer
        </h1>
        <p style={{ margin: '5px 0 0 0', color: '#6c757d' }}>
          Visualize treemap data from iOS and Android size analysis
        </p>
      </header>

      <main style={{ margin: '0 auto' }}>
        {error && (
          <div style={{
            backgroundColor: '#f8d7da',
            color: '#721c24',
            borderRadius: '4px',
            border: '1px solid #f5c6cb',
            overflow: 'hidden'
          }}>
            <strong>Error:</strong> {error}
          </div>
        )}

        {!treemapData ? (
          <div style={{ marginBottom: '40px' }}>
            <FileUpload onDataLoad={handleDataLoad} onError={handleError} />
          </div>
        ) : (
          <div>
            {/* Treemap Visualization */}
            <div style={{
              backgroundColor: '#f8f9fa',
              overflow: 'hidden',
              borderRadius: '6px',
              marginBottom: '1rem'
            }}>
              <div style={{
                padding: '1rem',
                borderBottom: '1px solid #dee2e6',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <h3 style={{ margin: 0, color: '#343a40' }}>Size Analysis</h3>
                <button
                  onClick={() => setSizeMode(sizeMode === 'install' ? 'download' : 'install')}
                  style={{
                    backgroundColor: '#007bff',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    padding: '6px 12px',
                    cursor: 'pointer',
                    fontSize: '12px'
                  }}
                >
                  {sizeMode === 'install' ? 'Install Size' : 'Download Size'}
                </button>
              </div>
              <TreemapVisualization data={treemapData} sizeMode={sizeMode} />
            </div>

            {/* App Info Display */}
            <AppInfoDisplay data={treemapData} />

            {/* Insights Display */}
            <InsightsDisplay data={treemapData} />
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
