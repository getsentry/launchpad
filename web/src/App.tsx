import React, { useState } from 'react';
import './App.css';
import FileUpload from './components/FileUpload';
import TreemapVisualization from './components/TreemapVisualization';
import type { TreemapResults } from './types/treemap';

function App() {
  const [treemapData, setTreemapData] = useState<TreemapResults | null>(null);
  const [sizeMode, setSizeMode] = useState<'install' | 'download'>('install');
  const [error, setError] = useState<string | null>(null);

  const handleDataLoad = (data: TreemapResults) => {
    setTreemapData(data);
    setError(null);
  };

  const handleError = (errorMessage: string) => {
    setError(errorMessage);
    setTreemapData(null);
  };

  const handleReset = () => {
    setTreemapData(null);
    setError(null);
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="App">
      <header style={{
        padding: '20px',
        backgroundColor: '#f8f9fa',
        borderBottom: '1px solid #dee2e6',
        marginBottom: '20px'
      }}>
        <h1 style={{ margin: 0, color: '#343a40' }}>
          Launchpad Size Analysis Viewer
        </h1>
        <p style={{ margin: '5px 0 0 0', color: '#6c757d' }}>
          Visualize treemap data from iOS and Android size analysis
        </p>
      </header>

      <main style={{ padding: '0 20px', maxWidth: '1200px', margin: '0 auto' }}>
        {error && (
          <div style={{
            backgroundColor: '#f8d7da',
            color: '#721c24',
            padding: '12px',
            borderRadius: '4px',
            marginBottom: '20px',
            border: '1px solid #f5c6cb'
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
            {/* Controls */}
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '20px',
              padding: '15px',
              backgroundColor: '#f8f9fa',
              borderRadius: '8px',
              border: '1px solid #dee2e6'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                <div>
                  <label style={{ marginRight: '10px', fontWeight: 'bold' }}>Size Mode:</label>
                  <select
                    value={sizeMode}
                    onChange={(e) => setSizeMode(e.target.value as 'install' | 'download')}
                    style={{
                      padding: '5px 10px',
                      borderRadius: '4px',
                      border: '1px solid #ced4da'
                    }}
                  >
                    <option value="install">Install Size</option>
                    <option value="download">Download Size</option>
                  </select>
                </div>
                <div style={{ fontSize: '14px', color: '#6c757d' }}>
                  <strong>Platform:</strong> {treemapData.platform.toUpperCase()} |
                  <strong> Files:</strong> {treemapData.file_count.toLocaleString()} |
                  <strong> Total:</strong> {formatBytes(sizeMode === 'install' ? treemapData.total_install_size : treemapData.total_download_size)}
                </div>
              </div>
              <button
                onClick={handleReset}
                style={{
                  padding: '8px 16px',
                  backgroundColor: '#dc3545',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                Load New File
              </button>
            </div>

            {/* Treemap Visualization */}
            <div style={{
              backgroundColor: 'white',
              borderRadius: '8px',
              border: '1px solid #dee2e6',
              overflow: 'hidden'
            }}>
              <TreemapVisualization data={treemapData} sizeMode={sizeMode} />
            </div>

            {/* Category Breakdown */}
            {Object.keys(treemapData.category_breakdown).length > 0 && (
              <div style={{
                marginTop: '20px',
                padding: '20px',
                backgroundColor: '#f8f9fa',
                borderRadius: '8px',
                border: '1px solid #dee2e6'
              }}>
                <h3 style={{ marginTop: 0 }}>Category Breakdown</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '15px' }}>
                  {Object.entries(treemapData.category_breakdown).map(([category, sizes]) => (
                    <div key={category} style={{
                      padding: '15px',
                      backgroundColor: 'white',
                      borderRadius: '6px',
                      border: '1px solid #dee2e6'
                    }}>
                      <h4 style={{ margin: '0 0 10px 0', textTransform: 'capitalize' }}>
                        {category.replace('_', ' ')}
                      </h4>
                      <div style={{ fontSize: '14px' }}>
                        {Object.entries(sizes).map(([type, size]) => (
                          <div key={type} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}>
                            <span style={{ textTransform: 'capitalize' }}>{type}:</span>
                            <span style={{ fontWeight: 'bold' }}>{formatBytes(size)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
