import React from 'react';
import type { FileAnalysisReport } from '../utils/dataConverter';

interface AppInfoDisplayProps {
  data: FileAnalysisReport;
}

const AppInfoDisplay: React.FC<AppInfoDisplayProps> = ({ data }) => {
  const formatBytes = (bytes: number, usesSiUnits: boolean): string => {
    if (bytes === 0) return '0 Bytes';
    const k = usesSiUnits ? 1000 : 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatSize = (bytes: number): string => {
    return formatBytes(bytes, data.use_si_units);
  };

  return (
    <div style={{
      backgroundColor: '#f8f9fa',
      borderRadius: '8px',
      padding: '1.5rem',
      marginBottom: '1.5rem',
      border: '1px solid #e9ecef',
      maxWidth: '800px',
      margin: '0 auto 1.5rem auto'
    }}>
      {/* App Basic Info */}
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 style={{
          margin: '0 0 1rem 0',
          color: '#343a40',
          fontSize: '1.5rem',
          fontWeight: '600'
        }}>
          {data.app_info.name}
        </h2>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '0.75rem',
          marginBottom: '1rem',
          color: '#6c757d'
        }}>
          <div>
            <strong>Version:</strong> {data.app_info.version}
          </div>
          <div>
            <strong>Build:</strong> {data.app_info.build}
          </div>
          <div>
            <strong>App ID:</strong> {data.app_info.app_id}
          </div>
          {data.app_info.executable && (
            <div>
              <strong>Executable:</strong> {data.app_info.executable}
            </div>
          )}
        </div>
      </div>

      {/* Size Information */}
      <div style={{ marginBottom: '1.5rem' }}>
        <h3 style={{
          margin: '0 0 1rem 0',
          color: '#495057',
          fontSize: '1.25rem',
          fontWeight: '600'
        }}>
          Size Analysis
        </h3>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '1rem'
        }}>
          <div style={{
            backgroundColor: '#e3f2fd',
            padding: '1rem',
            borderRadius: '6px',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#1976d2' }}>
              {formatSize(data.treemap.total_install_size)}
            </div>
            <div style={{ color: '#6c757d', fontSize: '0.875rem' }}>Install Size</div>
          </div>

          <div style={{
            backgroundColor: '#f3e5f5',
            padding: '1rem',
            borderRadius: '6px',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#7b1fa2' }}>
              {formatSize(data.treemap.total_download_size)}
            </div>
            <div style={{ color: '#6c757d', fontSize: '0.875rem' }}>Download Size</div>
          </div>

          <div style={{
            backgroundColor: '#e8f5e8',
            padding: '1rem',
            borderRadius: '6px',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#388e3c' }}>
              {data.treemap.file_count.toLocaleString()}
            </div>
            <div style={{ color: '#6c757d', fontSize: '0.875rem' }}>Files</div>
          </div>
        </div>
      </div>

      {/* Apple-specific Info */}
      {data.app_info.minimum_os_version && (
        <div style={{ marginBottom: '1.5rem' }}>
          <h3 style={{
            margin: '0 0 1rem 0',
            color: '#495057',
            fontSize: '1.25rem',
            fontWeight: '600'
          }}>
            Apple App Details
          </h3>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '0.75rem'
          }}>
            {data.app_info.minimum_os_version && (
              <div>
                <strong style={{ color: '#6c757d' }}>Minimum OS Version:</strong> {data.app_info.minimum_os_version}
              </div>
            )}

            {data.app_info.sdk_version && (
              <div>
                <strong style={{ color: '#6c757d' }}>SDK Version:</strong> {data.app_info.sdk_version}
              </div>
            )}

            {data.app_info.supported_platforms && data.app_info.supported_platforms.length > 0 && (
              <div>
                <strong style={{ color: '#6c757d' }}>Supported Platforms:</strong> {data.app_info.supported_platforms.join(', ')}
              </div>
            )}

            {data.app_info.is_simulator !== undefined && (
              <div>
                <strong style={{ color: '#6c757d' }}>Simulator Build:</strong> {data.app_info.is_simulator ? 'Yes' : 'No'}
              </div>
            )}

            {data.app_info.codesigning_type && (
              <div>
                <strong style={{ color: '#6c757d' }}>Code Signing:</strong> {data.app_info.codesigning_type}
              </div>
            )}

            {data.app_info.profile_name && (
              <div>
                <strong style={{ color: '#6c757d' }}>Provisioning Profile:</strong> {data.app_info.profile_name}
              </div>
            )}

            {data.app_info.is_code_signature_valid !== undefined && (
              <div>
                <strong style={{ color: '#6c757d' }}>Code Signature Valid:</strong>
                <span style={{
                  color: data.app_info.is_code_signature_valid ? '#28a745' : '#dc3545',
                  marginLeft: '0.5rem'
                }}>
                  {data.app_info.is_code_signature_valid ? 'Yes' : 'No'}
                </span>
              </div>
            )}
          </div>

          {data.app_info.code_signature_errors && data.app_info.code_signature_errors.length > 0 && (
            <div style={{ marginTop: '1rem' }}>
              <strong style={{ color: '#dc3545' }}>Code Signature Errors:</strong>
              <ul style={{ margin: '0.5rem 0 0 1.5rem', color: '#dc3545' }}>
                {data.app_info.code_signature_errors.map((error, index) => (
                  <li key={index}>{error}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Analysis Info */}
      <div style={{
        borderTop: '1px solid #dee2e6',
        paddingTop: '1rem',
        color: '#6c757d',
        fontSize: '0.875rem'
      }}>
        <strong>Analysis generated:</strong> {new Date(data.generated_at).toLocaleString()}
      </div>
    </div>
  );
};

export default AppInfoDisplay;
