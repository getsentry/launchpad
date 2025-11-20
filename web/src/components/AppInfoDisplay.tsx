import React from 'react';
import type { FileAnalysisReport } from '../utils/dataConverter';
import { ComponentType } from '../utils/dataConverter';

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

  const formatComponentType = (type: ComponentType): string => {
    switch (type) {
      case ComponentType.WATCH_ARTIFACT:
        return 'Watch App';
      case ComponentType.ANDROID_DYNAMIC_FEATURE:
        return 'Dynamic Feature';
      case ComponentType.MAIN_ARTIFACT:
        return 'Main App';
      default:
        return 'Unknown';
    }
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

        {/* Show breakdown if components exist */}
        {data.app_components && data.app_components.length > 0 ? (
          <>
            {(() => {
              // Calculate main app sizes
              const totalComponentInstall = data.app_components.reduce((sum, c) => sum + c.install_size, 0);
              const totalComponentDownload = data.app_components.reduce((sum, c) => sum + c.download_size, 0);
              const mainInstall = data.install_size - totalComponentInstall;
              const mainDownload = data.download_size - totalComponentDownload;

              return (
                <>
                  {/* Main App */}
                  <div style={{
                    marginBottom: '1rem',
                    fontSize: '0.875rem',
                    color: '#6c757d',
                    fontWeight: '500'
                  }}>
                    Main App
                  </div>
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
                    gap: '1rem',
                    marginBottom: '1.5rem'
                  }}>
                    <div style={{
                      backgroundColor: '#e3f2fd',
                      padding: '1rem',
                      borderRadius: '6px',
                      textAlign: 'center'
                    }}>
                      <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#1976d2' }}>
                        {formatSize(mainInstall)}
                      </div>
                      <div style={{ color: '#9e9e9e', fontSize: '0.75rem', marginTop: '0.25rem' }}>
                        {mainInstall.toLocaleString()} bytes
                      </div>
                      <div style={{ color: '#6c757d', fontSize: '0.875rem', marginTop: '0.5rem' }}>Install Size</div>
                    </div>

                    <div style={{
                      backgroundColor: '#f3e5f5',
                      padding: '1rem',
                      borderRadius: '6px',
                      textAlign: 'center'
                    }}>
                      <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#7b1fa2' }}>
                        {formatSize(mainDownload)}
                      </div>
                      <div style={{ color: '#9e9e9e', fontSize: '0.75rem', marginTop: '0.25rem' }}>
                        {mainDownload.toLocaleString()} bytes
                      </div>
                      <div style={{ color: '#6c757d', fontSize: '0.875rem', marginTop: '0.5rem' }}>Download Size</div>
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

                  {/* Components */}
                  <div style={{ marginBottom: '1.5rem' }}>
                    <div style={{
                      marginBottom: '0.75rem',
                      fontSize: '0.875rem',
                      color: '#6c757d',
                      fontWeight: '500'
                    }}>
                      Components ({data.app_components.length})
                    </div>
                    <div style={{
                      backgroundColor: '#fff3cd',
                      padding: '1rem',
                      borderRadius: '6px',
                      border: '1px solid #ffeaa7'
                    }}>
                      {data.app_components.map((component, index) => (
                        <div
                          key={index}
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            padding: '0.5rem 0',
                            borderBottom: index < data.app_components!.length - 1 ? '1px solid #ffeaa7' : 'none'
                          }}
                        >
                          <div>
                            <div style={{ fontWeight: '600', color: '#856404' }}>
                              {component.name}
                            </div>
                            <div style={{ fontSize: '0.75rem', color: '#856404' }}>
                              {formatComponentType(component.component_type)}
                            </div>
                          </div>
                          <div style={{ textAlign: 'right', color: '#856404' }}>
                            <div style={{ fontSize: '0.875rem', fontWeight: '500' }}>
                              Install: {formatSize(component.install_size)}
                            </div>
                            <div style={{ fontSize: '0.7rem', color: '#9e9e9e' }}>
                              {component.install_size.toLocaleString()} bytes
                            </div>
                            <div style={{ fontSize: '0.875rem', marginTop: '0.25rem' }}>
                              Download: {formatSize(component.download_size)}
                            </div>
                            <div style={{ fontSize: '0.7rem', color: '#9e9e9e' }}>
                              {component.download_size.toLocaleString()} bytes
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Total */}
                  <div style={{
                    marginBottom: '0.5rem',
                    fontSize: '0.875rem',
                    color: '#6c757d',
                    fontWeight: '500'
                  }}>
                    Total (Main + Components)
                  </div>
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
                    gap: '1rem'
                  }}>
                    <div style={{
                      backgroundColor: '#e3f2fd',
                      padding: '1rem',
                      borderRadius: '6px',
                      textAlign: 'center',
                      border: '2px solid #1976d2'
                    }}>
                      <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#1976d2' }}>
                        {formatSize(data.install_size)}
                      </div>
                      <div style={{ color: '#9e9e9e', fontSize: '0.75rem', marginTop: '0.25rem' }}>
                        {data.install_size.toLocaleString()} bytes
                      </div>
                      <div style={{ color: '#6c757d', fontSize: '0.875rem', marginTop: '0.5rem' }}>Total Install</div>
                    </div>

                    <div style={{
                      backgroundColor: '#f3e5f5',
                      padding: '1rem',
                      borderRadius: '6px',
                      textAlign: 'center',
                      border: '2px solid #7b1fa2'
                    }}>
                      <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#7b1fa2' }}>
                        {formatSize(data.download_size)}
                      </div>
                      <div style={{ color: '#9e9e9e', fontSize: '0.75rem', marginTop: '0.25rem' }}>
                        {data.download_size.toLocaleString()} bytes
                      </div>
                      <div style={{ color: '#6c757d', fontSize: '0.875rem', marginTop: '0.5rem' }}>Total Download</div>
                    </div>
                  </div>
                </>
              );
            })()}
          </>
        ) : (
          // No components - show simple view
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
                {formatSize(data.install_size)}
              </div>
              <div style={{ color: '#9e9e9e', fontSize: '0.75rem', marginTop: '0.25rem' }}>
                {data.install_size.toLocaleString()} bytes
              </div>
              <div style={{ color: '#6c757d', fontSize: '0.875rem', marginTop: '0.5rem' }}>Install Size</div>
            </div>

            <div style={{
              backgroundColor: '#f3e5f5',
              padding: '1rem',
              borderRadius: '6px',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#7b1fa2' }}>
                {formatSize(data.download_size)}
              </div>
              <div style={{ color: '#9e9e9e', fontSize: '0.75rem', marginTop: '0.25rem' }}>
                {data.download_size.toLocaleString()} bytes
              </div>
              <div style={{ color: '#6c757d', fontSize: '0.875rem', marginTop: '0.5rem' }}>Download Size</div>
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
        )}
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
