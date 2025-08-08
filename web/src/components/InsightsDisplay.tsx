import React from 'react';
import type { DuplicateFilesInsightResult, FileAnalysisReport, ImageOptimizationInsightResult, InsightResult, LooseImagesInsightResult, StripBinaryInsightResult } from '../utils/dataConverter';

// Add type for main binary export metadata
interface FileSavingsResult {
  file_path: string;
  total_savings: number;
}

interface MainBinaryExportMetadataResult {
  total_savings: number;
  files: FileSavingsResult[];
}

interface FileSavingsInsightResult {
  total_savings: number;
  files: FileSavingsResult[];
}

interface InsightsDisplayProps {
  data: FileAnalysisReport;
}

const InsightsDisplay: React.FC<InsightsDisplayProps> = ({ data }) => {
  const { insights } = data;

  if (!insights) {
    return null;
  }

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

    const renderFileSavingsResults = (
    files: FileSavingsResult[],
    savingsLabel: string = 'savings'
  ) => (
    <div style={{
      backgroundColor: '#f8f9fa',
      borderRadius: '6px',
      padding: '0.75rem',
      maxHeight: '200px',
      overflowY: 'auto'
    }}>
      {files.map((file, index) => (
        <div
          key={index}
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '0.75rem',
            marginBottom: index < files.length - 1 ? '0.5rem' : '0',
            backgroundColor: '#ffffff',
            borderRadius: '4px',
            border: '1px solid #e9ecef'
          }}
        >
          <div style={{
            flex: 1,
            color: '#495057',
            fontFamily: 'monospace',
            fontSize: '0.8rem',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            marginRight: '1rem'
          }}>
            {file.file_path}
          </div>
          <div style={{
            color: '#28a745',
            fontSize: '0.8rem',
            fontWeight: '600',
            flexShrink: 0
          }}>
            {formatSize(file.total_savings)} {savingsLabel}
          </div>
        </div>
      ))}
    </div>
  );

  const getInsightTitle = (key: string): string => {
    const titles: Record<string, string> = {
      duplicate_files: 'Duplicate Files',
      large_images: 'Large Images',
      large_videos: 'Large Videos',
      large_audio: 'Large Audio Files',
      audio_compression: 'Audio Compression',
      video_compression: 'Video Compression',
      hermes_debug_info: 'Hermes Debug Info',
      webp_optimization: 'WebP Optimization',
      image_optimization: 'Image Optimization',
      strip_binary: 'Binary Stripping',
      localized_strings: 'Localized Strings',
      localized_strings_minify: 'Localized Strings Minify',
      localized_strings_comments: 'Localized Strings Comments',
      small_files: 'Small Files',
      unnecessary_files: 'Unnecessary Files',
      main_binary_exported_symbols: 'Main Binary Export Metadata',
      loose_images: 'Loose Images',
    };
    return titles[key] || key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  };

  const getInsightDescription = (key: string): string => {
    const descriptions: Record<string, string> = {
      duplicate_files: 'Files that appear multiple times in your app, wasting space',
      large_images: 'Image files with potential optimization savings',
      large_videos: 'Video files with potential compression savings',
      large_audio: 'Audio files with potential optimization savings',
      audio_compression: 'Audio files that can be compressed to AAC format for size reduction',
      video_compression: 'Video files that can be compressed with H.264/HEVC encoding for size reduction',
      hermes_debug_info: 'Debug information that can be removed from production builds',
      webp_optimization: 'Images that could be converted to WebP format for better compression',
      image_optimization: 'Image files that can be optimized through minification or HEIC conversion',
      strip_binary: 'Debug symbols and metadata that can be removed from binaries',
      localized_strings: 'Localization strings with potential optimization savings',
      localized_strings_minify: 'Comments and whitespace in localized strings files that can be stripped to save space',
      localized_strings_comments: 'Comments in localized strings files that can be stripped to save space',
      small_files: 'Small files wasting space due to filesystem block size constraints',
      main_binary_exported_symbols: 'Export metadata in main binaries that could be optimized',
      unnecessary_files: 'Unnecessary files that can be removed to save space',
      loose_images: 'Loose image files that could benefit from app thinning via asset catalogs',
    };
    return descriptions[key] || 'Potential optimization opportunity';
  };

  const getInsightIcon = (key: string): string => {
    const icons: Record<string, string> = {
      duplicate_files: '📁',
      large_images: '🖼️',
      large_videos: '🎥',
      large_audio: '🎵',
      audio_compression: '🎵',
      video_compression: '🎥',
      hermes_debug_info: '🐛',
      webp_optimization: '🗜️',
      image_optimization: '📸',
      strip_binary: '⚡',
      localized_strings: '🌐',
      localized_strings_minify: '✂️',
      localized_strings_comments: '💬',
      small_files: '📄',
      main_binary_exported_symbols: '📦',
      unnecessary_files: '🗑️',
      loose_images: '🖼️',
    };
    return icons[key] || '💡';
  };

  const insightEntries = Object.entries(insights).filter(([key, value]) => {
    // Skip null, undefined, or invalid insights
    if (!value || typeof value !== 'object') {
      return false;
    }

    // Skip insights that don't have meaningful data
    const hasValidSavings = typeof value.total_savings === 'number' && value.total_savings >= 0;

    // Handle duplicate files differently (has groups instead of files)
    if (key === 'duplicate_files') {
      const duplicateInsight = value as DuplicateFilesInsightResult;
      const hasGroups = duplicateInsight.groups && Array.isArray(duplicateInsight.groups) && duplicateInsight.groups.length > 0;
      return hasValidSavings || hasGroups;
    }

    // Handle strip binary differently (has custom file format)
    if (key === 'strip_binary') {
      const stripInsight = value as StripBinaryInsightResult;
      const hasFiles = stripInsight.files && Array.isArray(stripInsight.files) && stripInsight.files.length > 0;
      return hasValidSavings || hasFiles;
    }

    // Handle loose images differently (has groups instead of image_groups)
    if (key === 'loose_images') {
      const looseImagesInsight = value as any; // Use any since actual structure doesn't match interface
      const hasGroups = looseImagesInsight.groups && Array.isArray(looseImagesInsight.groups) && looseImagesInsight.groups.length > 0;
      return hasValidSavings || hasGroups;
    }

    // Handle image optimization differently (has optimizable_files instead of files)
    if (key === 'image_optimization') {
      const imageOptInsight = value as ImageOptimizationInsightResult;
      const hasOptimizableFiles = imageOptInsight.optimizable_files && Array.isArray(imageOptInsight.optimizable_files) && imageOptInsight.optimizable_files.length > 0;
      return hasValidSavings || hasOptimizableFiles;
    }

    // Handle main binary export metadata differently (has FileSavingsResult files)
    if (key === 'main_binary_exported_symbols') {
      const exportInsight = value as MainBinaryExportMetadataResult;
      const hasFiles = exportInsight.files && Array.isArray(exportInsight.files) && exportInsight.files.length > 0;
      return hasValidSavings || hasFiles;
    }

    // Handle insights that now use FileSavingsResult format
    if (['large_images', 'large_videos', 'large_audio', 'hermes_debug_info', 'unnecessary_files', 'localized_strings', 'localized_strings_minify', 'small_files', 'audio_compression', 'video_compression'].includes(key)) {
      const fileSavingsInsight = value as FileSavingsInsightResult;
      const hasFiles = fileSavingsInsight.files && Array.isArray(fileSavingsInsight.files) && fileSavingsInsight.files.length > 0;
      return hasValidSavings || hasFiles;
    }

    const regularInsight = value as InsightResult;
    const hasFiles = regularInsight.files && Array.isArray(regularInsight.files) && regularInsight.files.length > 0;

    // Include insights that either have savings or have files to show
    return hasValidSavings || hasFiles;
  }) as [string, InsightResult | DuplicateFilesInsightResult | StripBinaryInsightResult | LooseImagesInsightResult | ImageOptimizationInsightResult | MainBinaryExportMetadataResult | FileSavingsInsightResult][];

  if (insightEntries.length === 0) {
    return null;
  }

  // Calculate total potential savings
  const totalSavings = insightEntries.reduce((sum, [, insight]) => {
    return sum + (insight?.total_savings || 0);
  }, 0);

  return (
    <div style={{
      backgroundColor: '#f8f9fa',
      borderRadius: '8px',
      padding: '1.5rem',
      marginTop: '2rem',
      border: '1px solid #e9ecef'
    }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 style={{
          margin: '0 0 0.5rem 0',
          color: '#343a40',
          fontSize: '1.5rem',
          fontWeight: '600',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}>
          💡 Optimization Insights
        </h2>
        <p style={{
          margin: '0 0 1rem 0',
          color: '#6c757d',
          fontSize: '0.95rem'
        }}>
          Potential space savings identified in your app
        </p>

        {totalSavings > 0 && (
          <div style={{
            backgroundColor: '#d4edda',
            color: '#155724',
            padding: '0.75rem 1rem',
            borderRadius: '6px',
            border: '1px solid #c3e6cb',
            fontSize: '1rem',
            fontWeight: '600'
          }}>
            🎯 Total potential savings: {formatSize(totalSavings)}
          </div>
        )}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {insightEntries.map(([key, insight]) => (
          <div
            key={key}
            style={{
              backgroundColor: '#ffffff',
              border: '1px solid #dee2e6',
              borderRadius: '8px',
              padding: '1.25rem',
              boxShadow: '0 1px 3px rgba(0, 0, 0, 0.1)'
            }}
          >
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'flex-start',
              marginBottom: '1rem'
            }}>
              <div style={{ flex: 1 }}>
                <h3 style={{
                  margin: '0 0 0.5rem 0',
                  color: '#343a40',
                  fontSize: '1.25rem',
                  fontWeight: '600',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}>
                  <span>{getInsightIcon(key)}</span>
                  {getInsightTitle(key)}
                </h3>
                <p style={{
                  margin: '0',
                  color: '#6c757d',
                  fontSize: '0.9rem',
                  lineHeight: '1.4'
                }}>
                  {getInsightDescription(key)}
                </p>
              </div>

              <div style={{
                backgroundColor: insight.total_savings > 0 ? '#e3f2fd' : '#f5f5f5',
                color: insight.total_savings > 0 ? '#1976d2' : '#6c757d',
                padding: '0.5rem 1rem',
                borderRadius: '20px',
                fontSize: '0.9rem',
                fontWeight: '600',
                textAlign: 'center',
                minWidth: '120px'
              }}>
                {insight.total_savings > 0 ? formatSize(insight.total_savings) : 'No savings'}
              </div>
            </div>

            {key === 'duplicate_files' ? (
              // Handle duplicate files with groups
              (() => {
                const duplicateInsight = insight as DuplicateFilesInsightResult;
                const totalFiles = duplicateInsight.groups?.reduce((sum, group) => sum + group.files.length, 0) || 0;

                return duplicateInsight.groups && duplicateInsight.groups.length > 0 && (
                  <div>
                    <h4 style={{
                      margin: '0 0 0.75rem 0',
                      color: '#495057',
                      fontSize: '1rem',
                      fontWeight: '600'
                    }}>
                      Duplicate File Groups ({duplicateInsight.groups.length} groups, {totalFiles} files)
                    </h4>
                    <div style={{
                      backgroundColor: '#f8f9fa',
                      borderRadius: '6px',
                      padding: '0.75rem',
                      maxHeight: '400px',
                      overflowY: 'auto'
                    }}>
                      {duplicateInsight.groups.map((group, groupIndex) => (
                        <div
                          key={groupIndex}
                          style={{
                            marginBottom: groupIndex < duplicateInsight.groups!.length - 1 ? '1rem' : '0',
                            padding: '0.75rem',
                            backgroundColor: '#ffffff',
                            borderRadius: '4px',
                            border: '1px solid #e9ecef'
                          }}
                        >
                          <div style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            marginBottom: '0.5rem',
                            paddingBottom: '0.5rem',
                            borderBottom: '1px solid #f0f0f0'
                          }}>
                            <div style={{
                              color: '#343a40',
                              fontWeight: '600',
                              fontSize: '0.9rem'
                            }}>
                              📄 {group.name} ({group.files.length} files)
                            </div>
                            <div style={{
                              color: '#28a745',
                              fontSize: '0.85rem',
                              fontWeight: '600'
                            }}>
                              {formatSize(group.total_savings)} savings
                            </div>
                          </div>
                          {group.files.map((file, fileIndex) => (
                            <div
                              key={fileIndex}
                              style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                                padding: '0.3rem 0',
                                borderBottom: fileIndex < group.files.length - 1 ? '1px solid #f0f0f0' : 'none',
                                fontSize: '0.8rem'
                              }}
                            >
                              <div style={{
                                flex: 1,
                                color: '#6c757d',
                                fontFamily: 'monospace',
                                fontSize: '0.75rem',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                                marginRight: '1rem'
                              }}>
                                {file.file_path}
                              </div>
                              <div style={{
                                color: '#6c757d',
                                fontSize: '0.75rem',
                                fontWeight: '500',
                                flexShrink: 0
                              }}>
                                {formatSize(file.total_savings)}
                              </div>
                            </div>
                          ))}
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()
            ) : key === 'strip_binary' ? (
              // Handle strip binary with custom file format
              (() => {
                const stripInsight = insight as StripBinaryInsightResult;
                return stripInsight.files && stripInsight.files.length > 0 && (
                  <div>
                    <h4 style={{
                      margin: '0 0 0.75rem 0',
                      color: '#495057',
                      fontSize: '1rem',
                      fontWeight: '600'
                    }}>
                      Binary Files ({stripInsight.files.length})
                    </h4>
                    <div style={{
                      backgroundColor: '#f8f9fa',
                      borderRadius: '6px',
                      padding: '0.75rem',
                      marginBottom: '1rem'
                    }}>
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: '1fr 1fr',
                        gap: '0.75rem',
                        marginBottom: '0.75rem',
                        padding: '0.75rem',
                        backgroundColor: '#e3f2fd',
                        borderRadius: '4px'
                      }}>
                        <div style={{ textAlign: 'center' }}>
                          <div style={{ fontSize: '0.8rem', color: '#6c757d', marginBottom: '0.25rem' }}>
                            Debug Sections Savings
                          </div>
                          <div style={{ fontSize: '1rem', fontWeight: '600', color: '#1976d2' }}>
                            {formatSize(stripInsight.total_debug_sections_savings)}
                          </div>
                        </div>
                        <div style={{ textAlign: 'center' }}>
                          <div style={{ fontSize: '0.8rem', color: '#6c757d', marginBottom: '0.25rem' }}>
                            Symbol Table Savings
                          </div>
                          <div style={{ fontSize: '1rem', fontWeight: '600', color: '#1976d2' }}>
                            {formatSize(stripInsight.total_symbol_table_savings)}
                          </div>
                        </div>
                      </div>
                    </div>
                    <div style={{
                      backgroundColor: '#f8f9fa',
                      borderRadius: '6px',
                      padding: '0.75rem',
                      maxHeight: '200px',
                      overflowY: 'auto'
                    }}>
                      {stripInsight.files.map((file, index) => (
                        <div
                          key={index}
                          style={{
                            padding: '0.75rem',
                            marginBottom: index < stripInsight.files.length - 1 ? '0.5rem' : '0',
                            backgroundColor: '#ffffff',
                            borderRadius: '4px',
                            border: '1px solid #e9ecef'
                          }}
                        >
                          <div style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            marginBottom: '0.5rem'
                          }}>
                            <div style={{
                              flex: 1,
                              color: '#495057',
                              fontFamily: 'monospace',
                              fontSize: '0.8rem',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                              marginRight: '1rem'
                            }}>
                              {file.file_path}
                            </div>
                            <div style={{
                              color: '#28a745',
                              fontSize: '0.8rem',
                              fontWeight: '600',
                              flexShrink: 0
                            }}>
                              {formatSize(file.total_savings)} total
                            </div>
                          </div>
                          <div style={{
                            display: 'grid',
                            gridTemplateColumns: '1fr 1fr',
                            gap: '0.5rem',
                            fontSize: '0.75rem',
                            color: '#6c757d'
                          }}>
                            <div>
                              Debug sections: {formatSize(file.debug_sections_savings)}
                            </div>
                            <div>
                              Symbol table: {formatSize(file.symbol_table_savings)}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()
            ) : key === 'main_binary_exported_symbols' ? (
              // Handle main binary export metadata with FileSavingsResult files
              (() => {
                const exportInsight = insight as MainBinaryExportMetadataResult;
                return exportInsight.files && exportInsight.files.length > 0 && (
                  <div>
                    <h4 style={{
                      margin: '0 0 0.75rem 0',
                      color: '#495057',
                      fontSize: '1rem',
                      fontWeight: '600'
                    }}>
                      Main Binary Files ({exportInsight.files.length})
                    </h4>
                    {renderFileSavingsResults(exportInsight.files, 'export metadata')}
                  </div>
                );
              })()
            ) : key === 'loose_images' ? (
              // Handle loose images - the actual data structure is similar to duplicate_files
              (() => {
                const looseImagesInsight = insight as any; // Use any since the actual structure doesn't match the interface

                // The actual data has 'groups' not 'image_groups'
                const groups = looseImagesInsight.groups;
                const totalFiles = groups?.reduce((sum: number, group: any) => sum + (group.files?.length || 0), 0) || 0;

                return groups && groups.length > 0 && (
                  <div>
                    <h4 style={{
                      margin: '0 0 0.75rem 0',
                      color: '#495057',
                      fontSize: '1rem',
                      fontWeight: '600'
                    }}>
                      Loose Image Groups ({groups.length} groups, {totalFiles} files)
                    </h4>
                    <div style={{
                      backgroundColor: '#f8f9fa',
                      borderRadius: '6px',
                      padding: '0.75rem',
                      maxHeight: '400px',
                      overflowY: 'auto'
                    }}>
                      {groups.map((group: any, groupIndex: number) => (
                        <div
                          key={groupIndex}
                          style={{
                            marginBottom: groupIndex < groups.length - 1 ? '1rem' : '0',
                            padding: '0.75rem',
                            backgroundColor: '#ffffff',
                            borderRadius: '4px',
                            border: '1px solid #e9ecef'
                          }}
                        >
                          <div style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            marginBottom: '0.5rem',
                            paddingBottom: '0.5rem',
                            borderBottom: '1px solid #f0f0f0'
                          }}>
                            <div style={{
                              color: '#343a40',
                              fontWeight: '600',
                              fontSize: '0.9rem'
                            }}>
                              🖼️ {group.name} ({group.files?.length || 0} files)
                            </div>
                            <div style={{
                              color: '#28a745',
                              fontSize: '0.85rem',
                              fontWeight: '600'
                            }}>
                              {formatSize(group.total_savings)}
                            </div>
                          </div>
                          {group.files && group.files.length > 0 ? renderFileSavingsResults(group.files, 'savings') : (
                            <div style={{ color: '#6c757d', fontSize: '0.8rem', fontStyle: 'italic', padding: '0.5rem' }}>
                              No files in this group
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()
            ) : key === 'image_optimization' ? (
              // Handle image optimization with optimizable files
              (() => {
                const imageOptInsight = insight as ImageOptimizationInsightResult;
                return imageOptInsight.optimizable_files && imageOptInsight.optimizable_files.length > 0 && (
                  <div>
                    <h4 style={{
                      margin: '0 0 0.75rem 0',
                      color: '#495057',
                      fontSize: '1rem',
                      fontWeight: '600'
                    }}>
                      Optimizable Images ({imageOptInsight.optimizable_files.length})
                    </h4>
                    <div style={{
                      backgroundColor: '#f8f9fa',
                      borderRadius: '6px',
                      padding: '0.75rem',
                      maxHeight: '400px',
                      overflowY: 'auto'
                    }}>
                      {imageOptInsight.optimizable_files.map((file, index) => {
                        const potentialSavings = Math.max(file.minify_savings || 0, file.conversion_savings || 0);
                        const bestOptimizationType = (file.conversion_savings || 0) > (file.minify_savings || 0)
                          ? 'convert_to_heic'
                          : (file.minify_savings || 0) > 0
                            ? 'minify'
                            : 'none';

                        return (
                          <div
                            key={index}
                            style={{
                              padding: '0.75rem',
                              marginBottom: index < imageOptInsight.optimizable_files.length - 1 ? '0.5rem' : '0',
                              backgroundColor: '#ffffff',
                              borderRadius: '4px',
                              border: '1px solid #e9ecef'
                            }}
                          >
                            <div style={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              alignItems: 'center',
                              marginBottom: '0.5rem'
                            }}>
                              <div style={{
                                flex: 1,
                                color: '#495057',
                                fontFamily: 'monospace',
                                fontSize: '0.8rem',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                                marginRight: '1rem'
                              }}>
                                {file.file_path}
                              </div>
                              <div style={{
                                color: '#28a745',
                                fontSize: '0.8rem',
                                fontWeight: '600',
                                flexShrink: 0
                              }}>
                                {formatSize(potentialSavings)} savings
                              </div>
                            </div>
                            <div style={{
                              display: 'grid',
                              gridTemplateColumns: '1fr 1fr 1fr',
                              gap: '0.5rem',
                              fontSize: '0.75rem',
                              color: '#6c757d'
                            }}>
                              <div>
                                Current: {formatSize(file.current_size)}
                              </div>
                              <div>
                                Minify: {formatSize(file.minify_savings || 0)} savings
                              </div>
                              <div>
                                HEIC: {formatSize(file.conversion_savings || 0)} savings
                              </div>
                            </div>
                            <div style={{
                              marginTop: '0.5rem',
                              fontSize: '0.7rem',
                              color: '#007bff',
                              fontWeight: '500'
                            }}>
                              Best option: {bestOptimizationType === 'convert_to_heic' ? 'Convert to HEIC' :
                                           bestOptimizationType === 'minify' ? 'Minify current format' : 'No optimization needed'}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })()
            ) : ['large_images', 'large_videos', 'large_audio', 'hermes_debug_info', 'unnecessary_files', 'localized_strings', 'localized_strings_minify', 'localized_strings_comments', 'small_files', 'audio_compression', 'video_compression'].includes(key) ? (
              // Handle insights that now use FileSavingsResult format
              (() => {
                const fileSavingsInsight = insight as FileSavingsInsightResult;
                return fileSavingsInsight.files && fileSavingsInsight.files.length > 0 && (
                  <div>
                    <h4 style={{
                      margin: '0 0 0.75rem 0',
                      color: '#495057',
                      fontSize: '1rem',
                      fontWeight: '600'
                    }}>
                      Affected Files ({fileSavingsInsight.files.length})
                    </h4>
                    {renderFileSavingsResults(fileSavingsInsight.files)}
                  </div>
                );
              })()
            ) : (
              // Handle regular insights with files array (legacy format)
              (() => {
                const regularInsight = insight as InsightResult;
                return regularInsight.files && regularInsight.files.length > 0 && (
                  <div>
                    <h4 style={{
                      margin: '0 0 0.75rem 0',
                      color: '#495057',
                      fontSize: '1rem',
                      fontWeight: '600'
                    }}>
                      Affected Files ({regularInsight.files.length})
                    </h4>
                    <div style={{
                      backgroundColor: '#f8f9fa',
                      borderRadius: '6px',
                      padding: '0.75rem',
                      maxHeight: '200px',
                      overflowY: 'auto'
                    }}>
                      {regularInsight.files.map((file, index) => (
                        <div
                          key={index}
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            padding: '0.4rem 0',
                            borderBottom: index < regularInsight.files!.length - 1 ? '1px solid #e9ecef' : 'none',
                            fontSize: '0.85rem'
                          }}
                        >
                          <div style={{
                            flex: 1,
                            color: '#495057',
                            fontFamily: 'monospace',
                            fontSize: '0.8rem',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            marginRight: '1rem'
                          }}>
                            {file.path}
                          </div>
                          <div style={{
                            color: '#6c757d',
                            fontSize: '0.8rem',
                            fontWeight: '500',
                            flexShrink: 0
                          }}>
                            {formatSize(file.size)}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default InsightsDisplay;
