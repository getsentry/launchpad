import { TreemapType } from '../types/treemap';
import type { TreemapResults, TreemapElement } from '../types/treemap';

// Legacy format interfaces
interface LegacyFile {
  path: string;
  size: number;
  file_type: string;
  hash_md5: string;
}

interface LegacyFileAnalysis {
  total_size: number;
  file_count: number;
  files_by_type: Record<string, LegacyFile[]>;
  largest_files: LegacyFile[];
}

interface LegacyAppInfo {
  name: string;
  version: string;
  build: string;
  executable: string;
  bundle_id: string;
}

interface LegacyAnalysisReport {
  file_analysis: LegacyFileAnalysis;
  app_info: LegacyAppInfo;
  binary_analysis?: {
    executable_size: number;
    [key: string]: unknown;
  };
  generated_at: string;
}

// File type to TreemapType mapping
const FILE_TYPE_TO_TREEMAP_TYPE: Record<string, TreemapType> = {
  'unknown': TreemapType.EXECUTABLES,
  'png': TreemapType.ASSETS,
  'jpg': TreemapType.ASSETS,
  'jpeg': TreemapType.ASSETS,
  'gif': TreemapType.ASSETS,
  'svg': TreemapType.ASSETS,
  'car': TreemapType.COMPILED_RESOURCES,
  'plist': TreemapType.PLISTS,
  'mobileprovision': TreemapType.SIGNATURES,
  'ttf': TreemapType.RESOURCES,
  'otf': TreemapType.RESOURCES,
  'xcprivacy': TreemapType.MANIFESTS,
  'bundle': TreemapType.RESOURCES,
  'framework': TreemapType.FRAMEWORKS,
  'dylib': TreemapType.FRAMEWORKS,
  'a': TreemapType.FRAMEWORKS,
};

export function detectDataFormat(data: unknown): 'treemap' | 'legacy' | 'unknown' {
  if (typeof data !== 'object' || data === null) {
    return 'unknown';
  }

  const obj = data as Record<string, unknown>;

  // Check for TreemapResults format
  if ('root' in obj && 'total_install_size' in obj && 'total_download_size' in obj) {
    return 'treemap';
  }

  // Check for legacy format
  if ('file_analysis' in obj && 'app_info' in obj) {
    return 'legacy';
  }

  return 'unknown';
}

export function convertLegacyToTreemap(legacyData: LegacyAnalysisReport): TreemapResults {
  const { file_analysis, app_info, binary_analysis } = legacyData;

  // Create root element with file type categories
  const typeCategories: TreemapElement[] = [];
  const categoryBreakdown: Record<string, Record<string, number>> = {};

  for (const [fileType, files] of Object.entries(file_analysis.files_by_type)) {
    if (files.length === 0) continue;

    const treemapType = FILE_TYPE_TO_TREEMAP_TYPE[fileType] || TreemapType.OTHER;
    const totalSize = files.reduce((sum, file) => sum + file.size, 0);

    // Create individual file elements
    const fileElements: TreemapElement[] = files.map(file => ({
      name: getFileName(file.path),
      install_size: file.size,
      download_size: Math.round(file.size * 0.8), // Estimate 80% compression
      element_type: treemapType,
      path: file.path,
      is_directory: false,
      children: [],
      details: {
        file_type: file.file_type,
        hash_md5: file.hash_md5,
      },
    }));

    // Create category element
    const categoryElement: TreemapElement = {
      name: formatFileType(fileType),
      install_size: totalSize,
      download_size: Math.round(totalSize * 0.8),
      element_type: treemapType,
      path: undefined,
      is_directory: true,
      children: fileElements,
      details: {
        file_count: files.length,
        file_type_category: fileType,
      },
    };

    typeCategories.push(categoryElement);

    // Add to category breakdown
    if (!categoryBreakdown[treemapType]) {
      categoryBreakdown[treemapType] = {};
    }
    categoryBreakdown[treemapType][fileType] = totalSize;
  }

  // Sort categories by size (largest first)
  typeCategories.sort((a, b) => b.install_size - a.install_size);

  // Create root element
  const rootElement: TreemapElement = {
    name: app_info.name || 'App',
    install_size: file_analysis.total_size,
    download_size: Math.round(file_analysis.total_size * 0.8),
    element_type: undefined,
    path: undefined,
    is_directory: true,
    children: typeCategories,
    details: {
      app_version: app_info.version,
      app_build: app_info.build,
      bundle_id: app_info.bundle_id,
      executable_size: binary_analysis?.executable_size || 0,
    },
  };

  return {
    root: rootElement,
    total_install_size: file_analysis.total_size,
    total_download_size: Math.round(file_analysis.total_size * 0.8),
    file_count: file_analysis.file_count,
    category_breakdown: categoryBreakdown,
    platform: 'ios', // Assume iOS for legacy format
  };
}

function getFileName(path: string): string {
  const parts = path.split('/');
  return parts[parts.length - 1] || path;
}

function formatFileType(fileType: string): string {
  switch (fileType) {
    case 'unknown':
      return 'Executables & Binaries';
    case 'png':
    case 'jpg':
    case 'jpeg':
    case 'gif':
    case 'svg':
      return 'Images';
    case 'car':
      return 'Asset Catalogs';
    case 'plist':
      return 'Property Lists';
    case 'mobileprovision':
      return 'Provisioning Profiles';
    case 'ttf':
    case 'otf':
      return 'Fonts';
    case 'xcprivacy':
      return 'Privacy Manifests';
    case 'bundle':
      return 'Resource Bundles';
    default:
      return fileType.toUpperCase();
  }
}

export function validateTreemapData(data: unknown): { isValid: boolean; error?: string } {
  if (typeof data !== 'object' || data === null) {
    return { isValid: false, error: 'Data must be an object' };
  }

  const obj = data as Record<string, unknown>;

  if (!('root' in obj)) {
    return { isValid: false, error: 'Missing "root" property' };
  }

  if (typeof obj.total_install_size !== 'number') {
    return { isValid: false, error: 'Missing or invalid "total_install_size" property' };
  }

  if (typeof obj.total_download_size !== 'number') {
    return { isValid: false, error: 'Missing or invalid "total_download_size" property' };
  }

  if (typeof obj.file_count !== 'number') {
    return { isValid: false, error: 'Missing or invalid "file_count" property' };
  }

  return { isValid: true };
}
