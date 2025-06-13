import type { TreemapElement, TreemapResults } from '../types/treemap';
import { TreemapType } from '../types/treemap';

// File analysis format interfaces
interface FileAnalysisFile {
  path: string;
  size: number;
  file_type: string;
  hash_md5: string;
}

interface FileAnalysisData {
  total_size: number;
  file_count: number;
  files_by_type: Record<string, FileAnalysisFile[]>;
  largest_files: FileAnalysisFile[];
}

interface AppInfo {
  name: string;
  version: string;
  build: string;
  executable: string;
  bundle_id: string;
}

interface FileAnalysisReport {
  file_analysis: FileAnalysisData;
  app_info: AppInfo;
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

export function detectDataFormat(data: unknown): 'treemap' | 'file_analysis' | 'unknown' {
  console.log('detectDataFormat called with data type:', typeof data);

  if (typeof data !== 'object' || data === null) {
    console.log('detectDataFormat: data is not an object or is null');
    return 'unknown';
  }

  const obj = data as Record<string, unknown>;
  console.log('detectDataFormat: object keys:', Object.keys(obj));

  // Check for TreemapResults format
  const hasRoot = 'root' in obj;
  const hasTotalInstallSize = 'total_install_size' in obj;
  const hasTotalDownloadSize = 'total_download_size' in obj;

  console.log('TreemapResults format check:', {
    hasRoot,
    hasTotalInstallSize,
    hasTotalDownloadSize
  });

  if (hasRoot && hasTotalInstallSize && hasTotalDownloadSize) {
    console.log('detectDataFormat: detected as treemap format');
    return 'treemap';
  }

  // Check for file analysis format
  const hasFileAnalysis = 'file_analysis' in obj;
  const hasAppInfo = 'app_info' in obj;

  console.log('File analysis format check:', {
    hasFileAnalysis,
    hasAppInfo
  });

  if (hasFileAnalysis && hasAppInfo) {
    console.log('detectDataFormat: detected as file analysis format');
    return 'file_analysis';
  }

  console.log('detectDataFormat: format unknown');
  return 'unknown';
}

export function convertFileAnalysisToTreemap(fileAnalysisData: FileAnalysisReport): TreemapResults {
  const { file_analysis, app_info, binary_analysis } = fileAnalysisData;

  // Create a map to store directory elements
  const directoryMap = new Map<string, TreemapElement>();
  const categoryBreakdown: Record<string, Record<string, number>> = {};

  // Helper function to get or create directory element
  function getOrCreateDirectory(path: string): TreemapElement {
    if (directoryMap.has(path)) {
      return directoryMap.get(path)!;
    }

    const parts = path.split('/');
    const name = parts[parts.length - 1] || path;
    const element: TreemapElement = {
      name,
      install_size: 0,
      download_size: 0,
      element_type: TreemapType.FILES,
      path,
      is_directory: true,
      children: [],
      details: {},
    };
    directoryMap.set(path, element);
    return element;
  }

  // Process all files and build the tree
  for (const [fileType, files] of Object.entries(file_analysis.files_by_type)) {
    if (files.length === 0) continue;

    const treemapType = FILE_TYPE_TO_TREEMAP_TYPE[fileType] || TreemapType.OTHER;

    for (const file of files) {
      const filePath = file.path;
      const parts = filePath.split('/');
      const fileName = parts[parts.length - 1];

      // Create file element
      const fileElement: TreemapElement = {
        name: fileName,
        install_size: file.size,
        download_size: Math.round(file.size * 0.8), // Estimate 80% compression
        element_type: treemapType,
        path: filePath,
        is_directory: false,
        children: [],
        details: {
          file_type: file.file_type,
          hash_md5: file.hash_md5,
        },
      };

      // Add to category breakdown
      if (!categoryBreakdown[treemapType]) {
        categoryBreakdown[treemapType] = {};
      }
      if (!categoryBreakdown[treemapType][fileType]) {
        categoryBreakdown[treemapType][fileType] = 0;
      }
      categoryBreakdown[treemapType][fileType] += file.size;

      // Build directory structure
      let currentPath = '';
      for (let i = 0; i < parts.length - 1; i++) {
        currentPath = currentPath ? `${currentPath}/${parts[i]}` : parts[i];
        const dirElement = getOrCreateDirectory(currentPath);

        // If this is the parent directory of the file, add the file as a child
        if (i === parts.length - 2) {
          dirElement.children.push(fileElement);
          dirElement.install_size += file.size;
          dirElement.download_size += Math.round(file.size * 0.8);
        }
      }
    }
  }

  // Get the root directory
  const rootElement: TreemapElement = {
    name: app_info.name || 'App',
    install_size: file_analysis.total_size,
    download_size: Math.round(file_analysis.total_size * 0.8),
    element_type: undefined,
    path: undefined,
    is_directory: true,
    children: Array.from(directoryMap.values()).filter(dir => !dir.path?.includes('/')),
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
    platform: 'ios', // Assume iOS for file analysis format
  };
}

export function validateTreemapData(data: unknown): { isValid: boolean; error?: string } {
  console.log('validateTreemapData called');

  if (typeof data !== 'object' || data === null) {
    return { isValid: false, error: 'Data must be an object' };
  }

  const obj = data as Record<string, unknown>;
  console.log('Validating TreemapResults with keys:', Object.keys(obj));

  if (!('root' in obj)) {
    return { isValid: false, error: 'Missing "root" property' };
  }

  if (typeof obj.root !== 'object' || obj.root === null) {
    return { isValid: false, error: '"root" property must be an object' };
  }

  const root = obj.root as Record<string, unknown>;
  console.log('Root object keys:', Object.keys(root));

  if (typeof obj.total_install_size !== 'number') {
    return {
      isValid: false,
      error: `Missing or invalid "total_install_size" property. Got: ${typeof obj.total_install_size} (${obj.total_install_size})`
    };
  }

  if (typeof obj.total_download_size !== 'number') {
    return {
      isValid: false,
      error: `Missing or invalid "total_download_size" property. Got: ${typeof obj.total_download_size} (${obj.total_download_size})`
    };
  }

  if (typeof obj.file_count !== 'number') {
    return {
      isValid: false,
      error: `Missing or invalid "file_count" property. Got: ${typeof obj.file_count} (${obj.file_count})`
    };
  }

  // Validate root element structure
  if (typeof root.name !== 'string') {
    return {
      isValid: false,
      error: `Root element missing or invalid "name" property. Got: ${typeof root.name}`
    };
  }

  if (typeof root.install_size !== 'number') {
    return {
      isValid: false,
      error: `Root element missing or invalid "install_size" property. Got: ${typeof root.install_size}`
    };
  }

  if (typeof root.download_size !== 'number') {
    return {
      isValid: false,
      error: `Root element missing or invalid "download_size" property. Got: ${typeof root.download_size}`
    };
  }

  if (typeof root.is_directory !== 'boolean') {
    return {
      isValid: false,
      error: `Root element missing or invalid "is_directory" property. Got: ${typeof root.is_directory}`
    };
  }

  if (!Array.isArray(root.children)) {
    return {
      isValid: false,
      error: `Root element missing or invalid "children" property. Got: ${typeof root.children}`
    };
  }

  console.log('TreemapResults validation passed');
  return { isValid: true };
}
