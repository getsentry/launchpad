import type { TreemapResults } from '../types/treemap';

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

export interface FileAnalysisReport {
  file_analysis: FileAnalysisData;
  treemap: TreemapResults;
  app_info: AppInfo;
  binary_analysis?: {
    executable_size: number;
    [key: string]: unknown;
  };
  generated_at: string;
  use_si_units: boolean;
}

export function parseFileAnalysisReport(data: unknown): FileAnalysisReport {
  if (typeof data !== 'object' || data === null) {
    throw new Error('Data must be an object');
  }

  return data as FileAnalysisReport;
}
