import type { TreemapResults } from '../types/treemap';

// File analysis format interfaces
interface FileAnalysisFile {
  path: string;
  size: number;
  file_type: string;
  hash: string;
}

interface FileAnalysisData {
  total_size: number;
  file_count: number;
  files_by_type: Record<string, FileAnalysisFile[]>;
  largest_files: FileAnalysisFile[];
}

interface AppInfo {
  name: string;
  app_id: string;
  version: string;
  build: string;
  // iOS-specific
  executable?: string;
  minimum_os_version?: string;
  supported_platforms?: string[];
  sdk_version?: string;
  is_simulator?: boolean;
  codesigning_type?: string;
  profile_name?: string;
  is_code_signature_valid?: boolean;
  code_signature_errors?: string[];
}

export interface InsightResult {
  total_savings: number;
  files?: {
    path: string;
    size: number;
    file_type: string;
  }[];
}

export interface StripBinaryFileInfo {
  file_path: string;
  debug_sections_savings: number;
  symbol_table_savings: number;
  total_savings: number;
}

export interface StripBinaryInsightResult {
  total_savings: number;
  files: StripBinaryFileInfo[];
  total_debug_sections_savings: number;
  total_symbol_table_savings: number;
}

export interface FileSavingsResultGroup {
  name: string;
  files: {
    file_path: string;
    total_savings: number;
  }[];
  total_savings: number;
}

export interface DuplicateFilesInsightResult {
  total_savings: number;
  groups: FileSavingsResultGroup[];
}

export interface LooseImageGroup {
  canonical_name: string;
  images: {
    file_path: string;
    total_savings: number;
  }[];
  total_savings: number;
}

export interface LooseImagesInsightResult {
  total_savings: number;
  image_groups: LooseImageGroup[];
  total_file_count: number;
}

export interface FileAnalysisReport {
  file_analysis: FileAnalysisData;
  treemap: TreemapResults;
  app_info: AppInfo;
  binary_analysis?: {
    executable_size: number;
    [key: string]: unknown;
  };
  insights?: {
    duplicate_files?: DuplicateFilesInsightResult | null;
    large_images?: InsightResult | null;
    large_videos?: InsightResult | null;
    large_audio?: InsightResult | null;
    hermes_debug_info?: InsightResult | null;
    webp_optimization?: InsightResult | null;
    strip_binary?: StripBinaryInsightResult | null;
    localized_strings?: InsightResult | null;
    loose_images?: LooseImagesInsightResult | null;
    [key: string]: InsightResult | DuplicateFilesInsightResult | StripBinaryInsightResult | LooseImagesInsightResult | null | undefined;
  };
  generated_at: string;
  use_si_units: boolean;
  install_size: number;
  download_size: number;
}

export function parseFileAnalysisReport(data: unknown): FileAnalysisReport {
  if (typeof data !== 'object' || data === null) {
    throw new Error('Data must be an object');
  }

  return data as FileAnalysisReport;
}
