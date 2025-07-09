/**
 * TypeScript types matching the Python treemap models
 */

export enum TreemapType {
  // Generic file categories (cross-platform)
  FILES = "files",
  EXECUTABLES = "executables",
  RESOURCES = "resources",
  ASSETS = "assets",
  MANIFESTS = "manifests",
  SIGNATURES = "signatures",
  FONTS = "fonts",

  // iOS-specific categories
  FRAMEWORKS = "frameworks",
  EXTENSIONS = "extensions",
  PLISTS = "plists",

  // Android-specific categories
  DEX = "dex",
  NATIVE_LIBRARIES = "native_libraries",
  COMPILED_RESOURCES = "compiled_resources",

  // Binary analysis categories (cross-platform)
  MODULES = "modules",
  CLASSES = "classes",
  METHODS = "methods",
  STRINGS = "strings",
  SYMBOLS = "symbols",

  // iOS binary categories
  DYLD = "dyld",
  MACHO = "macho",
  FUNCTION_STARTS = "function_starts",
  CODE_SIGNATURE = "code_signature",
  EXTERNAL_METHODS = "external_methods",

  // Generic categories
  OTHER = "other",
  UNMAPPED = "unmapped",
}

export interface TreemapElement {
  /** Display name of the element */
  name: string;
  /** Install size in bytes */
  install_size: number;
  /** Download size in bytes (compressed) */
  download_size: number;
  /** Type of element for visualization */
  element_type?: TreemapType;
  /** File or directory path */
  path?: string;
  /** Whether this element represents a directory */
  is_directory: boolean;
  /** Child elements */
  children: TreemapElement[];
  /** Platform and context-specific metadata */
  details: Record<string, unknown>;
}

export interface TreemapResults {
  /** Root element of the treemap */
  root: TreemapElement;
  /** Total install size */
  total_install_size: number;
  /** Total download size */
  total_download_size: number;
  /** Total number of files analyzed */
  file_count: number;
  /** Size breakdown by category */
  category_breakdown: Record<string, Record<string, number>>;
  /** Platform (ios, android, etc.) */
  platform: "ios" | "android";
}

export interface EChartsTreemapData {
  name: string;
  value: number;
  children?: EChartsTreemapData[];
  itemStyle?: {
    color?: string;
    borderColor?: string;
    borderWidth?: number;
    gapWidth?: number;
  };
  label?: {
    show?: boolean;
    position?: string;
    fontSize?: number;
    fontWeight?: string;
    color?: string;
    fontFamily?: string;
    padding?: number;
    textShadowBlur?: number;
    textShadowColor?: string;
    textShadowOffsetY?: number;
  };
  upperLabel?: {
    show?: boolean;
    backgroundColor?: string;
    color?: string;
    height?: number;
    fontSize?: number;
    fontWeight?: string;
    borderRadius?: number[];
    fontFamily?: string;
    padding?: number;
    textShadowBlur?: number;
    textShadowColor?: string;
    textShadowOffsetY?: number;
  };
}
