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
  BINARY = "binary",

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
  size: number;
  /** Type of element for visualization */
  type?: TreemapType;
  /** File or directory path */
  path?: string;
  /** Whether this element represents a directory */
  is_dir: boolean;
  /** Child elements */
  children: TreemapElement[];
}

export interface TreemapResults {
  /** Root element of the treemap */
  root: TreemapElement;
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
  path?: string;
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
