export interface AndroidManifest {
  packageName?: string;
  // Name of the split, if this is a feature split.
  split?: string;
  // Only nullable for test APKs
  versionName?: string;
  versionCode?: string;
  minSdkVersion: number;
  isFeatureSplit: boolean;
  permissions: string[];
  application?: AndroidManifestApplication;
  module?: AndroidManifestModule;
}

export interface AndroidManifestApplication {
  /**
   * The icon reference (mipmap, drawable or @ref) in the app for the launcher
   * icon.
   */
  iconPath?: string;
  /**
   * The label reference in strings used for the name of the app.
   */
  label?: string;
  /**
   * Whether the app allows cleartext traffic.
   */
  usesCleartextTraffic: boolean;
  /**
   * Whether emerge.reaper.instrumented is true.
   */
  reaperInstrumented: boolean;
}

export interface AndroidManifestModule {
  // If the module is an instant app.
  // https://developer.android.com/guide/playcore/feature-delivery/instant
  instant: boolean;
  title: string;
  // Delivery type, either on-demand or install-time
  // https://developer.android.com/guide/playcore/feature-delivery/on-demand
  // https://developer.android.com/guide/playcore/feature-delivery/install-time
  delivery: DeliveryType;
}

export enum DeliveryType {
  INSTALL_TIME = 'install-time',
  ON_DEMAND = 'on-demand',
  FAST_FOLLOW = 'fast-follow',
}

// Find constant values at https://stuff.mit.edu/afs/sipb/project/android/docs/reference/android/R.attr.html
export const LABEL_RESOURCE_ID = 0x01010001;
export const ICON_RESOURCE_ID = 0x01010002;
export const VERSION_NAME_RESOURCE_ID = 0x0101021c;
export const VERSION_CODE_RESOURCE_ID = 0x0101021b;
export const MIN_SDK_VERSION_RESOURCE_ID = 0x0101020c;
