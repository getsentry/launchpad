/* eslint-disable */
import { Reader, Writer, configure, util } from 'protobufjs/minimal';
// @ts-ignore
import * as Long from 'long';

export const protobufPackage = 'aapt.pb';

// Taken from https://android.googlesource.com/platform/frameworks/base/+/master/tools/aapt2/Configuration.proto
// and added TS representation for parsing in Typescript.

/**
 * A description of the requirements a device must have in order for a
 * resource to be matched and selected.
 */
export interface Configuration {
  /**
   * Axis/dimensions that are understood by the runtime.
   *
   * Mobile country code.
   */
  mcc: number;
  /** Mobile network code. */
  mnc: number;
  /** BCP-47 locale tag. */
  locale: string;
  /** Left-to-right, right-to-left... */
  layoutDirection: Configuration_LayoutDirection;
  /** Screen width in pixels. Prefer screen_width_dp. */
  screenWidth: number;
  /** Screen height in pixels. Prefer screen_height_dp. */
  screenHeight: number;
  /** Screen width in density independent pixels (dp). */
  screenWidthDp: number;
  /** Screen height in density independent pixels (dp). */
  screenHeightDp: number;
  /** The smallest screen dimension, regardless of orientation, in dp. */
  smallestScreenWidthDp: number;
  /** Whether the device screen is classified as small, normal, large, xlarge. */
  screenLayoutSize: Configuration_ScreenLayoutSize;
  /** Whether the device screen is long. */
  screenLayoutLong: Configuration_ScreenLayoutLong;
  /** Whether the screen is round (Android Wear). */
  screenRound: Configuration_ScreenRound;
  /** Whether the screen supports wide color gamut. */
  wideColorGamut: Configuration_WideColorGamut;
  /** Whether the screen has high dynamic range. */
  hdr: Configuration_Hdr;
  /** Which orientation the device is in (portrait, landscape). */
  orientation: Configuration_Orientation;
  /** Which type of UI mode the device is in (television, car, etc.). */
  uiModeType: Configuration_UiModeType;
  /** Whether the device is in night mode. */
  uiModeNight: Configuration_UiModeNight;
  /** The device's screen density in dots-per-inch (dpi). */
  density: number;
  /** Whether a touchscreen exists, supports a stylus, or finger. */
  touchscreen: Configuration_Touchscreen;
  /**
   * Whether the keyboard hardware keys are currently hidden, exposed, or
   * if the keyboard is a software keyboard.
   */
  keysHidden: Configuration_KeysHidden;
  /** The type of keyboard present (none, QWERTY, 12-key). */
  keyboard: Configuration_Keyboard;
  /** Whether the navigation is exposed or hidden. */
  navHidden: Configuration_NavHidden;
  /**
   * The type of navigation present on the device
   * (trackball, wheel, dpad, etc.).
   */
  navigation: Configuration_Navigation;
  /** The minimum SDK version of the device. */
  sdkVersion: number;
  /** Build-time only dimensions. */
  product: string;
}

export enum Configuration_LayoutDirection {
  LAYOUT_DIRECTION_UNSET = 0,
  LAYOUT_DIRECTION_LTR = 1,
  LAYOUT_DIRECTION_RTL = 2,
  UNRECOGNIZED = -1,
}

export function configuration_LayoutDirectionFromJSON(object: any): Configuration_LayoutDirection {
  switch (object) {
    case 0:
    case 'LAYOUT_DIRECTION_UNSET':
      return Configuration_LayoutDirection.LAYOUT_DIRECTION_UNSET;
    case 1:
    case 'LAYOUT_DIRECTION_LTR':
      return Configuration_LayoutDirection.LAYOUT_DIRECTION_LTR;
    case 2:
    case 'LAYOUT_DIRECTION_RTL':
      return Configuration_LayoutDirection.LAYOUT_DIRECTION_RTL;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Configuration_LayoutDirection.UNRECOGNIZED;
  }
}

export function configuration_LayoutDirectionToJSON(object: Configuration_LayoutDirection): string {
  switch (object) {
    case Configuration_LayoutDirection.LAYOUT_DIRECTION_UNSET:
      return 'LAYOUT_DIRECTION_UNSET';
    case Configuration_LayoutDirection.LAYOUT_DIRECTION_LTR:
      return 'LAYOUT_DIRECTION_LTR';
    case Configuration_LayoutDirection.LAYOUT_DIRECTION_RTL:
      return 'LAYOUT_DIRECTION_RTL';
    default:
      return 'UNKNOWN';
  }
}

export enum Configuration_ScreenLayoutSize {
  SCREEN_LAYOUT_SIZE_UNSET = 0,
  SCREEN_LAYOUT_SIZE_SMALL = 1,
  SCREEN_LAYOUT_SIZE_NORMAL = 2,
  SCREEN_LAYOUT_SIZE_LARGE = 3,
  SCREEN_LAYOUT_SIZE_XLARGE = 4,
  UNRECOGNIZED = -1,
}

export function configuration_ScreenLayoutSizeFromJSON(object: any): Configuration_ScreenLayoutSize {
  switch (object) {
    case 0:
    case 'SCREEN_LAYOUT_SIZE_UNSET':
      return Configuration_ScreenLayoutSize.SCREEN_LAYOUT_SIZE_UNSET;
    case 1:
    case 'SCREEN_LAYOUT_SIZE_SMALL':
      return Configuration_ScreenLayoutSize.SCREEN_LAYOUT_SIZE_SMALL;
    case 2:
    case 'SCREEN_LAYOUT_SIZE_NORMAL':
      return Configuration_ScreenLayoutSize.SCREEN_LAYOUT_SIZE_NORMAL;
    case 3:
    case 'SCREEN_LAYOUT_SIZE_LARGE':
      return Configuration_ScreenLayoutSize.SCREEN_LAYOUT_SIZE_LARGE;
    case 4:
    case 'SCREEN_LAYOUT_SIZE_XLARGE':
      return Configuration_ScreenLayoutSize.SCREEN_LAYOUT_SIZE_XLARGE;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Configuration_ScreenLayoutSize.UNRECOGNIZED;
  }
}

export function configuration_ScreenLayoutSizeToJSON(object: Configuration_ScreenLayoutSize): string {
  switch (object) {
    case Configuration_ScreenLayoutSize.SCREEN_LAYOUT_SIZE_UNSET:
      return 'SCREEN_LAYOUT_SIZE_UNSET';
    case Configuration_ScreenLayoutSize.SCREEN_LAYOUT_SIZE_SMALL:
      return 'SCREEN_LAYOUT_SIZE_SMALL';
    case Configuration_ScreenLayoutSize.SCREEN_LAYOUT_SIZE_NORMAL:
      return 'SCREEN_LAYOUT_SIZE_NORMAL';
    case Configuration_ScreenLayoutSize.SCREEN_LAYOUT_SIZE_LARGE:
      return 'SCREEN_LAYOUT_SIZE_LARGE';
    case Configuration_ScreenLayoutSize.SCREEN_LAYOUT_SIZE_XLARGE:
      return 'SCREEN_LAYOUT_SIZE_XLARGE';
    default:
      return 'UNKNOWN';
  }
}

export enum Configuration_ScreenLayoutLong {
  SCREEN_LAYOUT_LONG_UNSET = 0,
  SCREEN_LAYOUT_LONG_LONG = 1,
  SCREEN_LAYOUT_LONG_NOTLONG = 2,
  UNRECOGNIZED = -1,
}

export function configuration_ScreenLayoutLongFromJSON(object: any): Configuration_ScreenLayoutLong {
  switch (object) {
    case 0:
    case 'SCREEN_LAYOUT_LONG_UNSET':
      return Configuration_ScreenLayoutLong.SCREEN_LAYOUT_LONG_UNSET;
    case 1:
    case 'SCREEN_LAYOUT_LONG_LONG':
      return Configuration_ScreenLayoutLong.SCREEN_LAYOUT_LONG_LONG;
    case 2:
    case 'SCREEN_LAYOUT_LONG_NOTLONG':
      return Configuration_ScreenLayoutLong.SCREEN_LAYOUT_LONG_NOTLONG;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Configuration_ScreenLayoutLong.UNRECOGNIZED;
  }
}

export function configuration_ScreenLayoutLongToJSON(object: Configuration_ScreenLayoutLong): string {
  switch (object) {
    case Configuration_ScreenLayoutLong.SCREEN_LAYOUT_LONG_UNSET:
      return 'SCREEN_LAYOUT_LONG_UNSET';
    case Configuration_ScreenLayoutLong.SCREEN_LAYOUT_LONG_LONG:
      return 'SCREEN_LAYOUT_LONG_LONG';
    case Configuration_ScreenLayoutLong.SCREEN_LAYOUT_LONG_NOTLONG:
      return 'SCREEN_LAYOUT_LONG_NOTLONG';
    default:
      return 'UNKNOWN';
  }
}

export enum Configuration_ScreenRound {
  SCREEN_ROUND_UNSET = 0,
  SCREEN_ROUND_ROUND = 1,
  SCREEN_ROUND_NOTROUND = 2,
  UNRECOGNIZED = -1,
}

export function configuration_ScreenRoundFromJSON(object: any): Configuration_ScreenRound {
  switch (object) {
    case 0:
    case 'SCREEN_ROUND_UNSET':
      return Configuration_ScreenRound.SCREEN_ROUND_UNSET;
    case 1:
    case 'SCREEN_ROUND_ROUND':
      return Configuration_ScreenRound.SCREEN_ROUND_ROUND;
    case 2:
    case 'SCREEN_ROUND_NOTROUND':
      return Configuration_ScreenRound.SCREEN_ROUND_NOTROUND;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Configuration_ScreenRound.UNRECOGNIZED;
  }
}

export function configuration_ScreenRoundToJSON(object: Configuration_ScreenRound): string {
  switch (object) {
    case Configuration_ScreenRound.SCREEN_ROUND_UNSET:
      return 'SCREEN_ROUND_UNSET';
    case Configuration_ScreenRound.SCREEN_ROUND_ROUND:
      return 'SCREEN_ROUND_ROUND';
    case Configuration_ScreenRound.SCREEN_ROUND_NOTROUND:
      return 'SCREEN_ROUND_NOTROUND';
    default:
      return 'UNKNOWN';
  }
}

export enum Configuration_WideColorGamut {
  WIDE_COLOR_GAMUT_UNSET = 0,
  WIDE_COLOR_GAMUT_WIDECG = 1,
  WIDE_COLOR_GAMUT_NOWIDECG = 2,
  UNRECOGNIZED = -1,
}

export function configuration_WideColorGamutFromJSON(object: any): Configuration_WideColorGamut {
  switch (object) {
    case 0:
    case 'WIDE_COLOR_GAMUT_UNSET':
      return Configuration_WideColorGamut.WIDE_COLOR_GAMUT_UNSET;
    case 1:
    case 'WIDE_COLOR_GAMUT_WIDECG':
      return Configuration_WideColorGamut.WIDE_COLOR_GAMUT_WIDECG;
    case 2:
    case 'WIDE_COLOR_GAMUT_NOWIDECG':
      return Configuration_WideColorGamut.WIDE_COLOR_GAMUT_NOWIDECG;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Configuration_WideColorGamut.UNRECOGNIZED;
  }
}

export function configuration_WideColorGamutToJSON(object: Configuration_WideColorGamut): string {
  switch (object) {
    case Configuration_WideColorGamut.WIDE_COLOR_GAMUT_UNSET:
      return 'WIDE_COLOR_GAMUT_UNSET';
    case Configuration_WideColorGamut.WIDE_COLOR_GAMUT_WIDECG:
      return 'WIDE_COLOR_GAMUT_WIDECG';
    case Configuration_WideColorGamut.WIDE_COLOR_GAMUT_NOWIDECG:
      return 'WIDE_COLOR_GAMUT_NOWIDECG';
    default:
      return 'UNKNOWN';
  }
}

export enum Configuration_Hdr {
  HDR_UNSET = 0,
  HDR_HIGHDR = 1,
  HDR_LOWDR = 2,
  UNRECOGNIZED = -1,
}

export function configuration_HdrFromJSON(object: any): Configuration_Hdr {
  switch (object) {
    case 0:
    case 'HDR_UNSET':
      return Configuration_Hdr.HDR_UNSET;
    case 1:
    case 'HDR_HIGHDR':
      return Configuration_Hdr.HDR_HIGHDR;
    case 2:
    case 'HDR_LOWDR':
      return Configuration_Hdr.HDR_LOWDR;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Configuration_Hdr.UNRECOGNIZED;
  }
}

export function configuration_HdrToJSON(object: Configuration_Hdr): string {
  switch (object) {
    case Configuration_Hdr.HDR_UNSET:
      return 'HDR_UNSET';
    case Configuration_Hdr.HDR_HIGHDR:
      return 'HDR_HIGHDR';
    case Configuration_Hdr.HDR_LOWDR:
      return 'HDR_LOWDR';
    default:
      return 'UNKNOWN';
  }
}

export enum Configuration_Orientation {
  ORIENTATION_UNSET = 0,
  ORIENTATION_PORT = 1,
  ORIENTATION_LAND = 2,
  ORIENTATION_SQUARE = 3,
  UNRECOGNIZED = -1,
}

export function configuration_OrientationFromJSON(object: any): Configuration_Orientation {
  switch (object) {
    case 0:
    case 'ORIENTATION_UNSET':
      return Configuration_Orientation.ORIENTATION_UNSET;
    case 1:
    case 'ORIENTATION_PORT':
      return Configuration_Orientation.ORIENTATION_PORT;
    case 2:
    case 'ORIENTATION_LAND':
      return Configuration_Orientation.ORIENTATION_LAND;
    case 3:
    case 'ORIENTATION_SQUARE':
      return Configuration_Orientation.ORIENTATION_SQUARE;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Configuration_Orientation.UNRECOGNIZED;
  }
}

export function configuration_OrientationToJSON(object: Configuration_Orientation): string {
  switch (object) {
    case Configuration_Orientation.ORIENTATION_UNSET:
      return 'ORIENTATION_UNSET';
    case Configuration_Orientation.ORIENTATION_PORT:
      return 'ORIENTATION_PORT';
    case Configuration_Orientation.ORIENTATION_LAND:
      return 'ORIENTATION_LAND';
    case Configuration_Orientation.ORIENTATION_SQUARE:
      return 'ORIENTATION_SQUARE';
    default:
      return 'UNKNOWN';
  }
}

export enum Configuration_UiModeType {
  UI_MODE_TYPE_UNSET = 0,
  UI_MODE_TYPE_NORMAL = 1,
  UI_MODE_TYPE_DESK = 2,
  UI_MODE_TYPE_CAR = 3,
  UI_MODE_TYPE_TELEVISION = 4,
  UI_MODE_TYPE_APPLIANCE = 5,
  UI_MODE_TYPE_WATCH = 6,
  UI_MODE_TYPE_VRHEADSET = 7,
  UNRECOGNIZED = -1,
}

export function configuration_UiModeTypeFromJSON(object: any): Configuration_UiModeType {
  switch (object) {
    case 0:
    case 'UI_MODE_TYPE_UNSET':
      return Configuration_UiModeType.UI_MODE_TYPE_UNSET;
    case 1:
    case 'UI_MODE_TYPE_NORMAL':
      return Configuration_UiModeType.UI_MODE_TYPE_NORMAL;
    case 2:
    case 'UI_MODE_TYPE_DESK':
      return Configuration_UiModeType.UI_MODE_TYPE_DESK;
    case 3:
    case 'UI_MODE_TYPE_CAR':
      return Configuration_UiModeType.UI_MODE_TYPE_CAR;
    case 4:
    case 'UI_MODE_TYPE_TELEVISION':
      return Configuration_UiModeType.UI_MODE_TYPE_TELEVISION;
    case 5:
    case 'UI_MODE_TYPE_APPLIANCE':
      return Configuration_UiModeType.UI_MODE_TYPE_APPLIANCE;
    case 6:
    case 'UI_MODE_TYPE_WATCH':
      return Configuration_UiModeType.UI_MODE_TYPE_WATCH;
    case 7:
    case 'UI_MODE_TYPE_VRHEADSET':
      return Configuration_UiModeType.UI_MODE_TYPE_VRHEADSET;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Configuration_UiModeType.UNRECOGNIZED;
  }
}

export function configuration_UiModeTypeToJSON(object: Configuration_UiModeType): string {
  switch (object) {
    case Configuration_UiModeType.UI_MODE_TYPE_UNSET:
      return 'UI_MODE_TYPE_UNSET';
    case Configuration_UiModeType.UI_MODE_TYPE_NORMAL:
      return 'UI_MODE_TYPE_NORMAL';
    case Configuration_UiModeType.UI_MODE_TYPE_DESK:
      return 'UI_MODE_TYPE_DESK';
    case Configuration_UiModeType.UI_MODE_TYPE_CAR:
      return 'UI_MODE_TYPE_CAR';
    case Configuration_UiModeType.UI_MODE_TYPE_TELEVISION:
      return 'UI_MODE_TYPE_TELEVISION';
    case Configuration_UiModeType.UI_MODE_TYPE_APPLIANCE:
      return 'UI_MODE_TYPE_APPLIANCE';
    case Configuration_UiModeType.UI_MODE_TYPE_WATCH:
      return 'UI_MODE_TYPE_WATCH';
    case Configuration_UiModeType.UI_MODE_TYPE_VRHEADSET:
      return 'UI_MODE_TYPE_VRHEADSET';
    default:
      return 'UNKNOWN';
  }
}

export enum Configuration_UiModeNight {
  UI_MODE_NIGHT_UNSET = 0,
  UI_MODE_NIGHT_NIGHT = 1,
  UI_MODE_NIGHT_NOTNIGHT = 2,
  UNRECOGNIZED = -1,
}

export function configuration_UiModeNightFromJSON(object: any): Configuration_UiModeNight {
  switch (object) {
    case 0:
    case 'UI_MODE_NIGHT_UNSET':
      return Configuration_UiModeNight.UI_MODE_NIGHT_UNSET;
    case 1:
    case 'UI_MODE_NIGHT_NIGHT':
      return Configuration_UiModeNight.UI_MODE_NIGHT_NIGHT;
    case 2:
    case 'UI_MODE_NIGHT_NOTNIGHT':
      return Configuration_UiModeNight.UI_MODE_NIGHT_NOTNIGHT;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Configuration_UiModeNight.UNRECOGNIZED;
  }
}

export function configuration_UiModeNightToJSON(object: Configuration_UiModeNight): string {
  switch (object) {
    case Configuration_UiModeNight.UI_MODE_NIGHT_UNSET:
      return 'UI_MODE_NIGHT_UNSET';
    case Configuration_UiModeNight.UI_MODE_NIGHT_NIGHT:
      return 'UI_MODE_NIGHT_NIGHT';
    case Configuration_UiModeNight.UI_MODE_NIGHT_NOTNIGHT:
      return 'UI_MODE_NIGHT_NOTNIGHT';
    default:
      return 'UNKNOWN';
  }
}

export enum Configuration_Touchscreen {
  TOUCHSCREEN_UNSET = 0,
  TOUCHSCREEN_NOTOUCH = 1,
  TOUCHSCREEN_STYLUS = 2,
  TOUCHSCREEN_FINGER = 3,
  UNRECOGNIZED = -1,
}

export function configuration_TouchscreenFromJSON(object: any): Configuration_Touchscreen {
  switch (object) {
    case 0:
    case 'TOUCHSCREEN_UNSET':
      return Configuration_Touchscreen.TOUCHSCREEN_UNSET;
    case 1:
    case 'TOUCHSCREEN_NOTOUCH':
      return Configuration_Touchscreen.TOUCHSCREEN_NOTOUCH;
    case 2:
    case 'TOUCHSCREEN_STYLUS':
      return Configuration_Touchscreen.TOUCHSCREEN_STYLUS;
    case 3:
    case 'TOUCHSCREEN_FINGER':
      return Configuration_Touchscreen.TOUCHSCREEN_FINGER;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Configuration_Touchscreen.UNRECOGNIZED;
  }
}

export function configuration_TouchscreenToJSON(object: Configuration_Touchscreen): string {
  switch (object) {
    case Configuration_Touchscreen.TOUCHSCREEN_UNSET:
      return 'TOUCHSCREEN_UNSET';
    case Configuration_Touchscreen.TOUCHSCREEN_NOTOUCH:
      return 'TOUCHSCREEN_NOTOUCH';
    case Configuration_Touchscreen.TOUCHSCREEN_STYLUS:
      return 'TOUCHSCREEN_STYLUS';
    case Configuration_Touchscreen.TOUCHSCREEN_FINGER:
      return 'TOUCHSCREEN_FINGER';
    default:
      return 'UNKNOWN';
  }
}

export enum Configuration_KeysHidden {
  KEYS_HIDDEN_UNSET = 0,
  KEYS_HIDDEN_KEYSEXPOSED = 1,
  KEYS_HIDDEN_KEYSHIDDEN = 2,
  KEYS_HIDDEN_KEYSSOFT = 3,
  UNRECOGNIZED = -1,
}

export function configuration_KeysHiddenFromJSON(object: any): Configuration_KeysHidden {
  switch (object) {
    case 0:
    case 'KEYS_HIDDEN_UNSET':
      return Configuration_KeysHidden.KEYS_HIDDEN_UNSET;
    case 1:
    case 'KEYS_HIDDEN_KEYSEXPOSED':
      return Configuration_KeysHidden.KEYS_HIDDEN_KEYSEXPOSED;
    case 2:
    case 'KEYS_HIDDEN_KEYSHIDDEN':
      return Configuration_KeysHidden.KEYS_HIDDEN_KEYSHIDDEN;
    case 3:
    case 'KEYS_HIDDEN_KEYSSOFT':
      return Configuration_KeysHidden.KEYS_HIDDEN_KEYSSOFT;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Configuration_KeysHidden.UNRECOGNIZED;
  }
}

export function configuration_KeysHiddenToJSON(object: Configuration_KeysHidden): string {
  switch (object) {
    case Configuration_KeysHidden.KEYS_HIDDEN_UNSET:
      return 'KEYS_HIDDEN_UNSET';
    case Configuration_KeysHidden.KEYS_HIDDEN_KEYSEXPOSED:
      return 'KEYS_HIDDEN_KEYSEXPOSED';
    case Configuration_KeysHidden.KEYS_HIDDEN_KEYSHIDDEN:
      return 'KEYS_HIDDEN_KEYSHIDDEN';
    case Configuration_KeysHidden.KEYS_HIDDEN_KEYSSOFT:
      return 'KEYS_HIDDEN_KEYSSOFT';
    default:
      return 'UNKNOWN';
  }
}

export enum Configuration_Keyboard {
  KEYBOARD_UNSET = 0,
  KEYBOARD_NOKEYS = 1,
  KEYBOARD_QWERTY = 2,
  KEYBOARD_TWELVEKEY = 3,
  UNRECOGNIZED = -1,
}

export function configuration_KeyboardFromJSON(object: any): Configuration_Keyboard {
  switch (object) {
    case 0:
    case 'KEYBOARD_UNSET':
      return Configuration_Keyboard.KEYBOARD_UNSET;
    case 1:
    case 'KEYBOARD_NOKEYS':
      return Configuration_Keyboard.KEYBOARD_NOKEYS;
    case 2:
    case 'KEYBOARD_QWERTY':
      return Configuration_Keyboard.KEYBOARD_QWERTY;
    case 3:
    case 'KEYBOARD_TWELVEKEY':
      return Configuration_Keyboard.KEYBOARD_TWELVEKEY;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Configuration_Keyboard.UNRECOGNIZED;
  }
}

export function configuration_KeyboardToJSON(object: Configuration_Keyboard): string {
  switch (object) {
    case Configuration_Keyboard.KEYBOARD_UNSET:
      return 'KEYBOARD_UNSET';
    case Configuration_Keyboard.KEYBOARD_NOKEYS:
      return 'KEYBOARD_NOKEYS';
    case Configuration_Keyboard.KEYBOARD_QWERTY:
      return 'KEYBOARD_QWERTY';
    case Configuration_Keyboard.KEYBOARD_TWELVEKEY:
      return 'KEYBOARD_TWELVEKEY';
    default:
      return 'UNKNOWN';
  }
}

export enum Configuration_NavHidden {
  NAV_HIDDEN_UNSET = 0,
  NAV_HIDDEN_NAVEXPOSED = 1,
  NAV_HIDDEN_NAVHIDDEN = 2,
  UNRECOGNIZED = -1,
}

export function configuration_NavHiddenFromJSON(object: any): Configuration_NavHidden {
  switch (object) {
    case 0:
    case 'NAV_HIDDEN_UNSET':
      return Configuration_NavHidden.NAV_HIDDEN_UNSET;
    case 1:
    case 'NAV_HIDDEN_NAVEXPOSED':
      return Configuration_NavHidden.NAV_HIDDEN_NAVEXPOSED;
    case 2:
    case 'NAV_HIDDEN_NAVHIDDEN':
      return Configuration_NavHidden.NAV_HIDDEN_NAVHIDDEN;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Configuration_NavHidden.UNRECOGNIZED;
  }
}

export function configuration_NavHiddenToJSON(object: Configuration_NavHidden): string {
  switch (object) {
    case Configuration_NavHidden.NAV_HIDDEN_UNSET:
      return 'NAV_HIDDEN_UNSET';
    case Configuration_NavHidden.NAV_HIDDEN_NAVEXPOSED:
      return 'NAV_HIDDEN_NAVEXPOSED';
    case Configuration_NavHidden.NAV_HIDDEN_NAVHIDDEN:
      return 'NAV_HIDDEN_NAVHIDDEN';
    default:
      return 'UNKNOWN';
  }
}

export enum Configuration_Navigation {
  NAVIGATION_UNSET = 0,
  NAVIGATION_NONAV = 1,
  NAVIGATION_DPAD = 2,
  NAVIGATION_TRACKBALL = 3,
  NAVIGATION_WHEEL = 4,
  UNRECOGNIZED = -1,
}

export function configuration_NavigationFromJSON(object: any): Configuration_Navigation {
  switch (object) {
    case 0:
    case 'NAVIGATION_UNSET':
      return Configuration_Navigation.NAVIGATION_UNSET;
    case 1:
    case 'NAVIGATION_NONAV':
      return Configuration_Navigation.NAVIGATION_NONAV;
    case 2:
    case 'NAVIGATION_DPAD':
      return Configuration_Navigation.NAVIGATION_DPAD;
    case 3:
    case 'NAVIGATION_TRACKBALL':
      return Configuration_Navigation.NAVIGATION_TRACKBALL;
    case 4:
    case 'NAVIGATION_WHEEL':
      return Configuration_Navigation.NAVIGATION_WHEEL;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Configuration_Navigation.UNRECOGNIZED;
  }
}

export function configuration_NavigationToJSON(object: Configuration_Navigation): string {
  switch (object) {
    case Configuration_Navigation.NAVIGATION_UNSET:
      return 'NAVIGATION_UNSET';
    case Configuration_Navigation.NAVIGATION_NONAV:
      return 'NAVIGATION_NONAV';
    case Configuration_Navigation.NAVIGATION_DPAD:
      return 'NAVIGATION_DPAD';
    case Configuration_Navigation.NAVIGATION_TRACKBALL:
      return 'NAVIGATION_TRACKBALL';
    case Configuration_Navigation.NAVIGATION_WHEEL:
      return 'NAVIGATION_WHEEL';
    default:
      return 'UNKNOWN';
  }
}

const baseConfiguration: object = {
  mcc: 0,
  mnc: 0,
  locale: '',
  layoutDirection: 0,
  screenWidth: 0,
  screenHeight: 0,
  screenWidthDp: 0,
  screenHeightDp: 0,
  smallestScreenWidthDp: 0,
  screenLayoutSize: 0,
  screenLayoutLong: 0,
  screenRound: 0,
  wideColorGamut: 0,
  hdr: 0,
  orientation: 0,
  uiModeType: 0,
  uiModeNight: 0,
  density: 0,
  touchscreen: 0,
  keysHidden: 0,
  keyboard: 0,
  navHidden: 0,
  navigation: 0,
  sdkVersion: 0,
  product: '',
};

export const Configuration = {
  encode(message: Configuration, writer: Writer = Writer.create()): Writer {
    if (message.mcc !== 0) {
      writer.uint32(8).uint32(message.mcc);
    }
    if (message.mnc !== 0) {
      writer.uint32(16).uint32(message.mnc);
    }
    if (message.locale !== '') {
      writer.uint32(26).string(message.locale);
    }
    if (message.layoutDirection !== 0) {
      writer.uint32(32).int32(message.layoutDirection);
    }
    if (message.screenWidth !== 0) {
      writer.uint32(40).uint32(message.screenWidth);
    }
    if (message.screenHeight !== 0) {
      writer.uint32(48).uint32(message.screenHeight);
    }
    if (message.screenWidthDp !== 0) {
      writer.uint32(56).uint32(message.screenWidthDp);
    }
    if (message.screenHeightDp !== 0) {
      writer.uint32(64).uint32(message.screenHeightDp);
    }
    if (message.smallestScreenWidthDp !== 0) {
      writer.uint32(72).uint32(message.smallestScreenWidthDp);
    }
    if (message.screenLayoutSize !== 0) {
      writer.uint32(80).int32(message.screenLayoutSize);
    }
    if (message.screenLayoutLong !== 0) {
      writer.uint32(88).int32(message.screenLayoutLong);
    }
    if (message.screenRound !== 0) {
      writer.uint32(96).int32(message.screenRound);
    }
    if (message.wideColorGamut !== 0) {
      writer.uint32(104).int32(message.wideColorGamut);
    }
    if (message.hdr !== 0) {
      writer.uint32(112).int32(message.hdr);
    }
    if (message.orientation !== 0) {
      writer.uint32(120).int32(message.orientation);
    }
    if (message.uiModeType !== 0) {
      writer.uint32(128).int32(message.uiModeType);
    }
    if (message.uiModeNight !== 0) {
      writer.uint32(136).int32(message.uiModeNight);
    }
    if (message.density !== 0) {
      writer.uint32(144).uint32(message.density);
    }
    if (message.touchscreen !== 0) {
      writer.uint32(152).int32(message.touchscreen);
    }
    if (message.keysHidden !== 0) {
      writer.uint32(160).int32(message.keysHidden);
    }
    if (message.keyboard !== 0) {
      writer.uint32(168).int32(message.keyboard);
    }
    if (message.navHidden !== 0) {
      writer.uint32(176).int32(message.navHidden);
    }
    if (message.navigation !== 0) {
      writer.uint32(184).int32(message.navigation);
    }
    if (message.sdkVersion !== 0) {
      writer.uint32(192).uint32(message.sdkVersion);
    }
    if (message.product !== '') {
      writer.uint32(202).string(message.product);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Configuration {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseConfiguration } as Configuration;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.mcc = reader.uint32();
          break;
        case 2:
          message.mnc = reader.uint32();
          break;
        case 3:
          message.locale = reader.string();
          break;
        case 4:
          message.layoutDirection = reader.int32() as any;
          break;
        case 5:
          message.screenWidth = reader.uint32();
          break;
        case 6:
          message.screenHeight = reader.uint32();
          break;
        case 7:
          message.screenWidthDp = reader.uint32();
          break;
        case 8:
          message.screenHeightDp = reader.uint32();
          break;
        case 9:
          message.smallestScreenWidthDp = reader.uint32();
          break;
        case 10:
          message.screenLayoutSize = reader.int32() as any;
          break;
        case 11:
          message.screenLayoutLong = reader.int32() as any;
          break;
        case 12:
          message.screenRound = reader.int32() as any;
          break;
        case 13:
          message.wideColorGamut = reader.int32() as any;
          break;
        case 14:
          message.hdr = reader.int32() as any;
          break;
        case 15:
          message.orientation = reader.int32() as any;
          break;
        case 16:
          message.uiModeType = reader.int32() as any;
          break;
        case 17:
          message.uiModeNight = reader.int32() as any;
          break;
        case 18:
          message.density = reader.uint32();
          break;
        case 19:
          message.touchscreen = reader.int32() as any;
          break;
        case 20:
          message.keysHidden = reader.int32() as any;
          break;
        case 21:
          message.keyboard = reader.int32() as any;
          break;
        case 22:
          message.navHidden = reader.int32() as any;
          break;
        case 23:
          message.navigation = reader.int32() as any;
          break;
        case 24:
          message.sdkVersion = reader.uint32();
          break;
        case 25:
          message.product = reader.string();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Configuration {
    const message = { ...baseConfiguration } as Configuration;
    if (object.mcc !== undefined && object.mcc !== null) {
      message.mcc = Number(object.mcc);
    }
    if (object.mnc !== undefined && object.mnc !== null) {
      message.mnc = Number(object.mnc);
    }
    if (object.locale !== undefined && object.locale !== null) {
      message.locale = String(object.locale);
    }
    if (object.layoutDirection !== undefined && object.layoutDirection !== null) {
      message.layoutDirection = configuration_LayoutDirectionFromJSON(object.layoutDirection);
    }
    if (object.screenWidth !== undefined && object.screenWidth !== null) {
      message.screenWidth = Number(object.screenWidth);
    }
    if (object.screenHeight !== undefined && object.screenHeight !== null) {
      message.screenHeight = Number(object.screenHeight);
    }
    if (object.screenWidthDp !== undefined && object.screenWidthDp !== null) {
      message.screenWidthDp = Number(object.screenWidthDp);
    }
    if (object.screenHeightDp !== undefined && object.screenHeightDp !== null) {
      message.screenHeightDp = Number(object.screenHeightDp);
    }
    if (object.smallestScreenWidthDp !== undefined && object.smallestScreenWidthDp !== null) {
      message.smallestScreenWidthDp = Number(object.smallestScreenWidthDp);
    }
    if (object.screenLayoutSize !== undefined && object.screenLayoutSize !== null) {
      message.screenLayoutSize = configuration_ScreenLayoutSizeFromJSON(object.screenLayoutSize);
    }
    if (object.screenLayoutLong !== undefined && object.screenLayoutLong !== null) {
      message.screenLayoutLong = configuration_ScreenLayoutLongFromJSON(object.screenLayoutLong);
    }
    if (object.screenRound !== undefined && object.screenRound !== null) {
      message.screenRound = configuration_ScreenRoundFromJSON(object.screenRound);
    }
    if (object.wideColorGamut !== undefined && object.wideColorGamut !== null) {
      message.wideColorGamut = configuration_WideColorGamutFromJSON(object.wideColorGamut);
    }
    if (object.hdr !== undefined && object.hdr !== null) {
      message.hdr = configuration_HdrFromJSON(object.hdr);
    }
    if (object.orientation !== undefined && object.orientation !== null) {
      message.orientation = configuration_OrientationFromJSON(object.orientation);
    }
    if (object.uiModeType !== undefined && object.uiModeType !== null) {
      message.uiModeType = configuration_UiModeTypeFromJSON(object.uiModeType);
    }
    if (object.uiModeNight !== undefined && object.uiModeNight !== null) {
      message.uiModeNight = configuration_UiModeNightFromJSON(object.uiModeNight);
    }
    if (object.density !== undefined && object.density !== null) {
      message.density = Number(object.density);
    }
    if (object.touchscreen !== undefined && object.touchscreen !== null) {
      message.touchscreen = configuration_TouchscreenFromJSON(object.touchscreen);
    }
    if (object.keysHidden !== undefined && object.keysHidden !== null) {
      message.keysHidden = configuration_KeysHiddenFromJSON(object.keysHidden);
    }
    if (object.keyboard !== undefined && object.keyboard !== null) {
      message.keyboard = configuration_KeyboardFromJSON(object.keyboard);
    }
    if (object.navHidden !== undefined && object.navHidden !== null) {
      message.navHidden = configuration_NavHiddenFromJSON(object.navHidden);
    }
    if (object.navigation !== undefined && object.navigation !== null) {
      message.navigation = configuration_NavigationFromJSON(object.navigation);
    }
    if (object.sdkVersion !== undefined && object.sdkVersion !== null) {
      message.sdkVersion = Number(object.sdkVersion);
    }
    if (object.product !== undefined && object.product !== null) {
      message.product = String(object.product);
    }
    return message;
  },

  toJSON(message: Configuration): unknown {
    const obj: any = {};
    message.mcc !== undefined && (obj.mcc = message.mcc);
    message.mnc !== undefined && (obj.mnc = message.mnc);
    message.locale !== undefined && (obj.locale = message.locale);
    message.layoutDirection !== undefined &&
      (obj.layoutDirection = configuration_LayoutDirectionToJSON(message.layoutDirection));
    message.screenWidth !== undefined && (obj.screenWidth = message.screenWidth);
    message.screenHeight !== undefined && (obj.screenHeight = message.screenHeight);
    message.screenWidthDp !== undefined && (obj.screenWidthDp = message.screenWidthDp);
    message.screenHeightDp !== undefined && (obj.screenHeightDp = message.screenHeightDp);
    message.smallestScreenWidthDp !== undefined && (obj.smallestScreenWidthDp = message.smallestScreenWidthDp);
    message.screenLayoutSize !== undefined &&
      (obj.screenLayoutSize = configuration_ScreenLayoutSizeToJSON(message.screenLayoutSize));
    message.screenLayoutLong !== undefined &&
      (obj.screenLayoutLong = configuration_ScreenLayoutLongToJSON(message.screenLayoutLong));
    message.screenRound !== undefined && (obj.screenRound = configuration_ScreenRoundToJSON(message.screenRound));
    message.wideColorGamut !== undefined &&
      (obj.wideColorGamut = configuration_WideColorGamutToJSON(message.wideColorGamut));
    message.hdr !== undefined && (obj.hdr = configuration_HdrToJSON(message.hdr));
    message.orientation !== undefined && (obj.orientation = configuration_OrientationToJSON(message.orientation));
    message.uiModeType !== undefined && (obj.uiModeType = configuration_UiModeTypeToJSON(message.uiModeType));
    message.uiModeNight !== undefined && (obj.uiModeNight = configuration_UiModeNightToJSON(message.uiModeNight));
    message.density !== undefined && (obj.density = message.density);
    message.touchscreen !== undefined && (obj.touchscreen = configuration_TouchscreenToJSON(message.touchscreen));
    message.keysHidden !== undefined && (obj.keysHidden = configuration_KeysHiddenToJSON(message.keysHidden));
    message.keyboard !== undefined && (obj.keyboard = configuration_KeyboardToJSON(message.keyboard));
    message.navHidden !== undefined && (obj.navHidden = configuration_NavHiddenToJSON(message.navHidden));
    message.navigation !== undefined && (obj.navigation = configuration_NavigationToJSON(message.navigation));
    message.sdkVersion !== undefined && (obj.sdkVersion = message.sdkVersion);
    message.product !== undefined && (obj.product = message.product);
    return obj;
  },

  fromPartial(object: DeepPartial<Configuration>): Configuration {
    const message = { ...baseConfiguration } as Configuration;
    if (object.mcc !== undefined && object.mcc !== null) {
      message.mcc = object.mcc;
    } else {
      message.mcc = 0;
    }
    if (object.mnc !== undefined && object.mnc !== null) {
      message.mnc = object.mnc;
    } else {
      message.mnc = 0;
    }
    if (object.locale !== undefined && object.locale !== null) {
      message.locale = object.locale;
    } else {
      message.locale = '';
    }
    if (object.layoutDirection !== undefined && object.layoutDirection !== null) {
      message.layoutDirection = object.layoutDirection;
    } else {
      message.layoutDirection = 0;
    }
    if (object.screenWidth !== undefined && object.screenWidth !== null) {
      message.screenWidth = object.screenWidth;
    } else {
      message.screenWidth = 0;
    }
    if (object.screenHeight !== undefined && object.screenHeight !== null) {
      message.screenHeight = object.screenHeight;
    } else {
      message.screenHeight = 0;
    }
    if (object.screenWidthDp !== undefined && object.screenWidthDp !== null) {
      message.screenWidthDp = object.screenWidthDp;
    } else {
      message.screenWidthDp = 0;
    }
    if (object.screenHeightDp !== undefined && object.screenHeightDp !== null) {
      message.screenHeightDp = object.screenHeightDp;
    } else {
      message.screenHeightDp = 0;
    }
    if (object.smallestScreenWidthDp !== undefined && object.smallestScreenWidthDp !== null) {
      message.smallestScreenWidthDp = object.smallestScreenWidthDp;
    } else {
      message.smallestScreenWidthDp = 0;
    }
    if (object.screenLayoutSize !== undefined && object.screenLayoutSize !== null) {
      message.screenLayoutSize = object.screenLayoutSize;
    } else {
      message.screenLayoutSize = 0;
    }
    if (object.screenLayoutLong !== undefined && object.screenLayoutLong !== null) {
      message.screenLayoutLong = object.screenLayoutLong;
    } else {
      message.screenLayoutLong = 0;
    }
    if (object.screenRound !== undefined && object.screenRound !== null) {
      message.screenRound = object.screenRound;
    } else {
      message.screenRound = 0;
    }
    if (object.wideColorGamut !== undefined && object.wideColorGamut !== null) {
      message.wideColorGamut = object.wideColorGamut;
    } else {
      message.wideColorGamut = 0;
    }
    if (object.hdr !== undefined && object.hdr !== null) {
      message.hdr = object.hdr;
    } else {
      message.hdr = 0;
    }
    if (object.orientation !== undefined && object.orientation !== null) {
      message.orientation = object.orientation;
    } else {
      message.orientation = 0;
    }
    if (object.uiModeType !== undefined && object.uiModeType !== null) {
      message.uiModeType = object.uiModeType;
    } else {
      message.uiModeType = 0;
    }
    if (object.uiModeNight !== undefined && object.uiModeNight !== null) {
      message.uiModeNight = object.uiModeNight;
    } else {
      message.uiModeNight = 0;
    }
    if (object.density !== undefined && object.density !== null) {
      message.density = object.density;
    } else {
      message.density = 0;
    }
    if (object.touchscreen !== undefined && object.touchscreen !== null) {
      message.touchscreen = object.touchscreen;
    } else {
      message.touchscreen = 0;
    }
    if (object.keysHidden !== undefined && object.keysHidden !== null) {
      message.keysHidden = object.keysHidden;
    } else {
      message.keysHidden = 0;
    }
    if (object.keyboard !== undefined && object.keyboard !== null) {
      message.keyboard = object.keyboard;
    } else {
      message.keyboard = 0;
    }
    if (object.navHidden !== undefined && object.navHidden !== null) {
      message.navHidden = object.navHidden;
    } else {
      message.navHidden = 0;
    }
    if (object.navigation !== undefined && object.navigation !== null) {
      message.navigation = object.navigation;
    } else {
      message.navigation = 0;
    }
    if (object.sdkVersion !== undefined && object.sdkVersion !== null) {
      message.sdkVersion = object.sdkVersion;
    } else {
      message.sdkVersion = 0;
    }
    if (object.product !== undefined && object.product !== null) {
      message.product = object.product;
    } else {
      message.product = '';
    }
    return message;
  },
};

type Builtin = Date | Function | Uint8Array | string | number | boolean | undefined;
export type DeepPartial<T> = T extends Builtin
  ? T
  : T extends Array<infer U>
    ? Array<DeepPartial<U>>
    : T extends ReadonlyArray<infer U>
      ? ReadonlyArray<DeepPartial<U>>
      : T extends { $case: string }
        ? { [K in keyof Omit<T, '$case'>]?: DeepPartial<T[K]> } & {
            $case: T['$case'];
          }
        : T extends {}
          ? { [K in keyof T]?: DeepPartial<T[K]> }
          : Partial<T>;

// If you get a compile-error about 'Constructor<Long> and ... have no overlap',
// add '--ts_proto_opt=esModuleInterop=true' as a flag when calling 'protoc'.
// @ts-ignore
if (util.Long !== Long) {
  util.Long = Long as any;
  configure();
}
