/* eslint-disable no-bitwise */
export module AndroidResourceUtils {
  export function androidColorToHex(colorInt: number): string {
    const red = ((colorInt >> 16) & 0xff).toString(16).padStart(2, '0');
    const green = ((colorInt >> 8) & 0xff).toString(16).padStart(2, '0');
    const blue = (colorInt & 0xff).toString(16).padStart(2, '0');
    const fillColorHex = `#${red}${green}${blue}`;
    return fillColorHex;
  }

  export function resolveColor(colorValue: string): string {
    if (colorValue.endsWith('.xml')) {
      throw new Error(`Color value ${colorValue} is a reference to a color in a XML file`);
    }
    if (colorValue.startsWith('#')) {
      return colorValue;
    }
    const colorInt = parseInt(colorValue, 10);
    if (!isNaN(colorInt)) {
      return androidColorToHex(colorInt);
    }

    return '#ffffff';
  }

  export const ANDROID_FRAMEWORK_COLORS = new Map<string, string>([
    ['@android:color/white', '#FFFFFF'],
    ['@android:color/black', '#000000'],
    ['@android:color/transparent', '#00000000'],
    ['@android:color/background_dark', '#FF000000'],
    ['@android:color/background_light', '#FFFFFFFF'],
    ['@android:color/background_floating_material_dark', '#FF424242'],
    ['@android:color/background_floating_material_light', '#FFEEEEEE'],
    ['@android:color/primary_text_dark', '#FFFFFFFF'],
    ['@android:color/primary_text_light', '#DE000000'],
    ['@android:color/secondary_text_dark', '#B3FFFFFF'],
    ['@android:color/secondary_text_light', '#8A000000'],
    ['@android:color/primary_material_dark', '#FF212121'],
    ['@android:color/primary_material_light', '#FFFAFAFA'],
    ['@android:color/darker_gray', '#FFAAAAAA'],
    ['@android:color/holo_blue_bright', '#FF00DDFF'],
    ['@android:color/holo_blue_dark', '#FF0099CC'],
    ['@android:color/holo_blue_light', '#FF33B5E5'],
    ['@android:color/holo_green_dark', '#FF669900'],
    ['@android:color/holo_green_light', '#FF99CC00'],
    ['@android:color/holo_orange_dark', '#FFFF8800'],
    ['@android:color/holo_orange_light', '#FFFFBB33'],
    ['@android:color/holo_purple', '#FFAA66CC'],
    ['@android:color/holo_red_dark', '#FFCC0000'],
    ['@android:color/holo_red_light', '#FFFF4444'],
    ['@android:color/link_text_dark', '#FF5C5CFF'],
    ['@android:color/link_text_light', '#FF0000EE'],
    ['@android:color/accent_material_dark', '#FF80CBC4'],
    ['@android:color/accent_material_light', '#FF009688'],
    ['@android:color/background_material_dark', '#FF303030'],
    ['@android:color/background_material_light', '#FFEEEEEE'],
    ['@android:color/bright_foreground_dark', '#FFFFFFFF'],
    ['@android:color/bright_foreground_light', '#FF000000'],
    ['@android:color/bright_foreground_dark_disabled', '#80FFFFFF'],
    ['@android:color/bright_foreground_light_disabled', '#80000000'],
    ['@android:color/dim_foreground_dark', '#FFBEBEBE'],
    ['@android:color/dim_foreground_light', '#FF323232'],
    ['@android:color/highlighted_text_dark', '#6680CBC4'],
    ['@android:color/highlighted_text_light', '#66009688'],
    ['@android:color/hint_foreground_dark', '#80FFFFFF'],
    ['@android:color/hint_foreground_light', '#80000000'],
    ['@android:color/system_neutral1_0', '#FFFFFF'],
    ['@android:color/system_neutral1_1000', '#000000'],
  ]);
}
