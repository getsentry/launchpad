import plist from 'simple-plist';

export module PlistUtils {
  /**
   * Takes a pre-opened plist file as a buffer and parses it to a JSON representation.
   *
   * First tries to use the simple-plist library to parse the contents, if that fails
   * we'll convert the plist to a string and trims any whitespace before parsing it again.
   */
  export function safelyParsePlist(contents: Buffer): any {
    try {
      return plist.parse(contents, undefined);
    } catch (error) {
      const stringFile = contents.toString();
      const trimmedFile = stringFile.trim();
      return plist.parse(trimmedFile, undefined);
    }
  }

  export function isMacosPlist(plistJson: any | undefined): boolean {
    return plistJson?.CFBundleIdentifier && plistJson?.DTPlatformName === 'macosx';
  }

  export function isValidiOSPlist(plistJson: any | undefined): boolean {
    return plistJson?.CFBundleIdentifier && !isMacosPlist(plistJson);
  }
}
